//! Level-0 concurrent event extraction.
//!
//! Syntactic screening over cleaned source text. It never parses C, never
//! consults Frama-C, and never resolves an alias, so everything it produces is
//! a candidate. In particular it has no status meaning "not a race": the
//! strongest claim it makes about a lock is that two accesses name one
//! lexically, which is evidence and not protection. A status that meant
//! "protected" would be read as a verdict, and a lexical lockset cannot
//! support one.
//!
//! The event shape borrows the evidence carried by Deadlock_and_Racer's
//! MemoryAccess: access kind, abstract location, lockset, callsite and
//! provenance.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData as McpError};
use serde_json::json;

use crate::error::no_project_loaded_error;
use crate::mcp::budgets::CONCURRENCY_SCAN_BUDGET;
use crate::mcp::server::{json_result, FramaCMcpServer};
use crate::mcp::types::AnalyzeConcurrencyParams;

/// Words that open a construct rather than name a callee or a declarator.
const KEYWORDS: &[&str] = &[
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case", "goto", "break",
    "continue", "typedef", "struct", "union", "enum", "static", "const", "volatile", "extern",
    "unsigned", "signed", "register", "inline", "restrict",
];

/// What a modelled synchronisation call does to the lock it names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockOp {
    /// Blocks until the lock is held.
    Acquire,
    /// May return without the lock: every try and timed variant. Follows the
    /// trylock rule in apply_lock, so it is an event and never a lock held.
    Try,
    Release,
    /// pthread_cond_wait and pthread_cond_timedwait. The mutex is released
    /// for the wait and held again on return, timed out or not, so the
    /// lockset is unchanged and the reacquisition is an order edge.
    Wait,
}

/// Whether a held lock excludes every other holder or only writers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockMode {
    Exclusive,
    /// A read-held rwlock. Two holders in this mode run together, so it is
    /// evidence of nothing for a pair in which both sides hold it this way.
    Shared,
}

/// One entry of the synchronisation API this pass models.
///
/// No entry is reentrant: whether a mutex is recursive is an attribute set at
/// initialisation, not a property of the call that takes it, and this pass
/// does not read pthread_mutexattr_settype. A double_lock report says so.
struct LockApi {
    name: &'static str,
    /// The argument naming the lock, or None for the SV-COMP atomic section,
    /// which names no object and is reported as ATOMIC_SECTION.
    arg: Option<usize>,
    op: LockOp,
    mode: LockMode,
}

const fn api(name: &'static str, arg: usize, op: LockOp, mode: LockMode) -> LockApi {
    LockApi {
        name,
        arg: Some(arg),
        op,
        mode,
    }
}

const LOCK_API: &[LockApi] = &[
    api("pthread_mutex_lock", 0, LockOp::Acquire, LockMode::Exclusive),
    api("pthread_mutex_trylock", 0, LockOp::Try, LockMode::Exclusive),
    api("pthread_mutex_timedlock", 0, LockOp::Try, LockMode::Exclusive),
    api("pthread_mutex_unlock", 0, LockOp::Release, LockMode::Exclusive),
    api("pthread_spin_lock", 0, LockOp::Acquire, LockMode::Exclusive),
    api("pthread_spin_trylock", 0, LockOp::Try, LockMode::Exclusive),
    api("pthread_spin_unlock", 0, LockOp::Release, LockMode::Exclusive),
    api("pthread_rwlock_rdlock", 0, LockOp::Acquire, LockMode::Shared),
    api("pthread_rwlock_wrlock", 0, LockOp::Acquire, LockMode::Exclusive),
    api("pthread_rwlock_tryrdlock", 0, LockOp::Try, LockMode::Shared),
    api("pthread_rwlock_trywrlock", 0, LockOp::Try, LockMode::Exclusive),
    api("pthread_rwlock_timedrdlock", 0, LockOp::Try, LockMode::Shared),
    api("pthread_rwlock_timedwrlock", 0, LockOp::Try, LockMode::Exclusive),
    api("pthread_rwlock_unlock", 0, LockOp::Release, LockMode::Exclusive),
    api("sem_wait", 0, LockOp::Acquire, LockMode::Exclusive),
    api("sem_trywait", 0, LockOp::Try, LockMode::Exclusive),
    api("sem_timedwait", 0, LockOp::Try, LockMode::Exclusive),
    api("sem_post", 0, LockOp::Release, LockMode::Exclusive),
    api("pthread_cond_wait", 1, LockOp::Wait, LockMode::Exclusive),
    api("pthread_cond_timedwait", 1, LockOp::Wait, LockMode::Exclusive),
    LockApi {
        name: "__VERIFIER_atomic_begin",
        arg: None,
        op: LockOp::Acquire,
        mode: LockMode::Exclusive,
    },
    LockApi {
        name: "__VERIFIER_atomic_end",
        arg: None,
        op: LockOp::Release,
        mode: LockMode::Exclusive,
    },
];

/// The pseudo-lock of an SV-COMP atomic section: everything between
/// "__VERIFIER_atomic_begin()" and "__VERIFIER_atomic_end()", and the whole
/// body of a function whose name starts with ATOMIC_FUNCTION_PREFIX.
const ATOMIC_SECTION: &str = "<atomic>";
const ATOMIC_FUNCTION_PREFIX: &str = "__VERIFIER_atomic";

fn lock_api(name: &str) -> Option<&'static LockApi> {
    LOCK_API.iter().find(|api| api.name == name)
}

/// The event kind a lock call is reported as. LOCK, TRYLOCK and UNLOCK are
/// the kinds the mutex-only version used, kept for every API so a reader
/// keyed on them still sees an rwlock or a semaphore.
fn lock_kind(op: LockOp) -> &'static str {
    match op {
        LockOp::Acquire => "LOCK",
        LockOp::Try => "TRYLOCK",
        LockOp::Release => "UNLOCK",
        LockOp::Wait => "COND_WAIT",
    }
}

/// The access kind of an atomic builtin's address argument, or None when the
/// call is not one or touches no object. GCC's "__atomic_" and "__sync_"
/// families and C11's stdatomic functions are covered by prefix.
///
/// "atomic_init" is not an atomic operation, it initialises the object
/// without synchronisation, so it is a plain WRITE and pairs as one.
fn atomic_access(name: &str) -> Option<&'static str> {
    let family = ["__atomic_", "__sync_", "atomic_"]
        .iter()
        .any(|prefix| name.starts_with(prefix));
    if !family || ["fence", "lock_free", "synchronize"].iter().any(|w| name.contains(w)) {
        return None;
    }
    if name == "atomic_init" {
        return Some("WRITE");
    }
    if name.contains("load") {
        return Some("ATOMIC_READ");
    }
    if name.contains("store") || name.contains("clear") || name == "__sync_lock_release" {
        return Some("ATOMIC_WRITE");
    }
    Some("ATOMIC_RMW")
}

/// Whether an atomic builtin writes its second argument: a compare-exchange
/// that fails stores the value it found through the "expected" pointer. That
/// store is a plain one, since the expected object is not atomic, so it
/// races like any other write. The "__sync" forms take the expected value
/// itself and write nothing back.
fn writes_expected(name: &str) -> bool {
    name.starts_with("atomic_compare_exchange_")
        || name == "__atomic_compare_exchange"
        || name == "__atomic_compare_exchange_n"
}

/// Calls whose argument text this pass reads.
fn reads_arguments(name: &str) -> bool {
    name.starts_with("pthread_") || lock_api(name).is_some() || atomic_access(name).is_some()
}

/// Calls whose arguments are not memory accesses of the program: thread and
/// lock operations name a handle, not data the program races on.
fn is_modelled(name: &str) -> bool {
    name.starts_with("pthread_") || lock_api(name).is_some()
}

fn is_access(kind: &str) -> bool {
    matches!(
        kind,
        "READ" | "WRITE" | "ATOMIC_READ" | "ATOMIC_WRITE" | "ATOMIC_RMW"
    )
}

fn is_atomic(kind: &str) -> bool {
    kind.starts_with("ATOMIC_")
}

fn writes(kind: &str) -> bool {
    matches!(kind, "WRITE" | "ATOMIC_WRITE" | "ATOMIC_RMW")
}

/// Two accesses conflict when one writes, unless both are atomic. An atomic
/// access against a plain one is a data race whatever the plain side does,
/// because the atomicity of one side orders nothing on the other.
fn conflicting(left: &str, right: &str) -> bool {
    (writes(left) || writes(right)) && !(is_atomic(left) && is_atomic(right))
}

/// A thread name for code no thread entry reaches. Kept distinct from a real
/// entry so a pair involving it is still a candidate: not knowing which thread
/// runs a function is not evidence that only one does.
const UNATTRIBUTED: &str = "<unattributed>";

/// A wall-clock stop the scan checks for itself.
///
/// The tool also wraps the scan in a timeout, and that timeout cannot end it: a
/// blocking task is not cancellable, so dropping its handle detaches the thread
/// and leaves it running with everything it has allocated. Bounding the
/// caller's wait while the worker runs on is the shape that starves a pool one
/// retry at a time. This is the half that stops the work, and the timeout stays
/// as the backstop it should never reach.
///
/// Checked once per line. Measured at 35 ns a reading against roughly 8 us of
/// work per line, so under half a percent, and a line is the granularity the
/// known hazards live at.
#[derive(Clone, Copy)]
struct Deadline {
    stop: std::time::Instant,
}

impl Deadline {
    fn new(budget: std::time::Duration) -> Self {
        Deadline {
            stop: std::time::Instant::now() + budget,
        }
    }

    fn passed(&self) -> bool {
        std::time::Instant::now() >= self.stop
    }
}


#[derive(Clone, Debug)]
struct Event {
    id: String,
    threads: Vec<String>,
    may_repeat: bool,
    kind: &'static str,
    file: String,
    line: usize,
    function: String,
    zone: Option<String>,
    lockset: Vec<String>,
    /// The members of lockset held in shared mode, a read-held rwlock.
    read_locks: Vec<String>,
    /// "exclusive" or "shared" for a lock event, None for every other kind.
    lock_mode: Option<&'static str>,
}

// ──────────────────────────────────────────────────────────────────────────
// Cleaning
// ──────────────────────────────────────────────────────────────────────────

/// Where a character scan stands between lines.
#[derive(Default)]
struct Noise {
    block: bool,
    string: bool,
    character: bool,
    escaped: bool,
}

/// What a single character contributes to the cleaned line.
enum Step {
    /// Keep this character.
    Keep,
    /// Blank this many source characters.
    Blank(usize),
    /// The rest of the line is a line comment.
    Rest,
}

fn step_noise(state: &mut Noise, c: char, next: char) -> Step {
    if state.block {
        let closing = c == '*' && next == '/';
        state.block = !closing;
        return Step::Blank(if closing { 2 } else { 1 });
    }
    if state.string || state.character {
        return step_literal(state, c);
    }
    if c == '/' && next == '*' {
        state.block = true;
        return Step::Blank(2);
    }
    if c == '/' && next == '/' {
        return Step::Rest;
    }
    state.string = c == '"';
    state.character = c == '\'';
    Step::Keep
}

fn step_literal(state: &mut Noise, c: char) -> Step {
    if state.escaped {
        state.escaped = false;
        return Step::Blank(1);
    }
    if c == '\\' {
        state.escaped = true;
        return Step::Blank(1);
    }
    if (state.string && c == '"') || (state.character && c == '\'') {
        state.string = false;
        state.character = false;
        return Step::Keep;
    }
    Step::Blank(1)
}

/// Replace comment and literal content with spaces, keeping every column where
/// it was so an offset into a cleaned line still points at the same source
/// text. Blanking rather than deleting is what lets the caller order the
/// actions on one line by position.
///
/// An ACSL annotation is a block comment, so this is also what stops
/// "requires x > INT_MIN;" from being read as a declaration of INT_MIN.
fn strip_noise(text: &str) -> Vec<String> {
    let mut state = Noise::default();
    let mut cleaned = Vec::new();
    // A byte order mark is not a declarator. Left in place it fails the
    // identifier test and took the file's first declaration with it.
    for raw in text.trim_start_matches('\u{feff}').lines() {
        let characters: Vec<char> = raw.chars().collect();
        let mut out = String::with_capacity(raw.len());
        let mut index = 0;
        while index < characters.len() {
            let next = characters.get(index + 1).copied().unwrap_or(' ');
            match step_noise(&mut state, characters[index], next) {
                Step::Keep => {
                    out.push(characters[index]);
                    index += 1;
                }
                Step::Blank(width) => {
                    out.extend(std::iter::repeat_n(' ', width));
                    index += width;
                }
                Step::Rest => break,
            }
        }
        // A string or a character literal does not continue across a line in
        // any code this screens, and treating one as open would blank the rest
        // of the file. A block comment does continue, so "block" is kept.
        state.string = false;
        state.character = false;
        state.escaped = false;
        cleaned.push(out);
    }
    cleaned
}

// ──────────────────────────────────────────────────────────────────────────
// Tokens and calls
// ──────────────────────────────────────────────────────────────────────────

/// Identifier occurrences with their byte offsets, so a match is a whole token
/// rather than a substring: a global named "n" does not match the "n" in "int".
///
/// The names borrow the line. Every caller either compares them or copies one,
/// and owning each token cost an allocation per identifier in the file.
fn identifiers(line: &str) -> Vec<(usize, &str)> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_head(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_tail(bytes[index]) {
            index += 1;
        }
        found.push((start, &line[start..index]));
    }
    found
}

fn is_head(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_tail(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

struct Call {
    name: String,
    args: Vec<String>,
    start: usize,
    /// Offset of the bracket opening this call's argument list. The first
    /// argument starts one byte after it, since splitting keeps every byte.
    open: usize,
    /// Offset of the bracket closing this call's argument list.
    end: usize,
}

/// Every bracket pair on the line, in one pass.
///
/// Asking for one call's closing bracket at a time walks the suffix again per
/// call, so a line of nested calls costs the square of its length. One pass
/// with a stack answers every call on the line, and it answers them by the
/// same rule: a bracket pairs with the nearest unclosed one before it.
fn paren_pairs(line: &str) -> BTreeMap<usize, usize> {
    let mut unclosed = Vec::new();
    let mut pairs = BTreeMap::new();
    for (offset, c) in line.char_indices() {
        if c == '(' {
            unclosed.push(offset);
        }
        if c == ')' {
            if let Some(start) = unclosed.pop() {
                pairs.insert(start, offset);
            }
        }
    }
    pairs
}

/// Every call on the line, with arguments split at top-level commas only, so
/// "pthread_create(&t, get_attr(), worker, 0)" still yields "worker" as its
/// third argument and two lock calls on one line are both seen.
///
/// Takes the line's tokens rather than walking them again, because both
/// callers need them for something else too.
fn calls_among(line: &str, tokens: &[(usize, &str)]) -> Vec<Call> {
    let pairs = paren_pairs(line);
    let mut found = Vec::new();
    for (start, name) in tokens {
        let after = start + name.len();
        let rest = line[after..].trim_start();
        if !rest.starts_with('(') || KEYWORDS.contains(name) {
            continue;
        }
        let open = after + line[after..].find('(').unwrap_or(0);
        let Some(close) = pairs.get(&open).copied() else {
            continue;
        };
        // Only a modelled call's arguments are ever read, and splitting every
        // call's meant re-splitting the text of an inner call once per
        // enclosing one: quadratic in the line length, 47 ms at 1,600 nested
        // calls and growing fourfold per doubling. It is the last of the three
        // superlinear paths the scan budget was written to survive, and the
        // only one that could still exhaust it.
        let args = match reads_arguments(name) {
            true => split_top_level(&line[open + 1..close]),
            false => Vec::new(),
        };
        found.push(Call {
            name: (*name).to_string(),
            args,
            start: *start,
            open,
            end: close,
        });
    }
    found
}

/// The offset of the bracket closing the one at "open", or None when the line
/// does not hold it. A call whose arguments wrap is skipped rather than guessed
/// at, which is one of the places this pass under-reports on purpose.
fn matching(line: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    // Sliced rather than skipped. Skipping walked the line from column zero on
    // every call site, so one line cost the number of calls on it times its
    // length: a generated or preprocessed file that puts a whole body on one
    // line turned a scan into a hang, inside a spawn_blocking with no timeout.
    for (offset, c) in line[open..].char_indices() {
        depth += i32::from(c == '(') - i32::from(c == ')');
        if depth == 0 {
            return Some(open + offset);
        }
    }
    None
}

fn split_top_level(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in body.chars() {
        depth += i32::from("([{".contains(c)) - i32::from(")]}".contains(c));
        if c == ',' && depth == 0 {
            parts.push(std::mem::take(&mut current));
            continue;
        }
        current.push(c);
    }
    parts.push(current);
    parts
}

/// The name this pass gives a lock: the argument with casts, address-of and
/// whitespace removed. Two syntactically different spellings of one mutex stay
/// different here, and two spellings that happen to match stay equal; aliasing
/// is listed as unsupported for exactly this reason.
fn lock_expression(arg: &str) -> String {
    let mut text = arg.trim();
    while text.starts_with('(') {
        let Some(close) = matching(text, 0) else { break };
        if close + 1 >= text.len() {
            break;
        }
        text = text[close + 1..].trim();
    }
    let text = text.trim_start_matches(['&', '*', ' ']);
    text.split_whitespace().collect::<Vec<_>>().join("")
}

/// The function an argument names, for the entry point of pthread_create.
fn entry_function(arg: &str) -> Option<String> {
    let text = lock_expression(arg);
    let name = text.trim_end_matches(['(', ')']);
    (!name.is_empty() && is_head(name.as_bytes()[0]) && name.bytes().all(is_tail))
        .then(|| name.to_string())
}

// ──────────────────────────────────────────────────────────────────────────
// Structure
// ──────────────────────────────────────────────────────────────────────────

struct Function {
    name: String,
    /// One name per parameter, in order, "" for an unnamed one, so an index
    /// into it is an index into the argument list of a call.
    params: Vec<String>,
}

struct FileScan {
    path: String,
    lines: Vec<String>,
    /// The function owning each line, or None at file scope.
    owner: Vec<Option<usize>>,
    /// Whether each line sits inside a for, while or do block.
    in_loop: Vec<bool>,
    functions: Vec<Function>,
    globals: BTreeSet<String>,
    /// Globals declared "_Atomic" or with a stdatomic type such as
    /// "atomic_int". Every access to one is atomic.
    atomics: BTreeSet<String>,
}

/// The declarator names a statement introduces. "int a, b;" gives both, and
/// "int arr[10];" gives "arr" rather than the subscript text. Several
/// statements on one line are read separately, because a whole thread body is
/// routinely written on one.
fn declarators(statement: &str) -> Vec<String> {
    if opens_member_list(statement) {
        return Vec::new();
    }
    statement.split(';').flat_map(fragment_names).collect()
}

/// Whether the text defines an aggregate rather than declaring data. The names
/// inside such a brace are members of the type and not declarations of this
/// scope, and a definition written on one line put every one of them in the
/// global set: "struct point { int x, y; };" made each "p->x" in the file an
/// access to one shared zone named "x", whoever owned the structure. The same
/// definition spread over several lines never did, because its members sit
/// inside a block this scan already steps over.
fn opens_member_list(statement: &str) -> bool {
    let tag = identifiers(statement)
        .into_iter()
        .rfind(|(_, name)| ["struct", "union", "enum"].contains(name));
    let Some((start, name)) = tag else {
        return false;
    };
    let after = start + name.len();
    let Some(brace) = statement[after..].find('{') else {
        return false;
    };
    // Only the type's own name may stand between the tag and its member list.
    // Anything else, "struct S *p) {" for instance, is a brace belonging to
    // something other than this tag.
    statement[after..after + brace]
        .split_whitespace()
        .all(is_identifier)
}

/// The text before an initializer or a subscript, with pointer stars spaced out
/// so the declared name is the last token of it.
fn declarator_head(part: &str) -> String {
    part.split(['=', '['])
        .next()
        .unwrap_or_default()
        .replace('*', " ")
}

fn is_identifier(token: &str) -> bool {
    !token.is_empty() && is_head(token.as_bytes()[0]) && token.bytes().all(is_tail)
}

/// A declaration names a type before it names anything, which is what tells it
/// from the assignment beside it: "int local = 0" declares and "local = 1" does
/// not. Reading the second as a declaration made every assigned expression a
/// zone of its own.
fn fragment_names(fragment: &str) -> Vec<String> {
    // The declarator text ends where the initializer begins, so a brace past
    // that point opens an aggregate initializer rather than a scope. Scanning
    // the whole fragment for one dropped "int shared[4] = {0};" entirely, which
    // left every access to that array without a zone.
    let declared = fragment.split('=').next().unwrap_or(fragment);
    let start = declared.rfind(['{', '}']).map_or(0, |at| at + 1);
    let body = &fragment[start..];
    if declared_part(body).contains('(') {
        return Vec::new();
    }
    let parts = split_top_level(body);
    let head = declarator_head(parts.first().map(String::as_str).unwrap_or_default());
    let tokens: Vec<&str> = head.split_whitespace().collect();
    if tokens.len() < 2 || !tokens.iter().all(|token| is_identifier(token)) {
        return Vec::new();
    }
    parts.iter().filter_map(|part| declarator_name(part)).collect()
}

fn declarator_name(part: &str) -> Option<String> {
    let head = declarator_head(part);
    let name = head.split_whitespace().next_back()?;
    (is_identifier(name) && !KEYWORDS.contains(&name)).then(|| name.to_string())
}

/// The text a declaration declares in, which is everything before its
/// initializer. A macro or a call on the right of the "=" says nothing about
/// whether the left declares an object.
fn declared_part(statement: &str) -> &str {
    statement.split('=').next().unwrap_or(statement)
}

/// Whether a cleaned line is a plain data declaration: it ends a statement and
/// its declarator opens no call, which excludes a prototype and a function
/// pointer alike.
///
/// The parenthesis test reads the declarator rather than the line, because an
/// initializer routinely holds a call: "int limit = SEC(5);" declares limit,
/// and rejecting it on the parentheses made the global disappear along with
/// every access to it.
fn is_declaration(line: &str) -> bool {
    line.ends_with(';')
        && !declared_part(line).contains('(')
        && !line.starts_with('#')
        && !line.is_empty()
}

/// The name of the function a header declares, given the text from the end of
/// the previous statement up to the opening brace. Reading a buffer rather than
/// one line is what makes a definition written with its brace on the next line
/// visible, which is most C.
fn header_function(header: &str) -> Option<String> {
    let text = header.split('{').next()?;
    let open = parameter_list(text)?;
    let before = &text[..open];
    let name = identifiers(before).pop()?.1.to_string();
    (!KEYWORDS.contains(&name.as_str())).then_some(name)
}

/// The parameter names of the function a header declares, in order.
fn header_params(header: &str) -> Vec<String> {
    let text = header.split('{').next().unwrap_or_default();
    let Some(open) = parameter_list(text) else {
        return Vec::new();
    };
    let Some(close) = matching(text, open) else {
        return Vec::new();
    };
    split_top_level(&text[open + 1..close])
        .iter()
        .map(|part| parameter_name(part))
        .collect()
}

/// The name one parameter declares: the last identifier of its declarator,
/// or the first inside its bracket for "int (*cb)(int)". A lone type such as
/// "void" names nothing.
fn parameter_name(part: &str) -> String {
    if let Some(open) = part.find('(') {
        let named = identifiers(&part[open..]).first().map(|(_, name)| name.to_string());
        return named.unwrap_or_default();
    }
    let head = declarator_head(part);
    let names = identifiers(&head);
    match names.len() {
        0 | 1 => String::new(),
        _ => names.last().map(|(_, name)| name.to_string()).unwrap_or_default(),
    }
}

/// The offset where the parameter list opens: the last bracket opened at depth
/// zero, since an attribute macro can open one before it. Taking the last
/// bracket at any depth named "void apply(int (*cb)(int))" after its callback
/// parameter, so the body of a function taking one belonged to a function
/// nothing calls and lost its thread attribution.
fn parameter_list(text: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut found = None;
    for (offset, c) in text.char_indices() {
        if c == '(' && depth == 0 {
            found = Some(offset);
        }
        depth += i32::from(c == '(') - i32::from(c == ')');
    }
    found
}

/// Brace bookkeeping for one line.
struct Blocks {
    depth: usize,
    loops: Vec<bool>,
    header: String,
}

/// Whether the text opens with this keyword rather than with an identifier
/// that merely starts the same way, so "ifdef" is not an "if".
///
/// The byte after the keyword can be missing, because a keyword alone on a
/// line is ordinary C: "do" opens a do-while that way and "else" is written
/// that way in most of the C there is. Indexing for that byte panicked, and
/// the panic took the whole scan with it.
fn starts_with_word(head: &str, word: &str) -> bool {
    head.starts_with(word)
        && head
            .as_bytes()
            .get(word.len())
            .is_none_or(|byte| !is_tail(*byte))
}

/// Where the body of a brace-less conditional or loop on one line sits.
enum Branch {
    /// No brace-less branch head on this line.
    None,
    /// The head ends the line, so the body is the next statement.
    NextLine,
    /// The body follows the head on this line, so it is scoped to this line.
    SameLine,
}

/// A conditional or loop whose body is one statement, with no brace to scope
/// it, and on which side of the line break that statement sits.
///
/// Reading only "does this line open a branch" scoped the wrong statement
/// twice over on the single-line form. "if (c) pthread_mutex_lock(&m);" left
/// its lock in the enclosing frame, so every access below it in the function
/// was reported as holding a mutex taken under a condition; and the line after
/// it, which is not the branch body, was wrapped in a block of its own.
fn branch_on(line: &str) -> Branch {
    let mut head = line.trim_start();
    if head.contains('{') {
        return Branch::None;
    }
    // "else if (c)" is two branch heads, so the "else" is stepped past rather
    // than read as a branch whose body is the "if" beside it.
    let mut saw_else = false;
    while starts_with_word(head, "else") {
        saw_else = true;
        head = head["else".len()..].trim_start();
    }
    let opens_condition = ["if", "for", "while"]
        .iter()
        .any(|word| starts_with_word(head, word));
    if !opens_condition {
        return match (saw_else, head.is_empty()) {
            (false, _) => Branch::None,
            // "else" alone; the body is whatever comes next.
            (true, true) => Branch::NextLine,
            // "else shared = 1;" carries its own body.
            (true, false) => Branch::SameLine,
        };
    }
    // A condition whose bracket wraps puts the body on a later line either way.
    let Some(close) = head.find('(').and_then(|open| matching(head, open)) else {
        return Branch::NextLine;
    };
    match head[close + 1..].trim().is_empty() {
        true => Branch::NextLine,
        false => Branch::SameLine,
    }
}

fn opens_loop(line: &str) -> bool {
    let head = line.trim_start();
    ["for", "while", "do"]
        .iter()
        .any(|word| starts_with_word(head, word))
}

fn structure(path: &str, lines: Vec<String>) -> FileScan {
    let mut scan = FileScan {
        path: path.to_string(),
        owner: vec![None; lines.len()],
        in_loop: vec![false; lines.len()],
        functions: Vec::new(),
        globals: BTreeSet::new(),
        atomics: BTreeSet::new(),
        lines,
    };
    let mut blocks = Blocks {
        depth: 0,
        loops: Vec::new(),
        header: String::new(),
    };
    let mut current: Option<usize> = None;
    // A loop whose body is one statement has no brace to hang a block on, and
    // "for (i = 0; i < n; i++) pthread_create(...)" on two lines is how a pool
    // is usually spawned.
    let mut pending_loop = false;
    for index in 0..scan.lines.len() {
        let line = scan.lines[index].trim().to_string();
        if blocks.depth == 0 {
            current = file_scope_line(&mut scan, &mut blocks, &line);
        }
        scan.owner[index] = current;
        // Carried from the previous line, which is what tells a brace opening a
        // loop body from one opening anything else. Reading only this line left
        // a loop whose brace sits on the next one, the Allman form, with a body
        // nothing marked, so a pool spawned inside it was reported as a single
        // thread that cannot race with itself.
        // A loop header with its body beside it is a loop on this line, not
        // on the next: "for (...) pthread_create(...);" spawns a pool, and
        // hanging the mark on the following line alone reported it as a thread
        // that runs once and cannot race with itself.
        let same_line_body = opens_loop(&line) && matches!(branch_on(&line), Branch::SameLine);
        let carried = pending_loop || same_line_body;
        scan.in_loop[index] = carried || blocks.loops.iter().any(|is_loop| *is_loop);
        pending_loop = opens_loop(&line) && matches!(branch_on(&line), Branch::NextLine);
        let opened = line.matches('{').count();
        let closed = line.matches('}').count();
        for _ in 0..opened {
            blocks.loops.push(carried || opens_loop(&line));
        }
        blocks.depth = blocks.depth + opened - closed.min(blocks.depth + opened);
        blocks.loops.truncate(blocks.depth);
        if blocks.depth == 0 {
            current = None;
        }
    }
    scan
}

/// Handle one line seen at file scope: it either declares data, contributes to
/// a function header, or opens a function body.
fn file_scope_line(scan: &mut FileScan, blocks: &mut Blocks, line: &str) -> Option<usize> {
    let unwrapped = unwrap_atomic_specifier(line);
    let line = unwrapped.as_str();
    if is_declaration(line) {
        let names = declarators(line);
        if declares_atomic(line, &names) {
            scan.atomics.extend(names.iter().cloned());
        }
        scan.globals.extend(names);
        blocks.header.clear();
        return None;
    }
    // The brace is checked before the semicolon, because a definition written
    // "void *worker(void *a) { shared = 1;" is both. Discarding it on the
    // semicolon dropped the function and every line of its body with it, and a
    // doubly spawned unprotected write in it reported clean.
    if !line.contains('{') && (line.ends_with(';') || line.starts_with('#')) {
        blocks.header.clear();
        return None;
    }
    blocks.header.push(' ');
    blocks.header.push_str(line);
    if !line.contains('{') {
        return None;
    }
    let header = std::mem::take(&mut blocks.header);
    let name = header_function(&header)?;
    let params = header_params(&header);
    scan.functions.push(Function { name, params });
    Some(scan.functions.len() - 1)
}

/// "_Atomic(int) x;" rewritten as "_Atomic int x;". The specifier form puts a
/// bracket in the declarator text, which is_declaration reads as a prototype,
/// so the global and every access to it would otherwise disappear.
fn unwrap_atomic_specifier(line: &str) -> String {
    let mut text = line.to_string();
    let mut from = 0;
    while let Some(found) = text[from..].find("_Atomic") {
        let after = from + found + "_Atomic".len();
        from = after;
        let rest = &text[after..];
        let Some(open) = rest.trim_start().starts_with('(').then(|| after + rest.find('(').unwrap_or(0)) else {
            continue;
        };
        let Some(close) = matching(&text, open) else { break };
        text = format!("{} {} {}", &text[..after], &text[open + 1..close], &text[close + 1..]);
    }
    text
}

/// Whether a declaration's type names an atomic object: the "_Atomic"
/// qualifier, or a stdatomic typedef such as "atomic_int". The declared names
/// themselves are not read, so "int atomic_count;" stays a plain global.
///
/// A tag is not a type either: "struct atomic_stats s;" names a plain struct,
/// and reading it as atomic made every pair of accesses to s atomic against
/// atomic, which never conflicts, so its races went unreported.
fn declares_atomic(line: &str, names: &[String]) -> bool {
    let tokens = identifiers(declared_part(line));
    tokens.iter().enumerate().any(|(at, (_, token))| {
        let tag = at > 0 && ["struct", "union", "enum"].contains(&tokens[at - 1].1);
        *token == "_Atomic"
            || (is_stdatomic_type(token) && !tag && !names.iter().any(|name| name == token))
    })
}

/// The stdatomic.h typedefs after their "atomic_" prefix, other than the
/// least-width and fast-width families, which is_stdatomic_type spells out.
const STDATOMIC_TYPES: &[&str] = &[
    "bool", "char", "schar", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "llong",
    "ullong", "char8_t", "char16_t", "char32_t", "wchar_t", "intptr_t", "uintptr_t", "size_t",
    "ptrdiff_t", "intmax_t", "uintmax_t", "flag",
];

/// Whether a token is one of the type names stdatomic.h defines.
///
/// Any "atomic_" prefix used to count, so a program's own typedef such as
/// "atomic_counter_t" made its globals atomic, and every pair of accesses to
/// them atomic against atomic, which never conflicts: their races went
/// unreported.
fn is_stdatomic_type(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("atomic_") else {
        return false;
    };
    if STDATOMIC_TYPES.contains(&rest) {
        return true;
    }
    let rest = rest.strip_prefix('u').unwrap_or(rest);
    let width = rest.strip_prefix("int_least").or_else(|| rest.strip_prefix("int_fast"));
    width.is_some_and(|width| ["8_t", "16_t", "32_t", "64_t"].contains(&width))
}

// ──────────────────────────────────────────────────────────────────────────
// Program-wide facts
// ──────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Spawn {
    sites: usize,
    in_loop: bool,
    /// The functions holding a pthread_create naming this entry.
    spawners: BTreeSet<String>,
    /// Some spawner may itself run more than once, so one textual site
    /// starts several threads. Kept apart from in_loop, which stays the
    /// lexical fact its name says.
    spawner_repeats: bool,
}

impl Spawn {
    /// One definition, because the set this drives decides which pairs are
    /// candidates and the payload reports the same fact to the caller. Spelled
    /// out in both places, they can disagree, and the report then contradicts
    /// the analysis behind it.
    fn may_repeat(&self) -> bool {
        self.sites > 1 || self.in_loop || self.spawner_repeats
    }
}

/// How often a defined function is called, as far as the text shows.
#[derive(Default)]
struct CallSites {
    count: usize,
    in_loop: bool,
}

#[derive(Default)]
struct Program {
    entries: BTreeMap<String, Spawn>,
    edges: BTreeMap<String, BTreeSet<String>>,
    /// Call sites per defined callee, the definition's own header excluded.
    calls: BTreeMap<String, CallSites>,
    defined: BTreeSet<String>,
    globals: BTreeSet<String>,
    atomics: BTreeSet<String>,
    /// Every pthread_create this pass saw, whether or not it could name the
    /// entry. Kept apart from "entries", which holds only the ones it resolved.
    spawn_calls: usize,
    /// Parameter names per defined function.
    params: BTreeMap<String, Vec<String>>,
    /// Defined functions named somewhere other than by a call this pass
    /// resolved: an address taken, a spawn argument, or a call whose bracket
    /// wraps. Each is a caller this pass cannot see, so its entry lockset is
    /// empty.
    indirect: BTreeSet<String>,
    /// Calls to the lock table. None means no summary or entry lockset can be
    /// anything but empty, and the walks that compute them are skipped.
    lock_calls: usize,
}

impl Program {
    /// Spawn sites whose entry function this pass could not name: the argument
    /// list wrapped to the next line, or the third argument is an expression
    /// rather than a function name.
    fn unresolved_spawns(&self) -> usize {
        let resolved: usize = self.entries.values().map(|spawn| spawn.sites).sum();
        self.spawn_calls.saturating_sub(resolved)
    }

    /// Whether some thread runs code this pass cannot attribute: a spawn
    /// whose entry it could not read, or one whose entry names no function
    /// defined here, which is what a creation wrapper taking its start routine
    /// as a parameter looks like. That thread's body is UNATTRIBUTED, and
    /// nothing says it is started once.
    fn has_unattributed_threads(&self) -> bool {
        self.unresolved_spawns() > 0
            || self.entries.keys().any(|name| !self.defined.contains(name))
    }
}

/// Thread entries, the call graph and the global set, gathered before any event
/// is emitted because a thread entry can be defined in another file than the
/// one that spawns it.
fn survey(files: &[FileScan]) -> Program {
    let mut program = Program::default();
    for file in files {
        program.globals.extend(file.globals.iter().cloned());
        program.atomics.extend(file.atomics.iter().cloned());
        program
            .defined
            .extend(file.functions.iter().map(|f| f.name.clone()));
        for function in &file.functions {
            program.params.insert(function.name.clone(), function.params.clone());
        }
    }
    for file in files {
        for (index, line) in file.lines.iter().enumerate() {
            survey_line(&mut program, file, line, index);
        }
    }
    let many = runs_more_than_once(&program);
    for spawn in program.entries.values_mut() {
        spawn.spawner_repeats = spawn.spawners.iter().any(|name| many.contains(name));
    }
    program
}

fn survey_line(program: &mut Program, file: &FileScan, line: &str, index: usize) {
    let caller = file.owner[index].map(|at| file.functions[at].name.clone());
    let tokens = identifiers(line);
    // Counted off the token rather than off the parsed call, because a spawn
    // whose argument list wraps to the next line has no closing bracket here
    // and so is not a call this pass can read, and one whose entry is an
    // expression resolves to no name. Either way it is still a spawn, and
    // whether any was seen is what separates "no candidate in a concurrent
    // program" from "this program is not concurrent".
    program.spawn_calls += tokens
        .iter()
        .filter(|(_, name)| *name == "pthread_create")
        .count();
    let in_loop = file.in_loop[index];
    let found = calls_among(line, &tokens);
    let resolved: BTreeSet<usize> = found.iter().map(|call| call.start).collect();
    let named = tokens.iter().filter(|(start, name)| {
        !resolved.contains(start) && program.defined.contains(*name)
    });
    program.indirect.extend(named.map(|(_, name)| name.to_string()));
    for call in found {
        program.lock_calls += usize::from(lock_api(&call.name).is_some());
        if call.name == "pthread_create" {
            record_spawn(program, &call, in_loop, caller.as_deref());
        }
        let Some(from) = caller.clone() else { continue };
        let own_header = names_its_own_definition(file, index, line, &call.name, call.start);
        if own_header || !program.defined.contains(&call.name) {
            continue;
        }
        let sites = program.calls.entry(call.name.clone()).or_default();
        sites.count += 1;
        sites.in_loop |= in_loop;
        program.edges.entry(from).or_default().insert(call.name);
    }
}

/// Whether this call is the name of the function a header on this line
/// defines. "void start(void) {" opens start's body, so the line belongs to
/// start and its own name reads as a call: a self edge that made every
/// function written this way look recursive, and a call site that made every
/// function look called one time more than it is.
fn names_its_own_definition(file: &FileScan, index: usize, line: &str, name: &str, start: usize) -> bool {
    let Some(owner) = file.owner[index] else {
        return false;
    };
    let first_line = index == 0 || file.owner[index - 1] != Some(owner);
    let before_body = !line[..start].contains('{');
    first_line && before_body && name == file.functions[owner].name
}

fn record_spawn(program: &mut Program, call: &Call, in_loop: bool, caller: Option<&str>) {
    let Some(entry) = call.args.get(2).and_then(|arg| entry_function(arg)) else {
        return;
    };
    let spawn = program.entries.entry(entry).or_default();
    spawn.sites += 1;
    // One textual site inside a loop is many threads, which is how most C
    // spawns a pool. Counting sites alone reported such a pool as a single
    // thread that could not race with itself.
    spawn.in_loop = spawn.in_loop || in_loop;
    spawn.spawners.extend(caller.map(str::to_string));
}

/// The defined functions that may run more than once.
///
/// A function runs more than once when it has two call sites, a call site in
/// a loop, takes part in recursion, is called by a function that runs more
/// than once, or is reachable from a thread entry that is spawned more than
/// once. The last two feed each other, since a spawn inside such a function is
/// itself a repeating spawn, so the set is grown to a fixpoint. It only grows,
/// and it is bounded by the defined functions, so the loop ends.
///
/// Two call sites outside any loop are two runs. Reading them as one, which
/// is what keying on the loop alone does, reported a pool started by calling
/// its creation helper twice as a single thread that cannot race with itself.
fn runs_more_than_once(program: &Program) -> BTreeSet<String> {
    let mut many: BTreeSet<String> = program
        .calls
        .iter()
        .filter(|(_, sites)| sites.count > 1 || sites.in_loop)
        .map(|(name, _)| name.clone())
        .collect();
    for component in components(&program.edges) {
        let calls_itself = program
            .edges
            .get(&component[0])
            .is_some_and(|callees| callees.contains(&component[0]));
        if component.len() > 1 || calls_itself {
            many.extend(component);
        }
    }
    loop {
        let before = many.len();
        let repeating_entries = program
            .entries
            .iter()
            .filter(|(_, spawn)| {
                spawn.sites > 1 || spawn.in_loop || spawn.spawners.iter().any(|f| many.contains(f))
            })
            .map(|(name, _)| name.clone());
        let seeds: Vec<String> = many.iter().cloned().chain(repeating_entries).collect();
        many = reach(&program.edges, seeds);
        if many.len() == before {
            return many;
        }
    }
}

/// Everything the call graph reaches from the seeds, the seeds included.
fn reach(edges: &BTreeMap<String, BTreeSet<String>>, seeds: Vec<String>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = seeds;
    while let Some(function) = queue.pop() {
        if !seen.insert(function.clone()) {
            continue;
        }
        queue.extend(edges.get(&function).into_iter().flatten().cloned());
    }
    seen
}

/// The strongly connected components of a graph, for recursion in the call
/// graph and for cycles in the lock order.
///
/// petgraph's Kosaraju, which walks with explicit stacks, so a chain of a
/// hundred thousand lock edges does not become a hundred thousand frames on
/// the small stack of the blocking worker this runs on. Not tarjan_scc, which
/// petgraph documents as recursive. Members and components are sorted, so the
/// payload does not depend on node insertion order.
fn components(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    let names: BTreeSet<&str> = graph
        .iter()
        .flat_map(|(from, to)| std::iter::once(from).chain(to))
        .map(String::as_str)
        .collect();
    let mut directed = petgraph::graph::DiGraph::<&str, ()>::new();
    let index: BTreeMap<&str, petgraph::graph::NodeIndex> =
        names.into_iter().map(|name| (name, directed.add_node(name))).collect();
    for (from, targets) in graph {
        for to in targets {
            directed.add_edge(index[from.as_str()], index[to.as_str()], ());
        }
    }
    let mut found: Vec<Vec<String>> = petgraph::algo::kosaraju_scc(&directed)
        .into_iter()
        .map(|members| {
            let mut names: Vec<String> = members.into_iter().map(|n| directed[n].to_string()).collect();
            names.sort();
            names
        })
        .collect();
    found.sort();
    found
}

/// The thread entries that can reach each function, by walking the call graph
/// from every entry and from main. A function no entry reaches is attributed
/// to UNATTRIBUTED rather than to nothing.
fn thread_sets(program: &Program) -> BTreeMap<String, BTreeSet<String>> {
    let mut sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut roots: Vec<String> = program.entries.keys().cloned().collect();
    if program.defined.contains("main") {
        roots.push("main".to_string());
    }
    for root in roots {
        for function in reach(&program.edges, vec![root.clone()]) {
            sets.entry(function).or_default().insert(root.clone());
        }
    }
    sets
}

/// The threads that may have more than one instance. UNATTRIBUTED joins them
/// whenever some thread runs code this pass cannot attribute: a wrapper that
/// takes its start routine as a parameter and is called twice is two threads
/// running one body, and that body is UNATTRIBUTED.
fn repeating(program: &Program) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = program
        .entries
        .iter()
        .filter(|(_, spawn)| spawn.may_repeat())
        .map(|(entry, _)| entry.clone())
        .collect();
    if program.has_unattributed_threads() {
        set.insert(UNATTRIBUTED.to_string());
    }
    set
}

// ──────────────────────────────────────────────────────────────────────────
// Events
// ──────────────────────────────────────────────────────────────────────────

struct Sink {
    events: Vec<Event>,
    total: usize,
    limit: usize,
}

impl Sink {
    fn push(&mut self, mut event: Event) {
        self.total += 1;
        event.id = format!("E{}", self.total);
        if self.events.len() < self.limit {
            self.events.push(event);
        }
    }
}

/// What happens at one offset of one line, in source order.
enum Action {
    Lock(&'static LockApi, String),
    Create(String),
    Join,
    Access(&'static str, String),
    /// A block opens here, and its lockset is the enclosing one until something
    /// on this line or a later one changes it.
    Open,
    /// A block closes here, restoring the lockset of the block around it.
    Close,
    /// A call to a function defined in the files, placed at its closing
    /// bracket so the accesses in its arguments come first.
    Call(CallAt),
    /// A "return" statement: one path out of the function, for its summary.
    Return,
}

/// Where a call to a defined function sits on its line.
struct CallAt {
    name: String,
    start: usize,
    open: usize,
    end: usize,
}

/// Whether the identifier ending at "end" is written by what follows it. A
/// subscript or a field selector is stepped over first, so "arr[i] = 1" and
/// "p->field = 1" are writes of the base zone.
fn is_written(line: &str, start: usize, end: usize) -> bool {
    // At most three bytes back, not the whole prefix trimmed twice: this runs
    // for every identifier that resolved to a memory zone.
    let before = line[..start].trim_end();
    if before.ends_with("++") || before.ends_with("--") {
        return true;
    }
    let mut rest = line[end..].trim_start();
    while rest.starts_with('[') || rest.starts_with('.') || rest.starts_with("->") {
        rest = step_suffix(rest);
    }
    if rest.starts_with("++") || rest.starts_with("--") {
        return true;
    }
    for operator in ["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"] {
        if rest.starts_with(&format!("{operator}=")) {
            return true;
        }
    }
    rest.starts_with('=') && !rest.starts_with("==")
}

fn step_suffix(rest: &str) -> &str {
    if let Some(close) = matching_bracket(rest) {
        return rest[close + 1..].trim_start();
    }
    let skipped = rest.trim_start_matches(['.', '-', '>']).trim_start();
    // The first token's length, not every token on the line. Tokenizing the
    // rest of the line to keep its first token made this quadratic in the line
    // length, which is the same hang paren_pairs fixed on the call side and
    // left standing here: 46s over a 200 KB line, with no timeout around it.
    let end = skipped
        .as_bytes()
        .iter()
        .position(|byte| !is_tail(*byte))
        .unwrap_or(skipped.len());
    match end {
        0 => skipped,
        _ => skipped[end..].trim_start(),
    }
}

fn matching_bracket(rest: &str) -> Option<usize> {
    if !rest.starts_with('[') {
        return None;
    }
    let mut depth = 0i32;
    for (offset, c) in rest.char_indices() {
        depth += i32::from(c == '[') - i32::from(c == ']');
        if depth == 0 {
            return Some(offset);
        }
    }
    None
}

/// The byte ranges a modelled call covers, so an identifier inside one is not
/// also read as a memory access. Excluding the whole line instead dropped
/// "shared = 1" from a one-line thread body that also took a lock.
///
/// Every call in the lock table counts, not only the pthread ones: the
/// argument of "sem_wait(&s)" is a semaphore handle, and reading it as a READ
/// of a global named s paired a synchronisation object against itself.
fn modelled_ranges(found: &[Call]) -> Vec<(usize, usize)> {
    found
        .iter()
        .filter(|call| is_modelled(&call.name))
        .map(|call| (call.start, call.end))
        .collect()
}

/// A zone a token names, and whether that zone is an atomic object.
type Zones<'a> = &'a dyn Fn(&str) -> Option<(String, bool)>;

/// The offset of the first token in "range" that names a zone.
fn first_zone(tokens: &[(usize, &str)], range: std::ops::Range<usize>, zones: Zones) -> Option<usize> {
    tokens
        .iter()
        .find(|(start, name)| range.contains(start) && zones(name).is_some())
        .map(|(start, _)| *start)
}

/// The offset of the token an atomic builtin accesses, keyed to the access
/// kind it performs there: the first token of the address argument that names
/// a zone. A compare-exchange also writes through its second argument, which
/// is keyed the same way as a plain WRITE. A builtin the program defines for
/// itself is an ordinary function and is read as one.
fn atomic_targets(
    tokens: &[(usize, &str)],
    found: &[Call],
    zones: Zones,
    defined: &BTreeSet<String>,
) -> BTreeMap<usize, &'static str> {
    let mut targets = BTreeMap::new();
    for call in found.iter().filter(|call| !defined.contains(&call.name)) {
        let (Some(kind), Some(first)) = (atomic_access(&call.name), call.args.first()) else {
            continue;
        };
        // Splitting keeps every byte but the separating comma, so the second
        // argument starts one byte after the first ends.
        let second_at = call.open + 1 + first.len() + 1;
        if let Some(start) = first_zone(tokens, call.open + 1..second_at - 1, zones) {
            targets.insert(start, kind);
        }
        let expected = call.args.get(1).filter(|_| writes_expected(&call.name));
        if let Some(start) = expected.and_then(|arg| first_zone(tokens, second_at..second_at + arg.len(), zones)) {
            targets.insert(start, "WRITE");
        }
    }
    targets
}

/// A plain access's kind, made atomic when the zone is an atomic object: an
/// assignment to an "_Atomic int" is an atomic store.
fn plain_kind(line: &str, start: usize, name: &str, atomic: bool) -> &'static str {
    match (is_written(line, start, start + name.len()), atomic) {
        (true, false) => "WRITE",
        (false, false) => "READ",
        (true, true) => "ATOMIC_WRITE",
        (false, true) => "ATOMIC_READ",
    }
}

fn actions_on_line(line: &str, zones: Zones, defined: &BTreeSet<String>) -> Vec<(usize, Action)> {
    let tokens = identifiers(line);
    let found = calls_among(line, &tokens);
    let covered = modelled_ranges(&found);
    let atomic = atomic_targets(&tokens, &found, zones, defined);
    let mut actions = Vec::new();
    for call in &found {
        actions.extend(call_action(call));
        if defined.contains(&call.name) && !is_modelled(&call.name) {
            let at = CallAt {
                name: call.name.clone(),
                start: call.start,
                open: call.open,
                end: call.end,
            };
            actions.push((call.end, Action::Call(at)));
        }
    }
    for (start, name) in tokens {
        if name == "return" {
            actions.push((statement_end(line, start), Action::Return));
            continue;
        }
        let inside = covered
            .iter()
            .any(|(from, to)| start >= *from && start <= *to);
        let Some((zone, atomic_zone)) = zones(name).filter(|_| !inside) else {
            continue;
        };
        let kind = match atomic.get(&start) {
            Some(kind) => *kind,
            None => plain_kind(line, start, name, atomic_zone),
        };
        actions.push((start, Action::Access(kind, zone)));
    }
    for (offset, c) in line.char_indices() {
        if c == '{' {
            actions.push((offset, Action::Open));
        }
        if c == '}' {
            actions.push((offset, Action::Close));
        }
    }
    actions.sort_by_key(|(offset, _)| *offset);
    actions
}

/// Where the statement starting at "start" ends on its line: its ";" at
/// bracket depth zero, or the end of the line. A return is placed there rather
/// than at its keyword, so the calls in its expression apply first:
/// "return pthread_mutex_lock(m);" returns holding m, and "return unlock(m);"
/// through a wrapper returns without it.
fn statement_end(line: &str, start: usize) -> usize {
    let mut depth = 0i32;
    for (offset, c) in line[start..].char_indices() {
        depth += i32::from(c == '(') - i32::from(c == ')');
        if depth <= 0 && matches!(c, ';' | '}') {
            return start + offset;
        }
    }
    line.len()
}

fn call_action(call: &Call) -> Option<(usize, Action)> {
    if call.name == "pthread_join" {
        return Some((call.start, Action::Join));
    }
    if call.name == "pthread_create" {
        let entry = call.args.get(2).and_then(|arg| entry_function(arg))?;
        return Some((call.start, Action::Create(entry)));
    }
    let api = lock_api(&call.name)?;
    let lock = match api.arg {
        None => ATOMIC_SECTION.to_string(),
        Some(at) => call
            .args
            .get(at)
            .map(|arg| lock_expression(arg))
            .unwrap_or_else(|| "<unknown>".into()),
    };
    Some((call.start, Action::Lock(api, lock)))
}

// ──────────────────────────────────────────────────────────────────────────
// Emission
// ──────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Context<'a> {
    program: &'a Program,
    sets: &'a BTreeMap<String, BTreeSet<String>>,
    repeat: &'a BTreeSet<String>,
    include_unshared: bool,
    interproc: &'a Interproc,
}

impl Context<'_> {
    fn threads_of(&self, function: &str) -> Vec<String> {
        match self.sets.get(function) {
            Some(set) if !set.is_empty() => set.iter().cloned().collect(),
            _ => vec![UNATTRIBUTED.to_string()],
        }
    }

    fn repeats(&self, threads: &[String]) -> bool {
        threads.iter().any(|thread| self.repeat.contains(thread))
    }
}

/// A lock held at some point, and in which mode.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Held {
    name: String,
    shared: bool,
}

/// What a block is the body of, which decides where a "break" or a
/// "continue" inside it lands.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum Body {
    #[default]
    Plain,
    /// A break or a continue lands at this block.
    Loop,
    /// A break lands right after this block; a continue passes through it to
    /// the loop around it.
    Switch,
}

/// One block's lockset, plus what a loop or a switch needs to merge at its
/// end: the locksets of the paths that left it by "break" or "continue" from
/// inside a nested block.
#[derive(Default)]
struct Frame {
    held: Vec<Held>,
    body: Body,
    exits: Vec<Vec<Held>>,
}

/// How the last statement of a block leaves it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Exit {
    /// Control reaches the code after the block.
    FallThrough,
    /// "return", or a call that does not return: the code after the block is
    /// not reached from here, so this path says nothing about it.
    Leaves,
    /// "break": the path lands after the nearest enclosing loop or switch,
    /// and is merged there instead of after this block.
    Breaks,
    /// "continue": the path lands at the nearest enclosing loop, passing
    /// through any switch on the way, and is merged after that loop.
    Continues,
    /// "goto": the path lands at a label, and is merged at the next label.
    Jumps,
}

/// Calls that do not return, so a block ending in one never falls through.
const NO_RETURN: &[&str] = &[
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "pthread_exit",
    "longjmp",
    "siglongjmp",
    "__assert_fail",
];

/// The statement that ends the text, read after its last separator at bracket
/// depth zero, so the semicolons of a for header do not split it.
fn last_statement(text: &str) -> &str {
    let mut depth = 0i32;
    let mut start = 0;
    for (offset, c) in text.char_indices() {
        depth += i32::from(c == '(') - i32::from(c == ')');
        if depth == 0 && matches!(c, ';' | '{' | '}') {
            start = offset + 1;
        }
    }
    text[start..].trim()
}

/// How a block whose text ends with "text" is left. Anything that is not
/// recognisably a jump falls through, which is the safe reading: it keeps the
/// intersection that never claims a lock held.
fn block_exit(text: &str) -> Exit {
    let Some(body) = text.trim_end().strip_suffix(';') else {
        return Exit::FallThrough;
    };
    let statement = last_statement(body);
    if starts_with_word(statement, "return") {
        return Exit::Leaves;
    }
    if starts_with_word(statement, "goto") {
        return Exit::Jumps;
    }
    if starts_with_word(statement, "break") {
        return Exit::Breaks;
    }
    if starts_with_word(statement, "continue") {
        return Exit::Continues;
    }
    let no_return = NO_RETURN.iter().any(|name| {
        starts_with_word(statement, name) && statement[name.len()..].trim_start().starts_with('(')
    });
    match no_return {
        true => Exit::Leaves,
        false => Exit::FallThrough,
    }
}

/// Whether a block opened after "head" is the body of a loop or a switch.
fn opened_body(head: &str) -> Body {
    let statement = last_statement(head);
    let statement = statement.strip_prefix("else").map_or(statement, str::trim_start);
    if opens_loop(statement) {
        return Body::Loop;
    }
    match starts_with_word(statement, "switch") {
        true => Body::Switch,
        false => Body::Plain,
    }
}

/// Whether a path leaving by "exit" lands at a block that is "body".
fn lands_at(exit: Exit, body: Body) -> bool {
    match exit {
        Exit::Breaks => body != Body::Plain,
        Exit::Continues => body == Body::Loop,
        _ => false,
    }
}

/// Whether the line opens with a goto label, "out:" and not "default:".
fn is_label(line: &str) -> bool {
    let line = line.trim_start();
    let end = line.bytes().position(|byte| !is_tail(byte)).unwrap_or(line.len());
    let name = &line[..end];
    let rest = line[end..].trim_start();
    is_identifier(name)
        && !["default", "case"].contains(&name)
        && rest.starts_with(':')
        && !rest.starts_with("::")
}

fn intersect(outer: &mut Vec<Held>, path: &[Held]) {
    outer.retain(|lock| path.contains(lock));
}

/// The state the emission pass carries from one line to the next.
struct Walk {
    stack: Vec<Frame>,
    locals: BTreeSet<String>,
    /// Locksets of the paths that left a block by "goto", merged at the next
    /// label of the function. A backward goto lands on code already emitted,
    /// which this pass cannot revisit, the same limit it has at a loop head.
    gotos: Vec<Vec<Held>>,
    /// The last non-blank line, for a brace with nothing before it on its own.
    previous: String,
    /// The previous line was the body of a brace-less branch, so a jump on it
    /// is conditional and does not end the block around it.
    previous_conditional: bool,
}

impl Walk {
    fn new() -> Self {
        Walk {
            stack: vec![Frame::default()],
            locals: BTreeSet::new(),
            gotos: Vec::new(),
            previous: String::new(),
            previous_conditional: false,
        }
    }

    /// A lockset is restored when its block closes, so a lock taken inside an
    /// "if" is not held by the code after it. The lock is evidence either way,
    /// but a lockset that leaks out of a conditional is evidence for something
    /// that never happened.
    ///
    /// This used to open every block on the line before the line was emitted
    /// and close every one after, which is the right order only when a line
    /// does not do both. On "} else {" it applied the open first, so the else
    /// branch inherited the lockset of the branch above it, and the test that
    /// was supposed to catch that released its lock inside the branch and so
    /// passed on the unlock rather than on the block. Braces are ordinary
    /// positioned actions now, applied in source order with everything else on
    /// the line.
    fn enter(&mut self, body: Body) {
        let held = self.stack.last().map(|frame| frame.held.clone()).unwrap_or_default();
        self.stack.push(Frame {
            held,
            body,
            exits: Vec::new(),
        });
    }

    /// Open the block whose brace follows "before" on its line.
    fn open(&mut self, before: &str) {
        let head = match before.trim().is_empty() {
            true => self.previous.clone(),
            false => before.to_string(),
        };
        self.enter(opened_body(&head));
    }

    /// Close the block whose brace follows "before" on its line, and return
    /// the lockset held at that brace.
    fn close(&mut self, before: &str) -> Option<Vec<Held>> {
        let exit = match (before.trim().is_empty(), self.previous_conditional) {
            (false, _) => block_exit(before),
            (true, false) => block_exit(&self.previous),
            (true, true) => Exit::FallThrough,
        };
        self.leave(exit)
    }

    /// Leaving a block keeps only what is held both before it and at its end.
    ///
    /// Restoring the enclosing set was symmetric, and locking is not. A lock
    /// taken inside a block must not escape it, which restoring does correctly;
    /// a lock released inside one must escape, and restoring resurrected it. So
    ///
    ///     pthread_mutex_lock(&m);
    ///     if (1) { pthread_mutex_unlock(&m); }
    ///     shared = 1;
    ///
    /// reported the write as holding m, and unlock-in-both-branches is the
    /// shape real code takes. That is this pass manufacturing its own primary
    /// evidence, which is worse than missing a lock: lock_note then tells the
    /// caller both accesses hold a mutex that was released.
    ///
    /// Intersection is the must-lockset rule and it is right in both
    /// directions, because a block may not have run. It also drops a lock
    /// taken by a block that certainly did run, which is the safe way to be
    /// wrong here: this pass never needs to claim a lock is held.
    ///
    /// A block that ends by leaving is the exception, because its path never
    /// reaches the code after it. Intersecting it anyway dropped the lock from
    /// the early-return idiom, "if (err) { unlock(&m); return; }", so every
    /// access after that guard was reported as holding nothing. A path that
    /// breaks or jumps is not dropped but moved to where it lands: after the
    /// enclosing loop or switch for a break, after the enclosing loop for a
    /// continue, or at the next label.
    ///
    /// A continue used to land at the nearest switch like a break does, so a
    /// path that unlocked and continued from inside a switch was merged after
    /// the switch, which it never reaches, and dropped the lock from every
    /// access between the switch and the end of the loop.
    fn leave(&mut self, exit: Exit) -> Option<Vec<Held>> {
        // Never the last frame: a file with unbalanced braces, which is any
        // file this pass was handed mid-edit, would otherwise leave nothing to
        // hold the next function's locks.
        if self.stack.len() <= 1 {
            return None;
        }
        let inner = self.stack.pop()?;
        let exit = match lands_at(exit, inner.body) {
            true => Exit::FallThrough,
            false => exit,
        };
        let landing = self.stack.iter().rposition(|frame| lands_at(exit, frame.body));
        match (exit, landing) {
            (Exit::Leaves, _) => {}
            (Exit::Jumps, _) => self.gotos.push(inner.held.clone()),
            (Exit::Breaks | Exit::Continues, Some(at)) => self.stack[at].exits.push(inner.held.clone()),
            _ => intersect(&mut self.stack.last_mut()?.held, &inner.held),
        }
        let outer = self.stack.last_mut()?;
        for path in &inner.exits {
            intersect(&mut outer.held, path);
        }
        Some(inner.held)
    }

    /// A label is where a goto lands, so every path that jumped is merged in.
    fn land(&mut self) {
        let Some(frame) = self.stack.last_mut() else { return };
        for path in &self.gotos {
            intersect(&mut frame.held, path);
        }
    }

    fn held(&mut self) -> &mut Vec<Held> {
        if self.stack.is_empty() {
            self.stack.push(Frame::default());
        }
        let last = self.stack.len() - 1;
        &mut self.stack[last].held
    }

    /// The current lockset as event fields: every name held, and the ones held
    /// in shared mode. A function whose name marks it atomic runs entirely
    /// under ATOMIC_SECTION.
    fn lockset(&self, atomic_function: bool) -> (Vec<String>, Vec<String>) {
        let held = self.stack.last().map(|frame| frame.held.as_slice()).unwrap_or_default();
        let mut names: Vec<String> = held.iter().map(|lock| lock.name.clone()).collect();
        let shared = held.iter().filter(|l| l.shared).map(|l| l.name.clone()).collect();
        if atomic_function && !names.iter().any(|name| name == ATOMIC_SECTION) {
            names.insert(0, ATOMIC_SECTION.to_string());
        }
        (names, shared)
    }
}

/// Where a lock operation happened, and which threads may have performed it.
struct Site<'a> {
    file: &'a str,
    line: usize,
    threads: &'a [String],
}

/// How many acquisition sites one lock order edge keeps. The count is kept
/// whole; only the list of places is cut.
const SITES_PER_EDGE: usize = 16;

#[derive(Default)]
struct EdgeSites {
    sites: Vec<(String, usize)>,
    count: usize,
    threads: BTreeSet<String>,
    /// Some site of this pair held "from" or took "to" in exclusive mode.
    exclusive: bool,
}

/// The lock order graph, one entry per ordered pair of lock names.
///
/// The list it replaces held one entry per acquisition site with no bound,
/// so a lock taken under another in a loop body of a long file repeated the
/// same pair once per line, and nothing read it as a graph. A pair is kept
/// once with its sites, up to "cap" pairs, and a site whose pair did not fit
/// is counted rather than dropped silently.
#[derive(Default)]
struct LockGraph {
    edges: BTreeMap<(String, String), EdgeSites>,
    cap: usize,
    sites_dropped: usize,
    /// Every lock taken in exclusive mode anywhere, trylocks and acquisitions
    /// with nothing else held included, uncapped: a reader can queue behind
    /// any one of them.
    writers: BTreeSet<String>,
}

impl LockGraph {
    /// Note an acquisition of "lock", so a lock ever taken for writing is
    /// known whether or not the acquisition recorded an edge.
    ///
    /// Skipped on a zero-cap graph, which is what the fact walks use and then
    /// discard: a graph that can hold no edge can hold no cycle for the writers
    /// to keep.
    fn take(&mut self, lock: &str, shared: bool) {
        if self.cap == 0 {
            return;
        }
        if !shared && !self.writers.contains(lock) {
            self.writers.insert(lock.to_string());
        }
    }

    /// Record "from" held while "to" is taken. "shared" is true only when
    /// both ends are held in shared mode at this site.
    fn record(&mut self, from: &str, to: &str, shared: bool, site: &Site) {
        let key = (from.to_string(), to.to_string());
        if self.edges.len() >= self.cap && !self.edges.contains_key(&key) {
            self.sites_dropped += 1;
            return;
        }
        let edge = self.edges.entry(key).or_default();
        edge.count += 1;
        edge.exclusive |= !shared;
        edge.threads.extend(site.threads.iter().cloned());
        if edge.sites.len() < SITES_PER_EDGE {
            edge.sites.push((site.file.to_string(), site.line));
        }
    }
}

/// Remove the innermost hold of a lock, and say whether there was one.
fn release(held: &mut Vec<Held>, lock: &str) -> bool {
    let Some(at) = held.iter().rposition(|other| other.name == lock) else {
        return false;
    };
    held.remove(at);
    true
}

/// Apply one lock call to the held set, and return true for a release of a
/// lock that was not held, which is what makes a function an unlock wrapper.
/// "inherited" names held locks that record no order edge into this one: the
/// entry lockset, when the lock is one of the function's own parameters.
fn apply_lock(
    api: &LockApi,
    lock: &str,
    held: &mut Vec<Held>,
    inherited: &[String],
    site: &Site,
    graph: &mut LockGraph,
) -> bool {
    let ordered = |outer: &&Held| !inherited.contains(&outer.name);
    match api.op {
        LockOp::Release => return !release(held, lock),
        // A trylock can return EBUSY, so it is recorded as an event and never
        // as a lock held. Holding it claims protection on the path where the
        // call failed, which is this pass manufacturing its own primary
        // evidence, the thing leave goes out of its way not to do. The order
        // edge goes with it: a lock that may not have been taken cannot
        // deadlock against the one acquired under it. Every timed variant
        // fails the same way, by timing out.
        LockOp::Try => graph.take(lock, api.mode == LockMode::Shared),
        LockOp::Acquire => {
            let shared = api.mode == LockMode::Shared;
            graph.take(lock, shared);
            for outer in held.iter().filter(ordered) {
                graph.record(&outer.name, lock, outer.shared && shared, site);
            }
            held.push(Held {
                name: lock.to_string(),
                shared: api.mode == LockMode::Shared,
            });
        }
        // The mutex is taken again on return while everything else held is
        // still held, so each of those is ordered before it once more. Only
        // when the mutex is lexically held: otherwise this pass cannot tell
        // which lock is being waited with.
        LockOp::Wait if held.iter().any(|other| other.name == lock) => {
            graph.take(lock, false);
            for outer in held.iter().filter(|other| other.name != lock).filter(ordered) {
                graph.record(&outer.name, lock, false, site);
            }
        }
        LockOp::Wait => graph.take(lock, false),
    }
    false
}

// ──────────────────────────────────────────────────────────────────────────
// Interprocedural locksets
// ──────────────────────────────────────────────────────────────────────────

/// A lock named in a function summary.
#[derive(Clone, PartialEq, Eq, Debug)]
enum LockRef {
    /// A lock named the same way at every call site.
    Name(String),
    /// The lock a parameter points at, renamed to the argument at each call.
    Param(usize),
    /// Reached through a parameter, but not the parameter itself, such as
    /// "m->inner": no call site can name it, so every call site counts it in
    /// lock_arguments_unresolved.
    Opaque,
    /// Some lock this pass cannot name: a callee released one, or the
    /// summaries did not settle. It was already counted where it arose, so a
    /// call site applying it counts nothing.
    Unknown,
}

/// What calling a function does to the caller's held set.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct Summary {
    /// Held on every return, starting from nothing held, with the shared
    /// flag. A must-set, so a lock taken on one path only is not acquired.
    acquired: Vec<(LockRef, bool)>,
    /// Released on some path without having been taken there. A may-set,
    /// because dropping a lock the caller holds only removes a claim.
    released: Vec<LockRef>,
}

/// The facts the walks carry across calls.
#[derive(Default)]
struct Interproc {
    summaries: BTreeMap<String, Summary>,
    /// The locks held at every call site of a function, carried into its body.
    entries: BTreeMap<String, Vec<Held>>,
}

/// What one walk of the program saw at returns, releases and call sites.
#[derive(Default)]
struct Facts {
    /// The intersection of the held sets at every return of each function.
    returns: BTreeMap<String, Vec<Held>>,
    /// Locks each function released while not holding them.
    released: BTreeMap<String, BTreeSet<String>>,
    /// Functions that may release a lock this pass cannot name.
    releases_unknown: BTreeSet<String>,
    /// The intersection of the caller's held set at every call site of each
    /// defined function.
    sites: BTreeMap<String, Vec<Held>>,
    /// Call sites whose summary named a parameter no argument resolved.
    unresolved_arguments: usize,
}

/// Fold one path into a running intersection keyed by function.
fn meet(slot: &mut BTreeMap<String, Vec<Held>>, key: &str, path: Vec<Held>) {
    match slot.get_mut(key) {
        Some(sofar) => intersect(sofar, &path),
        None => {
            slot.insert(key.to_string(), path);
        }
    }
}

/// How many walks a fixpoint may take before it is given up. A chain of
/// wrappers needs one round per link, plus one to see nothing changed.
const LOCK_SUMMARY_ROUNDS: usize = 16;

fn lock_ref(name: &str, params: &[String]) -> LockRef {
    let named = |candidate: &str| params.iter().any(|p| !p.is_empty() && p == candidate);
    if let Some(at) = params.iter().position(|p| !p.is_empty() && p == name) {
        return LockRef::Param(at);
    }
    match identifiers(name).first() {
        Some((_, lead)) if named(lead) => LockRef::Opaque,
        _ => LockRef::Name(name.to_string()),
    }
}

fn params_of<'a>(program: &'a Program, function: &str) -> &'a [String] {
    program.params.get(function).map(Vec::as_slice).unwrap_or_default()
}

/// The summaries one walk implies. The walk must have run with every entry
/// lockset empty, so a lock held at a return was taken by the function.
fn summaries_from(facts: &Facts, program: &Program) -> BTreeMap<String, Summary> {
    let mut found = BTreeMap::new();
    for function in &program.defined {
        let params = params_of(program, function);
        let mut summary = Summary::default();
        // An Opaque entry is kept once per lock it stands for, so a call site
        // counts each one it cannot name. Dropping it here, as this used to,
        // made a lock wrapper over "m->inner" acquire nothing without a trace.
        for held in facts.returns.get(function).into_iter().flatten() {
            let named = lock_ref(&held.name, params);
            let fresh = named == LockRef::Opaque || !summary.acquired.iter().any(|(other, _)| *other == named);
            if held.name != "<unknown>" && fresh {
                summary.acquired.push((named, held.shared));
            }
        }
        for name in facts.released.get(function).into_iter().flatten() {
            let named = lock_ref(name, params);
            if named == LockRef::Opaque || !summary.released.contains(&named) {
                summary.released.push(named);
            }
        }
        let unknown = facts.releases_unknown.contains(function);
        if unknown && !summary.released.contains(&LockRef::Unknown) {
            summary.released.push(LockRef::Unknown);
        }
        if summary != Summary::default() {
            found.insert(function.clone(), summary);
        }
    }
    found
}

/// The entry locksets one walk implies. A thread entry, main, and a function
/// some caller reaches in a way this pass cannot see all start with nothing.
fn entries_from(facts: &Facts, program: &Program) -> BTreeMap<String, Vec<Held>> {
    facts
        .sites
        .iter()
        .filter(|(callee, held)| {
            !held.is_empty()
                && callee.as_str() != "main"
                && !program.entries.contains_key(*callee)
                && !program.indirect.contains(*callee)
        })
        .map(|(callee, held)| (callee.clone(), held.clone()))
        .collect()
}

/// The lock an argument names, when it is a plain identifier that is not a
/// local of the caller: a global, a global pointer, or the caller's own
/// parameter, which is how one wrapper composes into another.
fn argument_lock(line: &str, call: &CallAt, at: usize, locals: &BTreeSet<String>) -> Option<String> {
    let args = split_top_level(&line[call.open + 1..call.end]);
    let name = lock_expression(args.get(at)?);
    (is_identifier(&name) && !locals.contains(&name)).then_some(name)
}

/// A call to a defined function: record the caller's held set for the
/// callee's entry lockset, then apply the callee's summary to it.
fn call_site(ctx: &Context, caller: &str, call: &CallAt, line: &str, walk: &mut Walk, site: &Site, out: &mut Emission) {
    let params = params_of(ctx.program, caller);
    let carried: Vec<Held> = walk.held().iter().filter(|h| !params.contains(&h.name)).cloned().collect();
    meet(&mut out.facts.sites, &call.name, carried);
    let Some(summary) = ctx.interproc.summaries.get(&call.name) else {
        return;
    };
    let resolve = |named: &LockRef| match named {
        LockRef::Name(name) => Some(name.clone()),
        LockRef::Param(at) => argument_lock(line, call, *at, &walk.locals),
        LockRef::Opaque | LockRef::Unknown => None,
    };
    let counted = |named: &LockRef| matches!(named, LockRef::Param(_) | LockRef::Opaque);
    let released: Vec<(bool, Option<String>)> = summary
        .released
        .iter()
        .map(|named| (counted(named), resolve(named)))
        .collect();
    let acquired: Vec<(Option<String>, bool)> = summary
        .acquired
        .iter()
        .map(|(named, shared)| (resolve(named), *shared))
        .collect();
    for (param, name) in released {
        let held = walk.held();
        match name {
            Some(name) if !release(held, &name) => {
                out.facts.released.entry(caller.to_string()).or_default().insert(name);
            }
            Some(_) => {}
            None => {
                held.clear();
                out.facts.releases_unknown.insert(caller.to_string());
                out.facts.unresolved_arguments += usize::from(param);
            }
        }
    }
    for (name, shared) in acquired {
        let Some(name) = name else {
            out.facts.unresolved_arguments += 1;
            continue;
        };
        let held = walk.held();
        out.graph.take(&name, shared);
        for outer in held.iter() {
            out.graph.record(&outer.name, &name, outer.shared && shared, site);
        }
        held.push(Held { name, shared });
    }
}

/// One walk over every file, keeping only the facts.
fn walk_for_facts(scans: &[FileScan], ctx: &Context, deadline: Deadline) -> Option<Facts> {
    let mut facts = Facts::default();
    let mut graph = LockGraph {
        edges: BTreeMap::new(),
        cap: 0,
        ..LockGraph::default()
    };
    let mut unreleased = Vec::new();
    for file in scans {
        let mut out = Emission {
            sink: None,
            graph: &mut graph,
            unreleased: &mut unreleased,
            facts: &mut facts,
        };
        if !emit_file(file, ctx, &mut out, deadline) {
            return None;
        }
    }
    Some(facts)
}

/// One summary round made monotone: an acquisition survives only if the
/// previous round had it too, and a release once seen stays.
///
/// The plain step is not monotone, because a callee's releases shrink its
/// caller's acquisitions, so mutual recursion can make it alternate between
/// two answers forever. Measured on a pair of recursive wrappers that lock
/// and unlock each other's mutex: a two-round cycle. Acquisitions can only
/// fall and releases only rise from here, both over finite sets, so the
/// rounds settle. The result claims no more than its own recomputation would,
/// which is the safe side. It is applied only after the plain rounds have had
/// the chance to climb a chain of wrappers, which narrowing from the first
/// round would cut at its first link.
fn widen(previous: &BTreeMap<String, Summary>, next: BTreeMap<String, Summary>) -> BTreeMap<String, Summary> {
    let names: BTreeSet<&String> = previous.keys().chain(next.keys()).collect();
    let mut widened = BTreeMap::new();
    for name in names {
        let before = previous.get(name).cloned().unwrap_or_default();
        let after = next.get(name).cloned().unwrap_or_default();
        let mut summary = Summary {
            acquired: after.acquired.into_iter().filter(|held| before.acquired.contains(held)).collect(),
            released: before.released,
        };
        for named in after.released {
            if !summary.released.contains(&named) {
                summary.released.push(named);
            }
        }
        if summary != Summary::default() {
            widened.insert(name.clone(), summary);
        }
    }
    widened
}

/// Lock summaries, then entry locksets, each by repeated walks. None when the
/// deadline passed during a walk. The flag is false when the summaries did not
/// settle within LOCK_SUMMARY_ROUNDS, in which case every function is taken
/// to acquire nothing and to release anything, which only removes claims.
///
/// The entry rounds are left at whatever round they reach: the step is
/// monotone and starts from nothing held, so every round claims less than the
/// fixpoint does, and stopping early is safe where it was not for summaries.
fn interprocedural(scans: &[FileScan], base: &Context, deadline: Deadline) -> Option<(Interproc, bool)> {
    let mut interproc = Interproc::default();
    if base.program.lock_calls == 0 {
        return Some((interproc, true));
    }
    let mut converged = false;
    for round in 0..LOCK_SUMMARY_ROUNDS {
        let ctx = Context { interproc: &interproc, include_unshared: false, ..*base };
        let mut next = summaries_from(&walk_for_facts(scans, &ctx, deadline)?, base.program);
        if round >= LOCK_SUMMARY_ROUNDS / 2 {
            next = widen(&interproc.summaries, next);
        }
        converged = next == interproc.summaries;
        if converged {
            break;
        }
        interproc.summaries = next;
    }
    if !converged {
        let unknown = Summary {
            acquired: Vec::new(),
            released: vec![LockRef::Unknown],
        };
        interproc.summaries = base.program.defined.iter().map(|f| (f.clone(), unknown.clone())).collect();
    }
    for _ in 0..LOCK_SUMMARY_ROUNDS {
        let ctx = Context { interproc: &interproc, include_unshared: false, ..*base };
        let next = entries_from(&walk_for_facts(scans, &ctx, deadline)?, base.program);
        if next == interproc.entries {
            break;
        }
        interproc.entries = next;
    }
    Some((interproc, converged))
}

fn lock_ref_json(named: &LockRef, params: &[String]) -> serde_json::Value {
    match named {
        LockRef::Name(name) => json!({"lock": name}),
        LockRef::Param(at) => json!({"parameter": at, "name": params.get(*at)}),
        LockRef::Opaque | LockRef::Unknown => json!({"unknown": true}),
    }
}

fn summary_json(function: &str, summary: &Summary, params: &[String]) -> serde_json::Value {
    let acquires: Vec<serde_json::Value> = summary
        .acquired
        .iter()
        .map(|(named, shared)| {
            let mut value = lock_ref_json(named, params);
            let mode = if *shared { "shared" } else { "exclusive" };
            if let Some(fields) = value.as_object_mut() {
                fields.insert("mode".into(), json!(mode));
            }
            value
        })
        .collect();
    let releases: Vec<serde_json::Value> =
        summary.released.iter().map(|named| lock_ref_json(named, params)).collect();
    json!({"function": function, "acquires": acquires, "releases": releases})
}

/// The lock summaries and entry locksets, for the payload.
fn interproc_json(interproc: &Interproc, program: &Program) -> (serde_json::Value, serde_json::Value) {
    let summaries: Vec<serde_json::Value> = interproc
        .summaries
        .iter()
        .map(|(function, summary)| summary_json(function, summary, params_of(program, function)))
        .collect();
    let entries: Vec<serde_json::Value> = interproc
        .entries
        .iter()
        .map(|(function, held)| {
            let locks: Vec<&str> = held.iter().map(|lock| lock.name.as_str()).collect();
            json!({"function": function, "locks": locks})
        })
        .collect();
    (serde_json::Value::Array(summaries), serde_json::Value::Array(entries))
}

struct Emission<'a> {
    /// None for a walk that gathers facts only: up to two dozen of them run
    /// before the emitting one, and building an event they then drop cost a
    /// clone of its thread and lock sets per access.
    sink: Option<&'a mut Sink>,
    graph: &'a mut LockGraph,
    unreleased: &'a mut Vec<serde_json::Value>,
    facts: &'a mut Facts,
}

/// A thread entry that still holds a lock at its closing brace returns with
/// it held, and the next acquisition of that lock by any thread blocks for
/// good. Only entries are reported: a helper that returns holding a lock is
/// how a lock wrapper is written.
fn report_unreleased(
    ctx: &Context,
    function: Option<&str>,
    held: Option<Vec<Held>>,
    site: &Site,
    out: &mut Emission,
) {
    let (Some(entry), Some(held)) = (function, held) else {
        return;
    };
    if held.is_empty() || !ctx.program.entries.contains_key(entry) {
        return;
    }
    let locks: Vec<&str> = held.iter().map(|lock| lock.name.as_str()).collect();
    out.unreleased.push(json!({
        "status": "potential",
        "entry": entry,
        "locks": locks,
        "source": {"file": site.file, "line": site.line},
        "reason": "the thread entry's closing brace is reached with these locks lexically held",
        "provenance": "syntax",
    }));
}

/// Apply one lock call in "function". Two acquisitions record no edge from
/// the entry lockset, because the call site already records it. One is of a
/// lock named by the function's own parameter: the call site records the edge
/// under the argument's real name, and an edge into a parameter's name means
/// nothing outside the function. The other is of a lock the function still
/// holds on every return, a lock wrapper: the call site applies the summary
/// and records the same edge, so recording it here too counted one
/// acquisition twice, with two sites, under "lock_m()" called while holding A.
fn lock_action(
    ctx: &Context,
    function: &str,
    api: &LockApi,
    lock: &str,
    walk: &mut Walk,
    site: &Site,
    out: &mut Emission,
) {
    let own_param = params_of(ctx.program, function).iter().any(|p| p == lock);
    let wrapped = ctx.interproc.summaries.get(function).is_some_and(|summary| {
        summary
            .acquired
            .iter()
            .any(|(named, _)| matches!(named, LockRef::Name(name) if name == lock))
    });
    let inherited: Vec<String> = match own_param || wrapped {
        true => ctx.interproc.entries.get(function).into_iter().flatten().map(|h| h.name.clone()).collect(),
        false => Vec::new(),
    };
    if apply_lock(api, lock, walk.held(), &inherited, site, out.graph) {
        out.facts.released.entry(function.to_string()).or_default().insert(lock.to_string());
    }
}

fn emit_line(file: &FileScan, ctx: &Context, index: usize, walk: &mut Walk, out: &mut Emission) {
    let line = &file.lines[index];
    // A line at file scope emits no event, but its braces still move the block
    // stack: a struct definition or an initializer would otherwise unbalance it
    // for every function after it.
    let function = file.owner[index].map(|at| file.functions[at].name.clone());
    let named = function.clone().unwrap_or_default();
    let threads = function.as_ref().map(|name| ctx.threads_of(name)).unwrap_or_default();
    let may_repeat = ctx.repeats(&threads);
    let atomic_function = named.starts_with(ATOMIC_FUNCTION_PREFIX);
    let locals = &walk.locals;
    let zones = |name: &str| -> Option<(String, bool)> {
        if ctx.program.globals.contains(name) {
            return Some((name.to_string(), ctx.program.atomics.contains(name)));
        }
        (ctx.include_unshared && locals.contains(name)).then(|| (format!("{named}::{name}"), false))
    };
    let actions = actions_on_line(line, &zones, &ctx.program.defined);
    if function.is_some() && is_label(line) {
        walk.land();
    }
    let site = Site {
        file: &file.path,
        line: index + 1,
        threads: &threads,
    };
    for (offset, action) in actions {
        let (kind, zone, lock_mode) = match action {
            Action::Open => {
                walk.open(&line[..offset]);
                // A function body starts holding what every caller holds.
                let body = walk.stack.len() == 2 && function.is_some();
                let entry = ctx.interproc.entries.get(&named).filter(|_| body);
                walk.held().extend(entry.into_iter().flatten().cloned());
                continue;
            }
            Action::Close => {
                let held = walk.close(&line[..offset]);
                let ended = walk.stack.len() == 1 && function.is_some();
                if let Some(path) = held.as_ref().filter(|_| ended) {
                    meet(&mut out.facts.returns, &named, path.clone());
                }
                report_unreleased(ctx, function.as_deref().filter(|_| ended), held, &site, out);
                continue;
            }
            Action::Return => {
                let path = walk.held().clone();
                meet(&mut out.facts.returns, &named, path);
                continue;
            }
            Action::Call(call) => {
                let own = names_its_own_definition(file, index, line, &call.name, call.start);
                if function.is_some() && !own {
                    call_site(ctx, &named, &call, line, walk, &site, out);
                }
                continue;
            }
            Action::Lock(api, lock) => {
                lock_action(ctx, &named, api, &lock, walk, &site, out);
                let mode = match api.mode {
                    LockMode::Exclusive => "exclusive",
                    LockMode::Shared => "shared",
                };
                (lock_kind(api.op), Some(lock), Some(mode))
            }
            Action::Create(entry) => ("THREAD_CREATE", Some(entry), None),
            Action::Join => ("THREAD_JOIN", None, None),
            Action::Access(kind, zone) => (kind, Some(zone), None),
        };
        let Some(sink) = out.sink.as_deref_mut() else { continue };
        let Some(function) = function.clone() else { continue };
        let (lockset, read_locks) = walk.lockset(atomic_function);
        sink.push(Event {
            id: String::new(),
            threads: threads.clone(),
            may_repeat,
            kind,
            file: file.path.clone(),
            line: index + 1,
            function,
            zone,
            lockset,
            read_locks,
            lock_mode,
        });
    }
}

fn emit_file(file: &FileScan, ctx: &Context, out: &mut Emission, deadline: Deadline) -> bool {
    let mut walk = Walk::new();
    let mut pending_branch = false;
    for index in 0..file.lines.len() {
        if deadline.passed() {
            return false;
        }
        let line = file.lines[index].trim().to_string();
        // Gathered whatever include_unshared says, because a lock argument
        // naming a local cannot be renamed into a callee's summary. Zones
        // still read the set only under include_unshared.
        if file.owner[index].is_some() {
            let named = declarators(&line);
            let fresh = named.into_iter().filter(|n| !ctx.program.globals.contains(n));
            walk.locals.extend(fresh);
        }
        // "if (c) pthread_mutex_lock(&m);" scopes its lock to one statement
        // with no brace to hang it on, and it is ordinary C. Only a line whose
        // own braces balance is wrapped, so a body written as a block on the
        // next line is left to the braces themselves.
        //
        // Both sides of the line break are wrapped, because both are that one
        // statement: the branch body written beside its head is scoped to the
        // line it shares, and the body written under a bare head is scoped to
        // the line below. Wrapping only the second left the single-line form
        // leaking its lock into the rest of the function, and wrapped the line
        // after it, which is not the body at all.
        let branch = branch_on(&line);
        let balanced = line.matches('{').count() == line.matches('}').count();
        let wrapped = (pending_branch || matches!(branch, Branch::SameLine)) && balanced;
        if wrapped {
            walk.enter(Body::Plain);
        }
        emit_line(file, ctx, index, &mut walk, out);
        if wrapped {
            walk.leave(Exit::FallThrough);
        }
        if !line.is_empty() {
            walk.previous = line;
            walk.previous_conditional = pending_branch;
        }
        pending_branch = matches!(branch, Branch::NextLine);
        if walk.stack.len() == 1 {
            walk.locals.clear();
            walk.gotos.clear();
        }
    }
    true
}

// ──────────────────────────────────────────────────────────────────────────
// Lock order report
// ──────────────────────────────────────────────────────────────────────────

fn sites_json(edge: &EdgeSites) -> Vec<serde_json::Value> {
    edge.sites
        .iter()
        .map(|(file, line)| json!({"file": file, "line": line}))
        .collect()
}

/// One lock order edge. "from", "to" and "source" are the fields the
/// per-site list carried, so a reader of that list still finds them; "source"
/// is the first site.
fn edge_json(from: &str, to: &str, edge: &EdgeSites) -> serde_json::Value {
    let sites = sites_json(edge);
    json!({
        "from": from,
        "to": to,
        "source": sites.first().cloned(),
        "sites": sites,
        "site_count": edge.count,
        "threads": edge.threads,
    })
}

fn double_lock_json(lock: &str, edge: &EdgeSites) -> serde_json::Value {
    json!({
        "status": "potential",
        "lock": lock,
        "sites": sites_json(edge),
        "site_count": edge.count,
        "threads": edge.threads,
        "reason": "acquired while lexically already held: a self-deadlock for a default mutex; harmless for a recursive mutex, and for a second read lock unless a writer is queued; a second wait on a semaphore blocks unless its count covers both; this pass sees neither attributes nor counts",
        "provenance": "syntax",
    })
}

/// Whether two thread sets may run at the same time. See may_run_concurrently,
/// which is this question asked of two events.
fn threads_concurrent(left: &[String], right: &[String], repeat: &BTreeSet<String>) -> bool {
    // The pairwise loop this replaces returned false only when both events
    // named one and the same thread that is spawned once, so it paid a
    // quadratic string comparison for a question with a closed form, on the
    // false branch, which is the one the pair budget is charged for.
    match (left, right) {
        ([], _) | (_, []) => false,
        // UNATTRIBUTED is not a thread, it is the absence of an answer: the
        // function is reached by nothing the call graph saw, which includes
        // every call through a pointer. Treating it as one thread that runs
        // once discarded the pair, which is the claim its own name refuses to
        // make.
        ([one], [other]) if one == other => repeat.contains(one) || one == UNATTRIBUTED,
        _ => true,
    }
}

/// A cycle of the lock order, reported per strongly connected component of
/// two locks or more, and only when two of its edges may be taken by threads
/// running at once. A cycle whose every edge belongs to one thread that runs
/// once is an order that thread takes both ways at different times, which
/// cannot deadlock against itself.
fn cycle_json(
    members: &[String],
    edges: &[(&(String, String), &EdgeSites)],
    repeat: &BTreeSet<String>,
) -> Option<serde_json::Value> {
    let (_, first) = edges.first()?;
    let first: Vec<String> = first.threads.iter().cloned().collect();
    let concurrent = edges.iter().any(|(_, edge)| {
        let threads: Vec<String> = edge.threads.iter().cloned().collect();
        threads_concurrent(&first, &threads, repeat)
    });
    if !concurrent {
        return None;
    }
    let threads: BTreeSet<&String> = edges.iter().flat_map(|(_, edge)| &edge.threads).collect();
    let listed: Vec<serde_json::Value> = edges
        .iter()
        .map(|((from, to), edge)| edge_json(from, to, edge))
        .collect();
    Some(json!({
        "status": "potential",
        "locks": members,
        "edges": listed,
        "threads": threads,
        "reason": "these locks are acquired in a cyclic order by code that may run concurrently",
        "provenance": "syntax",
        "next_analysis": "alias_and_happens_before",
    }))
}

/// Whether a cycle is taken only by readers: every acquisition on every one
/// of its edges held both locks in shared mode, and no lock in it is taken in
/// exclusive mode anywhere. Two read locks never block each other, so such a
/// cycle cannot close on its own.
///
/// A reader can still wait behind a queued writer, which is how a cycle of
/// read locks deadlocks under a writer-preferring rwlock. So a single
/// exclusive acquisition of any member, even one with nothing else held and
/// so on no edge, keeps the cycle. Edges alone missed that writer, which is
/// why the lock graph keeps the writers apart from its capped edge list.
fn readers_only(members: &[String], edges: &[(&(String, String), &EdgeSites)], writers: &BTreeSet<String>) -> bool {
    edges.iter().all(|(_, edge)| !edge.exclusive) && !members.iter().any(|lock| writers.contains(lock))
}

struct LockReport {
    order: Vec<serde_json::Value>,
    double_lock: Vec<serde_json::Value>,
    deadlocks: Vec<serde_json::Value>,
}

fn lock_report(graph: &LockGraph, repeat: &BTreeSet<String>, threads_detected: bool) -> LockReport {
    let mut adjacency: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut report = LockReport {
        order: Vec::new(),
        double_lock: Vec::new(),
        deadlocks: Vec::new(),
    };
    for ((from, to), edge) in &graph.edges {
        report.order.push(edge_json(from, to, edge));
        if from == to {
            report.double_lock.push(double_lock_json(from, edge));
            continue;
        }
        adjacency.entry(from.clone()).or_default().insert(to.clone());
    }
    // Nothing spawns a thread, so no order can deadlock against another.
    if !threads_detected {
        return report;
    }
    let cycles: Vec<Vec<String>> = components(&adjacency)
        .into_iter()
        .filter(|members| members.len() > 1)
        .collect();
    let mut component_of: BTreeMap<&str, usize> = BTreeMap::new();
    for (at, members) in cycles.iter().enumerate() {
        component_of.extend(members.iter().map(|name| (name.as_str(), at)));
    }
    let mut inside: Vec<Vec<(&(String, String), &EdgeSites)>> = vec![Vec::new(); cycles.len()];
    for (key, edge) in &graph.edges {
        let from = component_of.get(key.0.as_str());
        let same = from == component_of.get(key.1.as_str());
        if let (Some(at), true) = (from, same) {
            inside[*at].push((key, edge));
        }
    }
    for (members, edges) in cycles.iter().zip(&inside) {
        if readers_only(members, edges, &graph.writers) {
            continue;
        }
        report.deadlocks.extend(cycle_json(members, edges, repeat));
    }
    report
}

// ──────────────────────────────────────────────────────────────────────────
// Candidates
// ──────────────────────────────────────────────────────────────────────────

/// How many pairs may be examined per candidate the caller is willing to read.
///
/// The cap on candidates bounds the response and not the work: counting them
/// honestly means enumerating every pair in a zone, which is quadratic in the
/// accesses to it, and at the event ceiling that is billions of comparisons for
/// a list of a few thousand. The budget buys a bounded scan at the price of a
/// count that can be partial, and a partial count says so rather than passing
/// itself off as a total.
const PAIRS_PER_CANDIDATE: usize = 1_024;

struct Candidates {
    emitted: Vec<serde_json::Value>,
    total: usize,
    cap: usize,
    budget: usize,
    exhausted: bool,
    timed_out: bool,
}

impl Candidates {
    /// Count always, build only what is kept. The budget allows up to a
    /// thousand pairs per candidate the caller asked for, so building the
    /// object before the cap was consulted threw away millions of nine-key
    /// JSON objects to keep a few thousand.
    fn push(&mut self, candidate: impl FnOnce() -> serde_json::Value) {
        self.total += 1;
        if self.emitted.len() < self.cap {
            self.emitted.push(candidate());
        }
    }

    /// Charge one pair comparison, or report that the scan has to stop.
    fn spend(&mut self) -> bool {
        if self.budget == 0 {
            self.exhausted = true;
            return false;
        }
        self.budget -= 1;
        true
    }
}

/// Two events can run at once when some thread of one differs from some thread
/// of the other, or when they share a thread that is spawned more than once.
/// Nothing here models a join, so a thread that has certainly finished still
/// counts: this pass does not own the evidence that would let it say otherwise.
fn may_run_concurrently(left: &Event, right: &Event, repeat: &BTreeSet<String>) -> bool {
    threads_concurrent(&left.threads, &right.threads, repeat)
}

/// The locks both events hold that could exclude one from the other. A lock
/// both hold in shared mode excludes nothing between them, since two readers
/// of an rwlock run together, so it is not listed as evidence for the pair.
fn common_locks(left: &Event, right: &Event) -> Vec<String> {
    left.lockset
        .iter()
        .filter(|lock| right.lockset.contains(lock))
        .filter(|lock| !(left.read_locks.contains(lock) && right.read_locks.contains(lock)))
        .cloned()
        .collect()
}

/// The locks an access holds that would exclude a second instance of itself,
/// which is every one it holds except in shared mode.
fn exclusive_locks(access: &Event) -> Vec<String> {
    access
        .lockset
        .iter()
        .filter(|lock| !access.read_locks.contains(lock))
        .cloned()
        .collect()
}

/// The lock note attached to a candidate. It never changes the status, because
/// a lexical lockset cannot rule a race out: the acquisition may be
/// conditional, the two names may be different mutexes, and this pass has not
/// looked at either question.
fn lock_note(shared: &[String]) -> serde_json::Value {
    if shared.is_empty() {
        return json!(null);
    }
    json!({
        "common_lexical_locks": shared,
        "note": "Both accesses lexically hold these names. That is evidence, not protection: acquisition is not path sensitive here and two spellings are not proof of one mutex.",
    })
}

fn pair_candidate(left: &Event, right: &Event) -> serde_json::Value {
    let shared = common_locks(left, right);
    let mut threads: Vec<String> = left.threads.iter().chain(&right.threads).cloned().collect();
    threads.sort();
    threads.dedup();
    json!({
        "status": "potential",
        "accesses": [left.id, right.id],
        "memory_zone": left.zone,
        "kinds": [left.kind, right.kind],
        "threads": threads,
        "lock_evidence": lock_note(&shared),
        "reason": match is_atomic(left.kind) || is_atomic(right.kind) {
            true => "an atomic access against a plain one, which its atomicity does not order",
            false => "conflicting accesses that this pass cannot order",
        },
        "provenance": "syntax",
        "next_analysis": "alias_and_happens_before",
    })
}

fn self_candidate(access: &Event) -> serde_json::Value {
    json!({
        "status": "potential",
        "accesses": [access.id, access.id],
        "memory_zone": access.zone,
        "kinds": [access.kind, access.kind],
        "threads": access.threads,
        "lock_evidence": lock_note(&exclusive_locks(access)),
        "reason": "the same write may execute in more than one instance of its thread",
        "provenance": "syntax",
        "next_analysis": "alias_and_happens_before",
    })
}

fn zone_candidates(
    group: &[&Event],
    repeat: &BTreeSet<String>,
    out: &mut Candidates,
    deadline: Deadline,
) {
    for (index, left) in group.iter().enumerate() {
        for right in group.iter().skip(index + 1) {
            if deadline.passed() {
                out.timed_out = true;
                return;
            }
            if !out.spend() {
                return;
            }
            if conflicting(left.kind, right.kind) && may_run_concurrently(left, right, repeat) {
                out.push(|| pair_candidate(left, right));
            }
        }
    }
}

/// Pairing runs per memory zone rather than over every access, because two
/// accesses to different zones can never be a candidate. On the shape that
/// matters, one hot global, this is the same work; on a file with many zones it
/// is the difference between a response and a hang.
fn candidate_list(
    events: &[Event],
    repeat: &BTreeSet<String>,
    cap: usize,
    deadline: Deadline,
) -> Candidates {
    let mut by_zone: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
    for event in events.iter().filter(|e| is_access(e.kind)) {
        if deadline.passed() {
            return Candidates {
                emitted: Vec::new(),
                total: 0,
                cap,
                budget: 0,
                exhausted: false,
                timed_out: true,
            };
        }
        let Some(zone) = event.zone.as_deref() else { continue };
        by_zone.entry(zone).or_default().push(event);
    }
    let mut out = Candidates {
        emitted: Vec::new(),
        total: 0,
        cap,
        budget: cap.saturating_mul(PAIRS_PER_CANDIDATE).max(PAIRS_PER_CANDIDATE),
        exhausted: false,
        timed_out: false,
    };
    for event in events.iter().filter(|e| e.kind == "WRITE" && e.may_repeat) {
        if deadline.passed() {
            out.timed_out = true;
            return out;
        }
        out.push(|| self_candidate(event));
    }
    for group in by_zone.values() {
        if out.exhausted || out.timed_out {
            break;
        }
        zone_candidates(group, repeat, &mut out, deadline);
    }
    out.timed_out |= deadline.passed();
    out
}

// ──────────────────────────────────────────────────────────────────────────
// Payload
// ──────────────────────────────────────────────────────────────────────────

fn event_json(event: &Event) -> serde_json::Value {
    let mut value = json!({
        "id": event.id,
        "threads": event.threads,
        "thread_may_repeat": event.may_repeat,
        "kind": event.kind,
        "source_location": {"file": event.file, "line": event.line},
        "function": event.function,
        "memory_zone": event.zone,
        "lockset": event.lockset,
        "provenance": "syntax",
    });
    // Only where they say something, because the event list is most of the
    // payload: a field on every event that is null on nearly all of them
    // costs bytes at the event ceiling and tells the reader nothing.
    let Some(fields) = value.as_object_mut() else {
        return value;
    };
    if let Some(mode) = event.lock_mode {
        fields.insert("lock_mode".into(), json!(mode));
    }
    if !event.read_locks.is_empty() {
        fields.insert("read_lockset".into(), json!(event.read_locks));
    }
    value
}

/// Read one source, refusing anything that is not a regular file.
///
/// A fifo, a character device or a directory is not a translation unit, and
/// read_to_string on the first two does not return. Refusing by file type
/// reports the reason instead of hanging, and a scan that names one still
/// reports every other file it was given.
fn read_source_file(path: &str) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|error| error.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    fs::read_to_string(path).map_err(|error| error.to_string())
}

/// Read every file, then screen them together: a thread entry is routinely
/// defined in a different translation unit from the pthread_create naming it.
pub fn scan_sources(
    files: &[String],
    max_events: usize,
    max_candidates: usize,
    include_unshared: bool,
) -> serde_json::Value {
    scan_within(files, max_events, max_candidates, include_unshared, CONCURRENCY_SCAN_BUDGET)
}

/// The same, with the budget named, so a test can watch the scan give up.
pub fn scan_within(
    files: &[String],
    max_events: usize,
    max_candidates: usize,
    include_unshared: bool,
    budget: std::time::Duration,
) -> serde_json::Value {
    scan_to_deadline(
        files,
        max_events,
        max_candidates,
        include_unshared,
        Deadline::new(budget),
    )
}

fn scan_to_deadline(
    files: &[String],
    max_events: usize,
    max_candidates: usize,
    include_unshared: bool,
    deadline: Deadline,
) -> serde_json::Value {
    let mut scans = Vec::new();
    let mut unreadable = Vec::new();
    let mut read_within_deadline = true;
    for file in files {
        // The budget covers reading too. It used to start at the emission
        // pass, so a caller naming a fifo or a character device blocked in
        // read_to_string forever, and since a blocking task cannot be
        // cancelled that thread was never coming back.
        if deadline.passed() {
            read_within_deadline = false;
            break;
        }
        match read_source_file(file) {
            Ok(text) => scans.push(structure(file, strip_noise(&text))),
            Err(error) => unreadable.push(json!({"file": file, "error": error})),
        }
    }
    let program = survey(&scans);
    let sets = thread_sets(&program);
    let repeat = repeating(&program);
    let nothing_known = Interproc::default();
    let base = Context {
        program: &program,
        sets: &sets,
        repeat: &repeat,
        include_unshared,
        interproc: &nothing_known,
    };
    // A deadline passed during the fixpoint walks leaves nothing carried
    // across calls, which claims no lock, and the scan says it is incomplete.
    let (interproc, summaries_converged, read_within_deadline) =
        match read_within_deadline.then(|| interprocedural(&scans, &base, deadline)).flatten() {
            Some((found, converged)) => (found, converged, true),
            None => (Interproc::default(), true, false),
        };
    let context = Context {
        interproc: &interproc,
        ..base
    };
    let mut facts = Facts::default();
    let mut sink = Sink {
        events: Vec::new(),
        total: 0,
        limit: max_events,
    };
    let mut graph = LockGraph {
        edges: BTreeMap::new(),
        // The same limit as the event list: a lock order edge is one more
        // thing the scan found, and the caller set how much of that to keep.
        cap: max_events,
        ..LockGraph::default()
    };
    let mut unreleased = Vec::new();
    let mut within_deadline = read_within_deadline;
    for file in &scans {
        if !within_deadline {
            break;
        }
        within_deadline = emit_file(
            file,
            &context,
            &mut Emission {
                sink: Some(&mut sink),
                graph: &mut graph,
                unreleased: &mut unreleased,
                facts: &mut facts,
            },
            deadline,
        );
    }
    // Any spawn at all, not only the ones whose entry resolved. Reading this
    // off "entries" made a program whose pthread_create wraps its argument
    // list, which is how most of them are written, report threads_detected
    // false, no candidates and a complete enumeration: exactly the "no race
    // here" verdict this pass exists not to give.
    let threads_detected = program.spawn_calls > 0;
    let candidates = match threads_detected {
        true => candidate_list(&sink.events, &repeat, max_candidates, deadline),
        // No pthread_create anywhere is not a thread whose entry was missed:
        // it is a program this pass has no reason to call concurrent. Pairing
        // regardless would make every write in single threaded code a race
        // candidate against itself.
        false => Candidates {
            emitted: Vec::new(),
            total: 0,
            cap: max_candidates,
            budget: 0,
            exhausted: false,
            timed_out: deadline.passed(),
        },
    };
    let locks = lock_report(&graph, &repeat, threads_detected);
    let (lock_summaries, entry_locksets) = interproc_json(&interproc, &program);
    payload(PayloadParts {
        files,
        events: &sink,
        threads_detected,
        entries: &program,
        candidates,
        locks,
        lock_edges: graph.edges.len(),
        lock_sites_dropped: graph.sites_dropped,
        unreleased,
        unreadable,
        within_deadline,
        lock_summaries,
        entry_locksets,
        summaries_converged,
        arguments_unresolved: facts.unresolved_arguments,
    })
}

struct PayloadParts<'a> {
    files: &'a [String],
    events: &'a Sink,
    threads_detected: bool,
    entries: &'a Program,
    candidates: Candidates,
    locks: LockReport,
    /// Distinct ordered lock pairs kept, and acquisition sites whose pair did
    /// not fit under the cap.
    lock_edges: usize,
    lock_sites_dropped: usize,
    unreleased: Vec<serde_json::Value>,
    unreadable: Vec<serde_json::Value>,
    /// False when the scan gave up its own budget partway, which makes every
    /// count below a floor.
    within_deadline: bool,
    lock_summaries: serde_json::Value,
    entry_locksets: serde_json::Value,
    /// False when the summary fixpoint hit its round cap and every function
    /// was taken to release anything.
    summaries_converged: bool,
    /// Call sites whose summary named a parameter no argument resolved.
    arguments_unresolved: usize,
}

fn payload(parts: PayloadParts) -> serde_json::Value {
    let kept = parts.candidates.emitted.len();
    let entries: Vec<serde_json::Value> = parts
        .entries
        .entries
        .iter()
        .map(|(name, spawn)| {
            json!({"entry": name, "spawn_sites": spawn.sites, "spawned_in_loop": spawn.in_loop,
                "spawner_may_repeat": spawn.spawner_repeats, "may_repeat": spawn.may_repeat()})
        })
        .collect();
    let events: Vec<serde_json::Value> = parts.events.events.iter().map(event_json).collect();

    // Inserted rather than written as one json! object, because json! sends
    // every non-literal expression through serde_json::to_value, which rebuilds
    // each node of a Value that is already built. The vectors here are the
    // whole payload, so that turned the assembly into a deep copy of it: 40% of
    // the scan's wall time at the event ceiling, and 12 million allocations.
    // json_result one layer up carries the same warning for the same reason.
    // The literal sub-objects below stay in json!, where there is nothing to
    // copy. With preserve_order the insertion order is the key order, so the
    // document is unchanged.
    let mut out = serde_json::Map::new();
    let mut put = |key: &str, value: serde_json::Value| {
        out.insert(key.to_string(), value);
    };
    put("schema", json!("frama-c-mcp.concurrency.v1"));
    put("analysis_level", json!(0));
    put("analysis", json!("syntactic_screening"));
    put("files", serde_json::Value::from(parts.files.to_vec()));
    put("threads_detected", json!(parts.threads_detected));
    put("thread_entries", serde_json::Value::Array(entries));
    // Spawns this pass saw but could not name an entry for. Every one of them
    // is a thread missing from thread_entries, so the functions it reaches are
    // attributed to no thread and their accesses pair only as unattributed
    // ones. Reported rather than left implicit, because the difference between
    // thread_entries being short and being right is not otherwise visible.
    put("unresolved_spawn_sites", json!(parts.entries.unresolved_spawns()));
    put("event_count", json!(parts.events.total));
    put(
        "events_omitted",
        json!(parts.events.total.saturating_sub(events.len())),
    );
    put("events", serde_json::Value::Array(events));
    put("candidate_count", json!(parts.candidates.total));
    put(
        "candidates_omitted",
        json!(parts.candidates.total.saturating_sub(kept)),
    );
    // False when the pair budget stopped the scan, when the event limit dropped
    // an event (pairing runs over the events that were kept, so a truncated
    // event list is a truncated enumeration), and when a file did not decode.
    // In each case candidate_count is a floor, and reading it as a total would
    // turn a bounded scan into an undercount nothing declared.
    put(
        "candidate_enumeration_complete",
        json!(!parts.candidates.exhausted
            && !parts.candidates.timed_out
            && parts.events.total == parts.events.events.len()
            && parts.unreadable.is_empty()
            && parts.within_deadline),
    );
    put(
        "candidates",
        serde_json::Value::Array(parts.candidates.emitted),
    );
    put(
        "scan_complete",
        json!(parts.within_deadline && !parts.candidates.timed_out),
    );
    put("lock_order", serde_json::Value::Array(parts.locks.order));
    put("lock_order_count", json!(parts.lock_edges));
    put("lock_order_sites_omitted", json!(parts.lock_sites_dropped));
    // A cycle among dropped edges is a cycle nothing reports, so a cut graph
    // makes deadlock_candidates a floor in the same way a cut event list
    // makes candidate_count one.
    put(
        "lock_order_complete",
        json!(parts.lock_sites_dropped == 0 && parts.within_deadline),
    );
    put("double_lock", serde_json::Value::Array(parts.locks.double_lock));
    put(
        "deadlock_candidates",
        serde_json::Value::Array(parts.locks.deadlocks),
    );
    put("unreleased_lock", serde_json::Value::Array(parts.unreleased));
    // What a call does to the caller's locks, and what a callee inherits.
    // Each lockset above already includes both; these say where they came from.
    put("lock_summaries", parts.lock_summaries);
    put("lock_summaries_converged", json!(parts.summaries_converged));
    put("entry_locksets", parts.entry_locksets);
    put("lock_arguments_unresolved", json!(parts.arguments_unresolved));
    put(
        "unreadable_files",
        serde_json::Value::Array(parts.unreadable),
    );
    put(
        "evidence",
        json!({
            "all_claims": "syntax",
            "soundness": "candidate generation only; an absent candidate is not evidence of an absent race",
            "unsupported": ["aliasing", "path feasibility", "happens-before", "join ordering",
                "macros", "headers not named in files", "calls through function pointers",
                "function-static storage", "context-sensitive locksets",
                "lock arguments that are not a plain global or parameter",
                "mutex attributes (recursive, error-checking)", "semaphore counts",
                "backward goto", "memory orders weaker than sequential consistency",
                "Eva states", "Mthread states"],
        }),
    );
    put(
        "refinement",
        json!({
            "tool": null,
            "note": "No tool on this surface confirms a race. Level 0 evidence has to be taken to Eva or Mthread outside it before a defect is reported.",
        }),
    );
    serde_json::Value::Object(out)
}

/// A scan that ran out of time reports that, rather than a payload whose
/// counts would all be floors with nothing saying so.
fn scan_timed_out() -> McpError {
    McpError::internal_error(
        format!(
            "concurrency scan exceeded {}s and was abandoned. This pass is \
             superlinear in the shape of the source, not only in its size: a \
             generated or preprocessed file that puts a whole function on one \
             line is the usual cause. Narrow the files argument, or lower \
             max_events.",
            CONCURRENCY_SCAN_BUDGET.as_secs()
        ),
        None,
    )
}

#[tool_router(router = concurrency_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    #[tool(
        description = "Build a source-grounded Concurrent Event IR and conservative race and lock-order candidates. Level-0 syntactic screening only: candidates are not proofs, and an absent candidate is not a proof either."
    )]
    async fn analyze_concurrency(
        &self,
        Parameters(params): Parameters<AnalyzeConcurrencyParams>,
    ) -> Result<CallToolResult, McpError> {
        let files = match params.files {
            Some(files) if !files.is_empty() => files,
            _ => self
                .main_frama_c_state()
                .lock()
                .await
                .as_ref()
                .map(|state| state.files.clone())
                .unwrap_or_default(),
        };
        if files.is_empty() {
            return Err(no_project_loaded_error());
        }
        let max_events = params.max_events.unwrap_or(10_000).min(100_000);
        let max_candidates = params.max_candidates.unwrap_or(2_000).min(20_000);
        let include_unshared = params.include_unshared.unwrap_or(false);
        let deadline = Deadline::new(CONCURRENCY_SCAN_BUDGET);
        let scan = tokio::task::spawn_blocking(move || {
            scan_to_deadline(&files, max_events, max_candidates, include_unshared, deadline)
        });
        // Bounded, because this pass reads caller-supplied text and its cost is
        // a function of that text's shape rather than of any limit the caller
        // set. Two superlinear paths have been found and fixed here under
        // review; a third is a reasonable thing to expect.
        //
        // What it bounds is the caller's wait and nothing else. Dropping the
        // handle does not cancel a blocking task, so a scan that overran this
        // budget would otherwise go on holding its worker until the process
        // dies, and enough of them would starve the pool the reload path's
        // source_identity also spawns into. The shared absolute deadline and
        // cooperative checks inside the scan keep this timeout as a backstop.
        let payload = match tokio::time::timeout(CONCURRENCY_SCAN_BUDGET, scan).await {
            Ok(joined) => joined.map_err(|error| {
                McpError::internal_error(format!("concurrency scan failed: {error}"), None)
            })?,
            Err(_) => return Err(scan_timed_out()),
        };
        Ok(json_result(payload))
    }
}
