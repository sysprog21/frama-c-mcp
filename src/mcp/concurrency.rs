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

const MUTEX_CALLS: [(&str, &str); 3] = [
    ("pthread_mutex_lock", "LOCK"),
    ("pthread_mutex_trylock", "TRYLOCK"),
    ("pthread_mutex_unlock", "UNLOCK"),
];

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
        // Only a pthread call's arguments are ever read, and splitting every
        // call's meant re-splitting the text of an inner call once per
        // enclosing one: quadratic in the line length, 47 ms at 1,600 nested
        // calls and growing fourfold per doubling. It is the last of the three
        // superlinear paths the scan budget was written to survive, and the
        // only one that could still exhaust it.
        let args = match name.starts_with("pthread_") {
            true => split_top_level(&line[open + 1..close]),
            false => Vec::new(),
        };
        found.push(Call {
            name: (*name).to_string(),
            args,
            start: *start,
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
    if is_declaration(line) {
        scan.globals.extend(declarators(line));
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
    scan.functions.push(Function { name });
    Some(scan.functions.len() - 1)
}

// ──────────────────────────────────────────────────────────────────────────
// Program-wide facts
// ──────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Spawn {
    sites: usize,
    in_loop: bool,
}

impl Spawn {
    /// One definition, because the set this drives decides which pairs are
    /// candidates and the payload reports the same fact to the caller. Spelled
    /// out in both places, they can disagree, and the report then contradicts
    /// the analysis behind it.
    fn may_repeat(&self) -> bool {
        self.sites > 1 || self.in_loop
    }
}

#[derive(Default)]
struct Program {
    entries: BTreeMap<String, Spawn>,
    edges: BTreeMap<String, BTreeSet<String>>,
    defined: BTreeSet<String>,
    globals: BTreeSet<String>,
    /// Every pthread_create this pass saw, whether or not it could name the
    /// entry. Kept apart from "entries", which holds only the ones it resolved.
    spawn_calls: usize,
}

impl Program {
    /// Spawn sites whose entry function this pass could not name: the argument
    /// list wrapped to the next line, or the third argument is an expression
    /// rather than a function name.
    fn unresolved_spawns(&self) -> usize {
        let resolved: usize = self.entries.values().map(|spawn| spawn.sites).sum();
        self.spawn_calls.saturating_sub(resolved)
    }
}

/// Thread entries, the call graph and the global set, gathered before any event
/// is emitted because a thread entry can be defined in another file than the
/// one that spawns it.
fn survey(files: &[FileScan]) -> Program {
    let mut program = Program::default();
    for file in files {
        program.globals.extend(file.globals.iter().cloned());
        program
            .defined
            .extend(file.functions.iter().map(|f| f.name.clone()));
    }
    for file in files {
        for (index, line) in file.lines.iter().enumerate() {
            survey_line(&mut program, file, line, index);
        }
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
    for call in calls_among(line, &tokens) {
        if call.name == "pthread_create" {
            record_spawn(program, &call, file.in_loop[index]);
        }
        let Some(from) = caller.clone() else { continue };
        if program.defined.contains(&call.name) {
            program.edges.entry(from).or_default().insert(call.name);
        }
    }
}

fn record_spawn(program: &mut Program, call: &Call, in_loop: bool) {
    let Some(entry) = call.args.get(2).and_then(|arg| entry_function(arg)) else {
        return;
    };
    let spawn = program.entries.entry(entry).or_default();
    spawn.sites += 1;
    // One textual site inside a loop is many threads, which is how most C
    // spawns a pool. Counting sites alone reported such a pool as a single
    // thread that could not race with itself.
    spawn.in_loop = spawn.in_loop || in_loop;
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
        let mut queue = vec![root.clone()];
        let mut seen = BTreeSet::new();
        while let Some(function) = queue.pop() {
            if !seen.insert(function.clone()) {
                continue;
            }
            sets.entry(function.clone()).or_default().insert(root.clone());
            queue.extend(program.edges.get(&function).into_iter().flatten().cloned());
        }
    }
    sets
}

fn repeating(program: &Program) -> BTreeSet<String> {
    program
        .entries
        .iter()
        .filter(|(_, spawn)| spawn.may_repeat())
        .map(|(entry, _)| entry.clone())
        .collect()
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
    Lock(&'static str, String),
    Create(String),
    Join,
    Access(&'static str, String),
    /// A block opens here, and its lockset is the enclosing one until something
    /// on this line or a later one changes it.
    Open,
    /// A block closes here, restoring the lockset of the block around it.
    Close,
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

/// The byte ranges a pthread call covers, so an identifier inside one is not
/// also read as a memory access. Excluding the whole line instead dropped
/// "shared = 1" from a one-line thread body that also took a lock.
fn pthread_ranges(found: &[Call]) -> Vec<(usize, usize)> {
    found
        .iter()
        .filter(|call| call.name.starts_with("pthread_"))
        .map(|call| (call.start, call.end))
        .collect()
}

fn actions_on_line(line: &str, zones: &dyn Fn(&str) -> Option<String>) -> Vec<(usize, Action)> {
    let tokens = identifiers(line);
    let found = calls_among(line, &tokens);
    let covered = pthread_ranges(&found);
    let mut actions = Vec::new();
    for call in &found {
        actions.extend(call_action(call));
    }
    for (start, name) in tokens {
        let inside = covered
            .iter()
            .any(|(from, to)| start >= *from && start <= *to);
        let Some(zone) = zones(name).filter(|_| !inside) else {
            continue;
        };
        let kind = if is_written(line, start, start + name.len()) {
            "WRITE"
        } else {
            "READ"
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

fn call_action(call: &Call) -> Option<(usize, Action)> {
    if call.name == "pthread_join" {
        return Some((call.start, Action::Join));
    }
    if call.name == "pthread_create" {
        let entry = call.args.get(2).and_then(|arg| entry_function(arg))?;
        return Some((call.start, Action::Create(entry)));
    }
    let (_, kind) = MUTEX_CALLS.iter().find(|(name, _)| *name == call.name)?;
    let lock = call.args.first().map(|arg| lock_expression(arg));
    Some((
        call.start,
        Action::Lock(kind, lock.unwrap_or_else(|| "<unknown>".into())),
    ))
}

// ──────────────────────────────────────────────────────────────────────────
// Emission
// ──────────────────────────────────────────────────────────────────────────

struct Context<'a> {
    program: &'a Program,
    sets: &'a BTreeMap<String, BTreeSet<String>>,
    repeat: &'a BTreeSet<String>,
    include_unshared: bool,
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

/// A lockset is restored when its block closes, so a lock taken inside an "if"
/// is not held by the code after it. The lock is evidence either way, but a
/// lockset that leaks out of a conditional is evidence for something that never
/// happened.
///
/// This used to open every block on the line before the line was emitted and
/// close every one after, which is the right order only when a line does not do
/// both. On "} else {" it applied the open first, so the else branch inherited
/// the lockset of the branch above it, and the test that was supposed to catch
/// that released its lock inside the branch and so passed on the unlock rather
/// than on the block. Braces are ordinary positioned actions now, applied in
/// source order with everything else on the line.
fn enter_block(stack: &mut Vec<Vec<String>>) {
    let enclosing = stack.last().cloned().unwrap_or_default();
    stack.push(enclosing);
}

/// Leaving a block keeps only what is held both before it and at its end.
///
/// Restoring the enclosing set was symmetric, and locking is not. A lock taken
/// inside a block must not escape it, which restoring does correctly; a lock
/// released inside one must escape, and restoring resurrected it. So
///
///     pthread_mutex_lock(&m);
///     if (1) { pthread_mutex_unlock(&m); }
///     shared = 1;
///
/// reported the write as holding m, and unlock-in-both-branches is the shape
/// real code takes. That is this pass manufacturing its own primary evidence,
/// which is worse than missing a lock: lock_note then tells the caller both
/// accesses hold a mutex that was released.
///
/// Intersection is the must-lockset rule and it is right in both directions,
/// because a block may not have run. It also drops a lock taken by a block that
/// certainly did run, which is the safe way to be wrong here: this pass never
/// needs to claim a lock is held.
fn leave_block(stack: &mut Vec<Vec<String>>) {
    // Never the last frame: a file with unbalanced braces, which is any file
    // this pass was handed mid-edit, would otherwise leave nothing to hold the
    // next function's locks.
    if stack.len() <= 1 {
        return;
    }
    let inner = stack.pop().unwrap_or_default();
    if let Some(outer) = stack.last_mut() {
        outer.retain(|lock| inner.contains(lock));
    }
}

fn apply_lock(
    kind: &'static str,
    lock: String,
    held: &mut Vec<String>,
    site: (&str, usize),
    lock_order: &mut Vec<serde_json::Value>,
) {
    if kind == "UNLOCK" {
        if let Some(at) = held.iter().rposition(|other| *other == lock) {
            held.remove(at);
        }
        return;
    }
    // A trylock can return EBUSY, so it is recorded as an event and never as a
    // lock held. Holding it claims protection on the path where the call
    // failed, which is this pass manufacturing its own primary evidence, the
    // thing leave_block goes out of its way not to do. The order edge goes
    // with it: a lock that may not have been taken cannot deadlock against the
    // one acquired under it.
    if kind == "TRYLOCK" {
        return;
    }
    for outer in held.iter() {
        lock_order.push(
            json!({"from": outer, "to": lock, "source": {"file": site.0, "line": site.1}}),
        );
    }
    held.push(lock);
}

struct Emission<'a> {
    sink: &'a mut Sink,
    lock_order: &'a mut Vec<serde_json::Value>,
}

fn emit_line(
    file: &FileScan,
    ctx: &Context,
    index: usize,
    locals: &BTreeSet<String>,
    stack: &mut Vec<Vec<String>>,
    out: &mut Emission,
) {
    let line = &file.lines[index];
    // A line at file scope emits no event, but its braces still move the block
    // stack: a struct definition or an initializer would otherwise unbalance it
    // for every function after it.
    let function = file.owner[index].map(|at| file.functions[at].name.clone());
    let named = function.clone().unwrap_or_default();
    let threads = function.as_ref().map(|name| ctx.threads_of(name)).unwrap_or_default();
    let may_repeat = ctx.repeats(&threads);
    let zones = |name: &str| -> Option<String> {
        if ctx.program.globals.contains(name) {
            return Some(name.to_string());
        }
        (ctx.include_unshared && locals.contains(name)).then(|| format!("{named}::{name}"))
    };
    let actions = actions_on_line(line, &zones);
    for (_, action) in actions {
        let (kind, zone) = match action {
            Action::Open => {
                enter_block(stack);
                continue;
            }
            Action::Close => {
                leave_block(stack);
                continue;
            }
            Action::Lock(kind, lock) => {
                let held = stack.last_mut().expect("the stack always keeps a frame");
                apply_lock(kind, lock.clone(), held, (&file.path, index + 1), out.lock_order);
                (kind, Some(lock))
            }
            Action::Create(entry) => ("THREAD_CREATE", Some(entry)),
            Action::Join => ("THREAD_JOIN", None),
            Action::Access(kind, zone) => (kind, Some(zone)),
        };
        let Some(function) = function.clone() else { continue };
        out.sink.push(Event {
            id: String::new(),
            threads: threads.clone(),
            may_repeat,
            kind,
            file: file.path.clone(),
            line: index + 1,
            function,
            zone,
            lockset: stack.last().cloned().unwrap_or_default(),
        });
    }
}

fn emit_file(file: &FileScan, ctx: &Context, out: &mut Emission, deadline: Deadline) -> bool {
    let mut stack: Vec<Vec<String>> = vec![Vec::new()];
    let mut locals = BTreeSet::new();
    let mut pending_branch = false;
    for index in 0..file.lines.len() {
        if deadline.passed() {
            return false;
        }
        let line = file.lines[index].trim().to_string();
        if ctx.include_unshared && file.owner[index].is_some() {
            let named = declarators(&line);
            locals.extend(named.into_iter().filter(|n| !ctx.program.globals.contains(n)));
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
            enter_block(&mut stack);
        }
        emit_line(file, ctx, index, &locals, &mut stack, out);
        if wrapped {
            leave_block(&mut stack);
        }
        pending_branch = matches!(branch, Branch::NextLine);
        if stack.len() == 1 {
            locals.clear();
        }
    }
    true
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
    // The pairwise loop this replaces returned false only when both events
    // named one and the same thread that is spawned once, so it paid a
    // quadratic string comparison for a question with a closed form, on the
    // false branch, which is the one the pair budget is charged for.
    match (left.threads.as_slice(), right.threads.as_slice()) {
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

fn common_locks(left: &Event, right: &Event) -> Vec<String> {
    left.lockset
        .iter()
        .filter(|lock| right.lockset.contains(lock))
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
        "reason": "conflicting accesses that this pass cannot order",
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
        "lock_evidence": lock_note(&access.lockset),
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
            let both_read = left.kind == "READ" && right.kind == "READ";
            if !both_read && may_run_concurrently(left, right, repeat) {
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
    for event in events.iter().filter(|e| e.kind == "READ" || e.kind == "WRITE") {
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
    json!({
        "id": event.id,
        "threads": event.threads,
        "thread_may_repeat": event.may_repeat,
        "kind": event.kind,
        "source_location": {"file": event.file, "line": event.line},
        "function": event.function,
        "memory_zone": event.zone,
        "lockset": event.lockset,
        "provenance": "syntax",
    })
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
    let context = Context {
        program: &program,
        sets: &sets,
        repeat: &repeat,
        include_unshared,
    };
    let mut sink = Sink {
        events: Vec::new(),
        total: 0,
        limit: max_events,
    };
    let mut lock_order = Vec::new();
    let mut within_deadline = read_within_deadline;
    for file in &scans {
        if !within_deadline {
            break;
        }
        within_deadline = emit_file(
            file,
            &context,
            &mut Emission {
                sink: &mut sink,
                lock_order: &mut lock_order,
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
    payload(PayloadParts {
        files,
        events: &sink,
        threads_detected,
        entries: &program,
        candidates,
        lock_order,
        unreadable,
        within_deadline,
    })
}

struct PayloadParts<'a> {
    files: &'a [String],
    events: &'a Sink,
    threads_detected: bool,
    entries: &'a Program,
    candidates: Candidates,
    lock_order: Vec<serde_json::Value>,
    unreadable: Vec<serde_json::Value>,
    /// False when the scan gave up its own budget partway, which makes every
    /// count below a floor.
    within_deadline: bool,
}

fn payload(parts: PayloadParts) -> serde_json::Value {
    let kept = parts.candidates.emitted.len();
    let entries: Vec<serde_json::Value> = parts
        .entries
        .entries
        .iter()
        .map(|(name, spawn)| {
            json!({"entry": name, "spawn_sites": spawn.sites, "spawned_in_loop": spawn.in_loop,
                "may_repeat": spawn.may_repeat()})
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
    put("lock_order", serde_json::Value::Array(parts.lock_order));
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
                "function-static storage",
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
