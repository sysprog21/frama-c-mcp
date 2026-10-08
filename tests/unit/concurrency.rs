//! What the Level-0 concurrency screen reports, and what it refuses to report.
//!
//! Lived in src/mcp/concurrency.rs as a #[cfg(test)] module until a review
//! found it there: src carries none, because a test under it runs only under
//! "cargo test --lib", which no documented gate and no CI lane runs.
//!
//! Every test below names the wrong answer it pins. The first version of this
//! pass produced all of them, and each one was a report a caller would have
//! read as "no race here".

use frama_c_mcp::mcp::server::concurrency::{scan_sources, scan_within};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Screen one source text with the defaults the tool uses.
fn scan(source: &str) -> Value {
    scan_in(source, 10_000, 2_000, false)
}

fn scan_in(source: &str, max_events: usize, max_candidates: usize, unshared: bool) -> Value {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("subject.c");
    std::fs::write(&file, source).expect("write fixture");
    scan_sources(
        &[file.to_string_lossy().into_owned()],
        max_events,
        max_candidates,
        unshared,
    )
}

fn candidates(payload: &Value) -> &Vec<Value> {
    payload["candidates"].as_array().expect("candidates")
}

fn events(payload: &Value) -> &Vec<Value> {
    payload["events"].as_array().expect("events")
}

fn zones(payload: &Value) -> BTreeSet<String> {
    events(payload)
        .iter()
        .filter_map(|event| event["memory_zone"].as_str())
        .map(str::to_string)
        .collect()
}

/// Two threads, one global, written the way C is actually written.
const KANDR: &str = r#"
int shared = 0;

void *writer(void *arg)
{
    shared = 1;
    return 0;
}

void *reader(void *arg)
{
    int local = shared;
    return 0;
}

int main(void)
{
    pthread_t a, b;
    pthread_create(&a, 0, writer, 0);
    pthread_create(&b, 0, reader, 0);
    return 0;
}
"#;

/// The scanner used to require a definition's brace on the same line as its
/// name, so a file in this style put every event in "<global>" on thread
/// "main", and the same-thread filter then discarded every pair. A textbook
/// write against read reported clean.
#[test]
fn a_definition_whose_brace_opens_the_next_line_is_still_a_function() {
    let payload = scan(KANDR);
    let functions: BTreeSet<&str> = events(&payload)
        .iter()
        .filter_map(|event| event["function"].as_str())
        .collect();
    assert!(functions.contains("writer"), "{functions:?}");
    assert!(functions.contains("reader"), "{functions:?}");
    assert_eq!(candidates(&payload).len(), 1, "{:?}", candidates(&payload));
    assert_eq!(candidates(&payload)[0]["memory_zone"], "shared");
}

/// "counter += 1" was reported as a READ, because only "=", "++" and "--" were
/// recognized, so the canonical counter race had no write in it and produced no
/// candidate at all.
#[test]
fn a_compound_assignment_is_a_write() {
    let payload = scan(
        r#"
int counter = 0;
void *worker(void *arg) { counter += 1; return 0; }
int main(void) { pthread_t a, b; pthread_create(&a, 0, worker, 0); pthread_create(&b, 0, worker, 0); return 0; }
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "counter" && event["function"] == "worker")
        .expect("an access to counter inside worker");
    assert_eq!(write["kind"], "WRITE", "{write:?}");
    assert!(!candidates(&payload).is_empty());
}

/// The mirror image: "assigned" looked at the first occurrence of the name on
/// the line and read the "=" of "==" as an assignment, so two threads that only
/// compared a global were reported racing on a write neither performs.
#[test]
fn a_comparison_is_not_a_write() {
    let payload = scan(
        r#"
int flag = 0;
void *watcher(void *arg) { if (flag == 0) { return 0; } return 0; }
int main(void) { pthread_t a, b; pthread_create(&a, 0, watcher, 0); pthread_create(&b, 0, watcher, 0); return 0; }
"#,
    );
    let kinds: BTreeSet<&str> = events(&payload)
        .iter()
        .filter(|event| event["memory_zone"] == "flag" && event["function"] == "watcher")
        .filter_map(|event| event["kind"].as_str())
        .collect();
    assert_eq!(kinds, BTreeSet::from(["READ"]), "{kinds:?}");
    assert!(candidates(&payload).is_empty(), "{:?}", candidates(&payload));
}

/// One event per line per zone meant "shared = shared + 1" reported a write and
/// no read. Accesses are per occurrence now.
#[test]
fn a_read_and_a_write_of_one_zone_on_one_line_are_two_events() {
    let payload = scan("int shared;\nvoid f(void) { shared = shared + 1; }\n");
    let kinds: Vec<&str> = events(&payload)
        .iter()
        .filter(|event| event["memory_zone"] == "shared")
        .filter_map(|event| event["kind"].as_str())
        .collect();
    assert_eq!(kinds, vec!["WRITE", "READ"], "{kinds:?}");
}

/// Only line comments were stripped, so a block comment naming a lock put that
/// lock in the lockset. Two comments turned a real write against write race
/// into a candidate whose status read "protected".
#[test]
fn a_lock_named_in_a_block_comment_is_not_held() {
    let payload = scan(
        r#"
int shared;
void *t1(void *arg)
{
    /* callers must hold pthread_mutex_lock(&big_lock) */
    shared = 1;
    return 0;
}
void *t2(void *arg)
{
    /* callers must hold pthread_mutex_lock(&big_lock) */
    shared = 2;
    return 0;
}
int main(void)
{
    pthread_t a, b;
    pthread_create(&a, 0, t1, 0);
    pthread_create(&b, 0, t2, 0);
    return 0;
}
"#,
    );
    for event in events(&payload) {
        assert_eq!(event["lockset"].as_array().expect("lockset").len(), 0, "{event:?}");
    }
    let found = candidates(&payload);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["status"], "potential");
    assert_eq!(found[0]["lock_evidence"], Value::Null);
}

/// The lockset was lexical and never popped at a block boundary, so a lock
/// taken inside an "if" was held by everything after it.
#[test]
fn a_lock_taken_inside_a_branch_does_not_survive_the_branch() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    if (c) {
        pthread_mutex_lock(&m);
    }
    shared = 1;
}
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// Whatever the locksets say, a candidate is never downgraded to something a
/// caller can read as "not a race".
#[test]
fn a_shared_lock_is_evidence_and_never_a_verdict() {
    let payload = scan(
        r#"
int shared;
void *t1(void *arg)
{
    pthread_mutex_lock(&m);
    shared = 1;
    pthread_mutex_unlock(&m);
    return 0;
}
void *t2(void *arg)
{
    pthread_mutex_lock(&m);
    shared = 2;
    pthread_mutex_unlock(&m);
    return 0;
}
int main(void)
{
    pthread_t a, b;
    pthread_create(&a, 0, t1, 0);
    pthread_create(&b, 0, t2, 0);
    return 0;
}
"#,
    );
    let found = candidates(&payload);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["status"], "potential");
    assert_eq!(found[0]["lock_evidence"]["common_lexical_locks"][0], "m");
    // What carries weight here is the line above and the one before it: a pair
    // holding one lock in both threads is still a candidate, and the lock rides
    // along as evidence. An assertion that every status reads "potential" was
    // dropped from this test: "potential" is a literal in both constructors, so
    // no implementation could fail it.
}

/// Pairing was quadratic over every access with no cap, so an ordinary file
/// could produce millions of candidates and hundreds of megabytes of JSON.
#[test]
fn the_candidate_list_is_capped_and_reports_what_it_dropped() {
    let mut source = String::from("int shared;\nvoid *t1(void *arg) {\n");
    for _ in 0..20 {
        source.push_str("    shared = 1;\n");
    }
    source.push_str("    return 0;\n}\nvoid *t2(void *arg) {\n");
    for _ in 0..20 {
        source.push_str("    shared = 2;\n");
    }
    source.push_str("    return 0;\n}\nint main(void) {\n    pthread_t a, b;\n");
    source.push_str("    pthread_create(&a, 0, t1, 0);\n    pthread_create(&b, 0, t2, 0);\n    return 0;\n}\n");
    let payload = scan_in(&source, 10_000, 5, false);
    assert_eq!(candidates(&payload).len(), 5);
    assert!(payload["candidate_count"].as_u64().expect("count") > 5);
    assert!(payload["candidates_omitted"].as_u64().expect("omitted") > 0);
}

/// The cap bounds the response; the budget bounds the work behind it. Counting
/// candidates honestly means enumerating every pair in a zone, so without a
/// budget the cap left the quadratic scan in place: bounded output, unbounded
/// CPU. A stopped scan reports a floor and says that it is one.
#[test]
fn the_pair_scan_is_bounded_and_a_partial_count_says_so() {
    let mut source = String::from("int shared;\nvoid *t1(void *arg) {\n");
    for _ in 0..30 {
        source.push_str("    shared = 1;\n");
    }
    source.push_str("    return 0;\n}\nvoid *t2(void *arg) {\n");
    for _ in 0..30 {
        source.push_str("    shared = 2;\n");
    }
    source.push_str("    return 0;\n}\nint main(void) {\n    pthread_t a, b;\n");
    source.push_str("    pthread_create(&a, 0, t1, 0);\n    pthread_create(&b, 0, t2, 0);\n    return 0;\n}\n");

    // 60 accesses to one zone is 1770 pairs, against a budget of 1024 at a cap
    // of one candidate.
    let stopped = scan_in(&source, 10_000, 1, false);
    assert_eq!(stopped["candidate_enumeration_complete"], false, "{stopped:?}");
    assert!(stopped["candidate_count"].as_u64().expect("count") < 1770);

    // The same file with room to finish reports a total, and the total is
    // larger than the floor the stopped scan reported.
    let whole = scan_in(&source, 10_000, 4_000, false);
    assert_eq!(whole["candidate_enumeration_complete"], true, "{whole:?}");
    assert!(
        whole["candidate_count"].as_u64().expect("count")
            > stopped["candidate_count"].as_u64().expect("count")
    );
}

/// A scan that finishes says so, which is what makes the flag above readable.
#[test]
fn an_unstopped_scan_reports_a_complete_enumeration() {
    let payload = scan(KANDR);
    assert_eq!(payload["candidate_enumeration_complete"], true, "{payload:?}");
}

/// "int flag, count;" recorded only "count", and "int arr[10];" recorded the
/// pseudo-identifier "arr[10", so accesses to the others were never events.
#[test]
fn every_declarator_of_a_global_is_recorded() {
    let payload = scan("int flag, count;\nint arr[10];\nvoid f(void) { flag = 1; count = 2; arr[0] = 3; }\n");
    assert_eq!(
        zones(&payload),
        BTreeSet::from(["arr".to_string(), "count".to_string(), "flag".to_string()])
    );
}

/// A pool spawned from one textual pthread_create inside a loop is many
/// threads. Counting call sites alone reported it as one thread that could not
/// race with itself.
#[test]
fn a_thread_spawned_in_a_loop_may_repeat() {
    let payload = scan(
        r#"
int shared;
void *worker(void *arg) { shared = 1; return 0; }
int main(void)
{
    pthread_t t[4];
    int i;
    for (i = 0; i < 4; i++) {
        pthread_create(&t[i], 0, worker, 0);
    }
    return 0;
}
"#,
    );
    let entry = payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["entry"] == "worker")
        .expect("worker is a thread entry");
    assert_eq!(entry["spawned_in_loop"], true, "{entry:?}");
    assert_eq!(entry["may_repeat"], true, "{entry:?}");
    assert!(!candidates(&payload).is_empty());
}

/// A loop whose body is a single statement has no brace, and that is how a
/// pool is usually spawned. Hanging the loop on a block alone reported the
/// entry as a thread that runs once.
#[test]
fn a_thread_spawned_in_a_loop_without_braces_may_repeat() {
    let payload = scan(
        r#"
int shared;
void *worker(void *arg) { shared = 1; return 0; }
int main(void)
{
    pthread_t t[4];
    int i;
    for (i = 0; i < 4; i++)
        pthread_create(&t[i], 0, worker, 0);
    return 0;
}
"#,
    );
    let entry = payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["entry"] == "worker")
        .expect("worker is a thread entry");
    assert_eq!(entry["spawn_sites"], 1, "{entry:?}");
    assert_eq!(entry["may_repeat"], true, "{entry:?}");
}

/// Excluding every line holding "pthread_" dropped the access from a one-line
/// thread body, which is how most small thread functions are written.
#[test]
fn an_access_sharing_a_line_with_a_pthread_call_is_still_an_event() {
    let payload = scan(
        "int shared;\nvoid *t1(void *a) { pthread_mutex_lock(&m); shared = 1; pthread_mutex_unlock(&m); return 0; }\n",
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["kind"], "WRITE");
    assert_eq!(write["lockset"][0], "m", "{write:?}");
}

/// Both locks on one line were read as one, so the order edge that is the whole
/// point of the lock_order list was never recorded and the second lock was
/// never released.
#[test]
fn two_lock_calls_on_one_line_record_their_order() {
    let payload = scan(
        "void f(void) { pthread_mutex_lock(&a); pthread_mutex_lock(&b); pthread_mutex_unlock(&b); pthread_mutex_unlock(&a); }\n",
    );
    let order = payload["lock_order"].as_array().expect("lock order");
    assert_eq!(order.len(), 1, "{order:?}");
    assert_eq!(order[0]["from"], "a");
    assert_eq!(order[0]["to"], "b");
}

/// Nested across lines, the shape the first version did handle, kept as a
/// regression for the rewrite.
#[test]
fn nested_locks_across_lines_record_their_order() {
    let payload = scan(
        "void f(void)\n{\n    pthread_mutex_lock(&a);\n    pthread_mutex_lock(&b);\n    pthread_mutex_unlock(&b);\n    pthread_mutex_unlock(&a);\n}\n",
    );
    let order = payload["lock_order"].as_array().expect("lock order");
    assert_eq!(order.len(), 1, "{order:?}");
    assert_eq!(order[0]["from"], "a");
    assert_eq!(order[0]["to"], "b");
}

/// Arguments were split at the first ")", so a call in an earlier argument hid
/// the entry point and the thread vanished.
#[test]
fn a_thread_entry_behind_a_call_argument_is_found() {
    let payload = scan(
        "int shared;\nvoid *worker(void *a) { shared = 1; return 0; }\nint main(void) { pthread_t t; pthread_create(&t, get_attr(), worker, 0); return 0; }\n",
    );
    let entries: Vec<&str> = payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|entry| entry["entry"].as_str())
        .collect();
    assert_eq!(entries, vec!["worker"], "{entries:?}");
}

/// A cast in front of the mutex named the type instead of the lock.
#[test]
fn a_cast_in_front_of_a_mutex_does_not_become_its_name() {
    let payload = scan("void f(void) { pthread_mutex_lock((pthread_mutex_t *)&m); }\n");
    let lock = events(&payload)
        .iter()
        .find(|event| event["kind"] == "LOCK")
        .expect("a lock event");
    assert_eq!(lock["memory_zone"], "m", "{lock:?}");
}

/// "line.contains(global)" matched inside longer words, so a short global name
/// turned every line that spelled its letters into an access.
#[test]
fn a_global_is_matched_as_a_token_and_not_a_substring() {
    let payload = scan("int n;\nvoid f(void) { int index = 0; int number = 1; return; }\n");
    assert!(zones(&payload).is_empty(), "{:?}", zones(&payload));
}

/// A string literal is not source the scanner reads.
#[test]
fn a_global_named_in_a_string_literal_is_not_an_access() {
    let payload = scan("int shared;\nvoid f(void) { puts(\"shared\"); }\n");
    assert!(zones(&payload).is_empty(), "{:?}", zones(&payload));
}

/// An ACSL clause is a block comment, and its last token was being recorded as
/// a global. Measured on the shape this repository's own fixtures carry, which
/// is the first input this tool sees.
#[test]
fn an_acsl_annotation_is_not_a_declaration() {
    let payload = scan(
        "/*@ requires x > INT_MIN;\n    assigns \\nothing;\n    ensures \\result >= 0; */\nint f(int x) { return x < 0 ? -x : x; }\n",
    );
    assert!(zones(&payload).is_empty(), "{:?}", zones(&payload));
    assert_eq!(payload["candidate_count"], 0);
}

/// The scan was intraprocedural, so a global touched in a helper was attributed
/// to a function no pthread_create names, and the pair was discarded.
#[test]
fn a_race_reached_through_a_shared_helper_is_a_candidate() {
    let payload = scan(
        r#"
int shared;
void bump(void) { shared = shared + 1; }
void *t1(void *arg) { bump(); return 0; }
void *t2(void *arg) { bump(); return 0; }
int main(void)
{
    pthread_t a, b;
    pthread_create(&a, 0, t1, 0);
    pthread_create(&b, 0, t2, 0);
    return 0;
}
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["function"] == "bump" && event["kind"] == "WRITE")
        .expect("the write inside bump");
    let threads: Vec<&str> = write["threads"]
        .as_array()
        .expect("threads")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(threads, vec!["t1", "t2"], "{write:?}");
    assert!(!candidates(&payload).is_empty());
}

/// A file that stats cleanly and does not decode contributed nothing and was
/// reported as scanned, which reads as a file with no races in it.
#[test]
fn a_file_that_does_not_decode_is_reported_unreadable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("latin1.c");
    let mut bytes = b"int shared; /* copyright ".to_vec();
    bytes.push(0xa9);
    bytes.extend_from_slice(b" */\n");
    std::fs::write(&file, bytes).expect("write fixture");
    let payload = scan_sources(
        &[file.to_string_lossy().into_owned()],
        10_000,
        2_000,
        false,
    );
    let unreadable = payload["unreadable_files"].as_array().expect("unreadable");
    assert_eq!(unreadable.len(), 1, "{unreadable:?}");
}

/// A missing file is reported the same way.
#[test]
fn a_missing_file_is_reported_unreadable() {
    let payload = scan_sources(&["/nonexistent/subject.c".to_string()], 10, 10, false);
    assert_eq!(payload["unreadable_files"].as_array().expect("unreadable").len(), 1);
}

/// A file-scope initializer ran before any thread existed, and reporting it as
/// a write paired it against every read in the program.
#[test]
fn a_file_scope_initializer_is_not_a_write_event() {
    let payload = scan("int counter = 0;\nvoid f(void) { counter = 1; }\n");
    let writes: Vec<u64> = events(&payload)
        .iter()
        .filter(|event| event["kind"] == "WRITE")
        .filter_map(|event| event["source_location"]["line"].as_u64())
        .collect();
    assert_eq!(writes, vec![2], "{writes:?}");
}

/// Nothing spawns a thread, so nothing here is concurrent. Pairing regardless
/// would make every write in single threaded code a candidate against itself.
#[test]
fn a_program_with_no_thread_entry_reports_no_candidates() {
    let payload = scan("int shared;\nvoid f(void) { shared = 1; }\nvoid g(void) { shared = 2; }\n");
    assert_eq!(payload["threads_detected"], false);
    assert_eq!(payload["candidate_count"], 0);
    assert!(!events(&payload).is_empty(), "events are still reported");
}

/// Ids are allocated from one counter across files, including under a limit
/// that stops them being kept.
#[test]
fn event_ids_are_unique_across_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("first.c");
    let second = dir.path().join("second.c");
    std::fs::write(&first, "int one;\nvoid f(void) { one = 1; }\n").expect("write");
    std::fs::write(&second, "int two;\nvoid g(void) { two = 1; }\n").expect("write");
    let payload = scan_sources(
        &[
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ],
        10_000,
        2_000,
        false,
    );
    let ids: Vec<&str> = events(&payload)
        .iter()
        .filter_map(|event| event["id"].as_str())
        .collect();
    assert_eq!(ids.len(), ids.iter().collect::<BTreeSet<_>>().len(), "{ids:?}");
}

/// The count is of what was found, not of what was kept.
#[test]
fn events_omitted_counts_what_the_limit_dropped() {
    let payload = scan_in("int shared;\nvoid f(void) { shared = 1; shared = 2; }\n", 1, 10, false);
    assert_eq!(events(&payload).len(), 1);
    assert!(payload["event_count"].as_u64().expect("count") > 1);
    assert!(payload["events_omitted"].as_u64().expect("omitted") > 0);
}

/// The opt-in adds function-local zones, which are named for their function so
/// two functions' locals are different zones.
#[test]
fn include_unshared_adds_local_accesses() {
    let source = "void f(void) { int local = 0; local = 1; }\n";
    let without = scan_in(source, 10_000, 2_000, false);
    let with = scan_in(source, 10_000, 2_000, true);
    assert!(zones(&without).is_empty());
    assert_eq!(zones(&with), BTreeSet::from(["f::local".to_string()]));
}

/// "do" on its own line is how a do-while is written, and the loop detector
/// indexed the byte after the keyword without checking there was one. The whole
/// scan died on an index out of bounds, so the tool reported nothing at all for
/// any file holding one.
#[test]
fn a_do_on_its_own_line_does_not_stop_the_scan() {
    let payload = scan("int shared;\nvoid f(void)\n{\n    do\n    {\n        shared = 1;\n    } while (shared);\n}\n");
    assert_eq!(zones(&payload), BTreeSet::from(["shared".to_string()]));
}

/// A brace initializer was read as a scope, so the declarator in front of it
/// was thrown away with it: "int shared[4] = {0};" declared no zone and every
/// access to that array was invisible.
#[test]
fn a_brace_initialized_global_is_still_a_declaration() {
    let payload = scan("int arr[4] = {0};\nint plain = 0;\nvoid f(void) { arr[0] = 1; plain = 2; }\n");
    assert_eq!(
        zones(&payload),
        BTreeSet::from(["arr".to_string(), "plain".to_string()])
    );
}

/// The members of a one-line aggregate definition were recorded as globals, so
/// every "p->x" in the file became an access to one zone named "x" whoever
/// owned the structure, and two threads touching different instances were
/// reported racing. The same definition spread over several lines never was.
#[test]
fn the_members_of_a_one_line_aggregate_are_not_globals() {
    let payload = scan("struct point { int x, y; };\nvoid f(struct point *p) { p->x = 1; p->y = 2; }\n");
    assert!(zones(&payload).is_empty(), "{:?}", zones(&payload));

    let typedef = scan("typedef struct { int len; } buf_t;\nvoid f(buf_t *b) { b->len = 1; }\n");
    assert!(zones(&typedef).is_empty(), "{:?}", zones(&typedef));

    // The instance is still a zone; only its members stopped being one.
    let instance = scan("struct S { int a; int b; };\nstruct S g;\nvoid f(void) { g.a = 1; g.b = 2; }\n");
    assert_eq!(zones(&instance), BTreeSet::from(["g".to_string()]));
}

/// The parameter list was found with the last bracket of the header rather than
/// the last one opened at depth zero, so "void apply(int (*cb)(int))" was named
/// after its callback. A function taking one was reachable from no caller, its
/// body fell to <unattributed>, and the pair was discarded.
#[test]
fn a_function_pointer_parameter_does_not_rename_its_function() {
    let payload = scan("int shared;\nvoid apply(int (*cb)(int))\n{\n    shared = 1;\n}\n");
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["function"], "apply", "{write:?}");
}

/// A loop whose brace opens the next line, the Allman form, left its body
/// marked by nothing: the brace itself does not spell "for". A pool spawned
/// inside one was reported as a single thread that cannot race with itself, so
/// the file came back with no candidate at all.
#[test]
fn a_thread_spawned_in_a_loop_whose_brace_opens_the_next_line_may_repeat() {
    let payload = scan(
        r#"
int shared;
void *worker(void *arg) { shared = 1; return 0; }
int main(void)
{
    pthread_t t[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        pthread_create(&t[i], 0, worker, 0);
    }
    return 0;
}
"#,
    );
    let entry = payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["entry"] == "worker")
        .expect("worker is a thread entry");
    assert_eq!(entry["spawned_in_loop"], true, "{entry:?}");
    assert_eq!(entry["may_repeat"], true, "{entry:?}");
    assert!(!candidates(&payload).is_empty());
}

/// Pairing runs over the events that were kept, so the event limit truncates
/// the enumeration as surely as the pair budget does. Reporting it complete
/// made a candidate list built from two events out of six read as the whole
/// answer.
#[test]
fn an_event_limit_makes_the_candidate_enumeration_incomplete() {
    let source = concat!(
        "int s;\n",
        "void *t1(void *a){ s = 1; s = 2; s = 3; return 0; }\n",
        "void *t2(void *a){ s = 4; return 0; }\n",
        "int main(void){ pthread_t x, y; pthread_create(&x, 0, t1, 0);",
        " pthread_create(&y, 0, t2, 0); return 0; }\n",
    );
    let cut = scan_in(source, 2, 2_000, false);
    assert!(cut["events_omitted"].as_u64().expect("omitted") > 0, "{cut:?}");
    assert_eq!(cut["candidate_enumeration_complete"], false, "{cut:?}");

    let whole = scan_in(source, 10_000, 2_000, false);
    assert_eq!(whole["events_omitted"], 0, "{whole:?}");
    assert_eq!(whole["candidate_enumeration_complete"], true, "{whole:?}");
}

/// The same question one line earlier. Braces used to be applied as every open
/// then every close, so on "} else {" the open ran first and the else branch
/// inherited the lockset of the branch above it. The test above did not catch
/// it because it unlocked inside the branch.
#[test]
fn a_lock_in_one_branch_does_not_reach_the_else_branch() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    if (c) {
        pthread_mutex_lock(&m);
    } else {
        shared = 1;
    }
}
"#,
    );
    // Without this the test passes on a scan that found no lock at all, which
    // is the shape the previous stdio test failed in.
    let lock = events(&payload)
        .iter()
        .find(|event| event["kind"] == "LOCK")
        .expect("the lock inside the branch");
    assert_eq!(lock["lockset"], json!(["m"]), "{lock:?}");

    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// An extra closing brace must not pop the frame that holds the next function's
/// locks, and a file mid-edit is the ordinary way this pass is handed one.
#[test]
fn an_unbalanced_brace_does_not_leak_a_lock_into_the_next_function() {
    let payload = scan(
        "int shared;\nvoid f(void) { pthread_mutex_lock(&m); }}\nvoid g(void) { shared = 1; }\n",
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["function"] == "g" && event["memory_zone"] == "shared")
        .expect("the write inside g");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// UNATTRIBUTED means the call graph did not reach this function, which is what
/// every call through a pointer looks like. Two such accesses were being
/// compared as one thread that runs once, and the pair discarded: the one claim
/// the name exists to refuse.
#[test]
fn an_unattributed_function_still_pairs() {
    let payload = scan(
        r#"
int shared;
void helper(void) { shared = 1; shared = 2; }
void *worker(void *p)
{
    void (*fp)(void) = helper;
    fp();
    return 0;
}
int main(void)
{
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    return 0;
}
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["function"] == "helper")
        .expect("an access inside helper");
    assert_eq!(write["threads"], json!(["<unattributed>"]), "{write:?}");
    assert!(
        candidates(&payload)
            .iter()
            .any(|candidate| candidate["memory_zone"] == "shared"),
        "{:?}",
        candidates(&payload)
    );
}

/// A comment, a string and an identifier that are not ASCII. The scan indexes
/// bytes and blanks per character, so this is where those two would disagree.
#[test]
fn non_ascii_source_is_scanned_without_panicking() {
    let payload = scan(
        "int shared;\n/* caf\u{e9} \u{2615} */\nvoid f(void) { const char *s = \"na\u{ef}ve\"; shared = 1; }\n",
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["kind"], "WRITE", "{write:?}");
    assert_eq!(zones(&payload), BTreeSet::from(["shared".to_string()]));
}

/// A call inside an earlier argument, nested. One pass over the line's brackets
/// answers every call on it; asking per call walked the suffix again each time.
#[test]
fn a_nested_call_argument_does_not_hide_the_thread_entry() {
    let payload = scan(
        "int shared;\nvoid *worker(void *p) { shared = 1; return 0; }\nint main(void) { pthread_t t; pthread_create(&t, attr(opts(1, 2)), worker, 0); return 0; }\n",
    );
    let entries: Vec<&str> = payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|entry| entry["entry"].as_str())
        .collect();
    assert_eq!(entries, vec!["worker"], "{payload:?}");
}

/// A limit of zero is a limit, not a special case: the counts still describe
/// what was found, and the completion flag still says the list is partial.
#[test]
fn a_zero_limit_keeps_the_counts_honest() {
    let source = r#"
int shared;
void *t1(void *a) { shared = 1; return 0; }
void *t2(void *a) { shared = 2; return 0; }
int main(void)
{
    pthread_t a, b;
    pthread_create(&a, 0, t1, 0);
    pthread_create(&b, 0, t2, 0);
    return 0;
}
"#;
    let no_events = scan_in(source, 0, 2_000, false);
    assert!(events(&no_events).is_empty());
    assert!(no_events["event_count"].as_u64().expect("count") > 0);
    assert_eq!(
        no_events["events_omitted"].as_u64(),
        no_events["event_count"].as_u64()
    );
    assert_eq!(no_events["candidate_enumeration_complete"], false, "{no_events:?}");

    let no_candidates = scan_in(source, 10_000, 0, false);
    assert!(candidates(&no_candidates).is_empty());
    assert!(no_candidates["candidate_count"].as_u64().expect("count") > 0);
    assert_eq!(
        no_candidates["candidates_omitted"].as_u64(),
        no_candidates["candidate_count"].as_u64()
    );
}

/// A definition whose opening line also ends a statement was discarded whole,
/// body and all, because the semicolon was tested before the brace.
#[test]
fn a_definition_that_opens_and_ends_a_statement_on_one_line_is_a_function() {
    let payload = scan(
        "int shared;\nvoid *worker(void *a) { shared = 1;\n    return 0;\n}\nint main(void) { pthread_t t, u; pthread_create(&t, 0, worker, 0); pthread_create(&u, 0, worker, 0); return 0; }\n",
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write inside worker");
    assert_eq!(write["function"], "worker", "{write:?}");
    assert!(!candidates(&payload).is_empty(), "{payload:?}");
}

/// A lock released inside a block must stay released after it. Restoring the
/// enclosing lockset resurrected the mutex, so the write below was reported as
/// holding a lock that had been given up: this pass inventing its own evidence,
/// which is worse than missing some.
#[test]
fn a_lock_released_inside_a_block_stays_released() {
    let payload = scan(
        r#"
int shared;
void f(void)
{
    pthread_mutex_lock(&m);
    if (1) {
        pthread_mutex_unlock(&m);
    }
    shared = 1;
}
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// The same scoping question with no brace to hang it on. "if (c) lock(&m);"
/// is ordinary C, and the lock was escaping to the rest of the function.
#[test]
fn a_lock_under_a_brace_less_branch_does_not_escape_it() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    if (c)
        pthread_mutex_lock(&m);
    shared = 1;
}
"#,
    );
    let lock = events(&payload)
        .iter()
        .find(|event| event["kind"] == "LOCK")
        .expect("the lock under the branch");
    assert_eq!(lock["lockset"], json!(["m"]), "{lock:?}");
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// A lock held across a block that neither takes nor releases one survives it,
/// which is what keeps the rule above from being "drop every lock".
#[test]
fn a_lock_held_across_a_block_survives_it() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    pthread_mutex_lock(&m);
    if (c) {
        shared = 1;
    }
    shared = 2;
}
"#,
    );
    for event in events(&payload).iter().filter(|e| e["memory_zone"] == "shared") {
        assert_eq!(event["lockset"], json!(["m"]), "{event:?}");
    }
}

/// A file that was never read truncates the scan at its input, harder than any
/// limit does, so the completion flag cannot stay true.
#[test]
fn an_unreadable_file_makes_the_enumeration_incomplete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let good = dir.path().join("good.c");
    std::fs::write(
        &good,
        "int shared;\nvoid *t1(void *a) { shared = 1; return 0; }\nvoid *t2(void *a) { shared = 2; return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }\n",
    )
    .expect("write");
    let payload = scan_sources(
        &[
            good.to_string_lossy().into_owned(),
            "/nonexistent/missing.c".to_string(),
        ],
        10_000,
        2_000,
        false,
    );
    assert_eq!(payload["unreadable_files"].as_array().expect("unreadable").len(), 1);
    assert_eq!(payload["candidate_enumeration_complete"], false, "{payload:?}");
}

/// A byte order mark is not part of the first declaration.
#[test]
fn a_byte_order_mark_does_not_eat_the_first_declaration() {
    let payload = scan("\u{feff}int shared;\nvoid f(void) { shared = 1; }\n");
    assert_eq!(zones(&payload), BTreeSet::from(["shared".to_string()]));
}

/// A keyword alone on a line has no byte after it, and opens_branch indexed
/// for one. "else" written that way is most of the C there is, so an ordinary
/// file panicked the scan inside its spawn_blocking and the tool answered
/// "concurrency scan failed" for every source that contained one.
#[test]
fn a_branch_keyword_alone_on_a_line_does_not_stop_the_scan() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    if (c)
        shared = 1;
    else
        shared = 2;
}
"#,
    );
    assert_eq!(zones(&payload), BTreeSet::from(["shared".to_string()]));
    assert_eq!(events(&payload).len(), 2, "{payload:?}");
}

/// The single-line form of a brace-less branch scopes its lock to the line it
/// is written on. Only the next line was ever wrapped, so this lock escaped
/// into the rest of the function and every access below it was reported as
/// holding a mutex taken under a condition, while the line after it, which is
/// not the branch body, was wrapped in a block of its own.
#[test]
fn a_lock_beside_its_branch_head_does_not_escape_the_line() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    if (c) pthread_mutex_lock(&m);
    shared = 1;
}
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// "else if (c)" is two branch heads and not a branch whose body is the "if"
/// beside it, so the statement below it is still the one that gets scoped.
#[test]
fn an_else_if_scopes_the_statement_under_it() {
    let payload = scan(
        r#"
int shared;
void f(int c)
{
    if (c)
        shared = 0;
    else if (c > 1)
        pthread_mutex_lock(&m);
    shared = 1;
}
"#,
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared" && event["source_location"]["line"] == 9)
        .expect("the write after the branch");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
}

/// A trylock can return EBUSY, so it is never a lock held. Treating it as an
/// acquisition put it in the lockset of everything below it, and lock_note
/// then told the caller both accesses were protected by a mutex neither of
/// them may have taken.
#[test]
fn a_trylock_is_an_event_and_never_a_lock_held() {
    let payload = scan(
        r#"
int shared;
void *t1(void *arg)
{
    pthread_mutex_trylock(&m);
    shared = 1;
    return 0;
}
"#,
    );
    let attempt = events(&payload)
        .iter()
        .find(|event| event["kind"] == "TRYLOCK")
        .expect("the trylock event");
    assert_eq!(attempt["memory_zone"], "m", "{attempt:?}");
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write to shared");
    assert_eq!(write["lockset"].as_array().expect("lockset").len(), 0, "{write:?}");
    assert_eq!(payload["lock_order"].as_array().expect("lock_order").len(), 0, "{payload:?}");
}

/// A spawn whose argument list wraps is still a spawn. threads_detected read
/// the entries this pass resolved rather than the calls it saw, so a
/// pthread_create written over two lines, which is how most of them are
/// written, reported a concurrent program as not concurrent: no candidates, a
/// complete enumeration, and nothing saying an entry had been missed.
#[test]
fn a_spawn_whose_arguments_wrap_is_still_a_spawn() {
    let payload = scan(
        r#"
int shared;
void *worker(void *arg)
{
    shared = 1;
    return 0;
}
int main(void)
{
    pthread_t a;
    pthread_create(&a, 0,
                   worker, 0);
    return 0;
}
"#,
    );
    assert_eq!(payload["threads_detected"], true, "{payload:?}");
    assert_eq!(payload["unresolved_spawn_sites"], 1, "{payload:?}");
    assert_eq!(
        payload["thread_entries"].as_array().expect("entries").len(),
        0,
        "{payload:?}"
    );
}

/// A program with no spawn at all still reports none of the above, which is
/// what keeps the flag above from meaning nothing.
#[test]
fn a_program_with_no_spawn_reports_no_unresolved_site() {
    let payload = scan("int shared;\nvoid f(void) { shared = 1; }\n");
    assert_eq!(payload["threads_detected"], false, "{payload:?}");
    assert_eq!(payload["unresolved_spawn_sites"], 0, "{payload:?}");
}

/// The scan stops itself, rather than the caller stopping waiting for it.
///
/// A blocking task cannot be cancelled, so the tool's timeout detaches the
/// thread and leaves it running with everything it allocated. This is the half
/// that ends the work, and a scan that gave up says so in the same field every
/// other truncation uses.
#[test]
fn a_scan_that_runs_out_of_budget_says_the_counts_are_a_floor() {
    let mut source = String::from("int shared;\nvoid *t1(void *a) {\n");
    for _ in 0..4000 {
        source.push_str("    shared = 1;\n");
    }
    source.push_str("    return 0;\n}\n");
    source.push_str("int main(void) { pthread_t a; pthread_create(&a, 0, t1, 0); return 0; }\n");

    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("long.c");
    std::fs::write(&file, &source).expect("write fixture");
    let path = [file.to_string_lossy().into_owned()];

    // A budget this small expires before the first line is emitted, so the
    // scan stops at once. That is what makes the two flags deterministic; it
    // is not a partial count, and an earlier version of this test compared the
    // two runs' event counts as though it were, which only ever asserted that
    // some number exceeds zero.
    let stopped = scan_within(&path, 10_000, 2_000, false, std::time::Duration::from_nanos(1));
    assert_eq!(stopped["scan_complete"], false, "{stopped:?}");
    assert_eq!(stopped["candidate_enumeration_complete"], false, "{stopped:?}");
    assert_eq!(stopped["event_count"], 0, "{stopped:?}");

    let whole = scan_within(&path, 10_000, 2_000, false, std::time::Duration::from_secs(120));
    assert_eq!(whole["scan_complete"], true, "{whole:?}");
    assert!(whole["event_count"].as_u64().expect("count") > 0);
}

/// A pool spawned by a loop whose body sits beside its head. Marking only the
/// following line reported the entry as a thread that runs once, so four
/// threads writing one global produced no candidate at all.
#[test]
fn a_loop_that_spawns_on_its_own_line_may_repeat() {
    let payload = scan(
        r#"
int shared;
void *worker(void *a) { shared = 1; return 0; }
int main(void)
{
    pthread_t t[4];
    int i;
    for (i = 0; i < 4; i++) pthread_create(&t[i], 0, worker, 0);
    return 0;
}
"#,
    );
    let entry = payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["entry"] == "worker")
        .expect("worker is a thread entry");
    assert_eq!(entry["spawned_in_loop"], true, "{entry:?}");
    assert_eq!(entry["may_repeat"], true, "{entry:?}");
    assert!(!candidates(&payload).is_empty(), "{payload:?}");
}

/// An initializer is allowed parentheses. Testing the whole statement for them
/// rejected the declaration, and the global went with it.
#[test]
fn a_global_initialized_by_a_macro_call_is_still_a_global() {
    let payload = scan("int limit = SEC(5);\nvoid f(void) { limit = 1; }\n");
    assert_eq!(zones(&payload), BTreeSet::from(["limit".to_string()]));
}

/// A fifo is not a translation unit, and reading one does not return. It is
/// named as unreadable rather than hung on.
#[test]
fn a_file_that_is_not_regular_is_reported_rather_than_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("subdir.c");
    std::fs::create_dir(&path).expect("make a directory where a file is named");
    let payload = scan_sources(
        &[path.to_string_lossy().into_owned()],
        10_000,
        2_000,
        false,
    );
    let unreadable = payload["unreadable_files"].as_array().expect("unreadable");
    assert_eq!(unreadable.len(), 1, "{unreadable:?}");
    assert_eq!(unreadable[0]["error"], "not a regular file", "{unreadable:?}");
}

fn entry<'a>(payload: &'a Value, name: &str) -> &'a Value {
    payload["thread_entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["entry"] == name)
        .unwrap_or_else(|| panic!("{name} is a thread entry: {payload:?}"))
}

/// Whether some candidate pairs a write to "zone" with itself, which is the
/// report for one write running in two instances of its thread.
fn has_self_candidate(payload: &Value, zone: &str) -> bool {
    candidates(payload).iter().any(|candidate| {
        candidate["memory_zone"] == zone && candidate["accesses"][0] == candidate["accesses"][1]
    })
}

fn access_kinds<'a>(payload: &'a Value, zone: &str) -> BTreeSet<&'a str> {
    events(payload)
        .iter()
        .filter(|event| event["memory_zone"] == zone)
        .filter_map(|event| event["kind"].as_str())
        .collect()
}

fn lockset_at_line(payload: &Value, zone: &str, line: u64) -> Value {
    events(payload)
        .iter()
        .find(|event| event["memory_zone"] == zone && event["source_location"]["line"] == line)
        .unwrap_or_else(|| panic!("an access to {zone} on line {line}: {payload:?}"))["lockset"]
        .clone()
}

/// A creation helper called twice starts two threads from one textual
/// pthread_create that sits in no loop. Only a loop around that line was read
/// as repetition, so the counter both instances bump was reported as written
/// by one thread that cannot race with itself, and the file came back clean.
#[test]
fn a_creation_helper_called_twice_spawns_a_repeating_thread() {
    let payload = scan(
        "int counter;\npthread_t t;\nvoid *w(void *a) { counter++; return 0; }\nvoid start(void) { pthread_create(&t, 0, w, 0); }\nint main(void) { start(); start(); return 0; }\n",
    );
    let spawned = entry(&payload, "w");
    assert_eq!(spawned["spawn_sites"], 1, "{spawned:?}");
    assert_eq!(spawned["spawned_in_loop"], false, "{spawned:?}");
    assert_eq!(spawned["spawner_may_repeat"], true, "{spawned:?}");
    assert_eq!(spawned["may_repeat"], true, "{spawned:?}");
    assert!(has_self_candidate(&payload, "counter"), "{payload:?}");
}

/// The same helper called once from a loop, and once from a function that
/// calls itself. Both run the pthread_create more than once.
#[test]
fn a_creation_helper_in_a_loop_or_a_recursion_spawns_a_repeating_thread() {
    let looped = scan(
        "int counter;\npthread_t t;\nvoid *w(void *a) { counter++; return 0; }\nvoid start(void) { pthread_create(&t, 0, w, 0); }\nint main(void)\n{\n    int i;\n    for (i = 0; i < 4; i++)\n        start();\n    return 0;\n}\n",
    );
    assert!(has_self_candidate(&looped, "counter"), "{looped:?}");

    let recursive = scan(
        "int counter;\npthread_t t;\nvoid *w(void *a) { counter++; return 0; }\nvoid start(int n) { pthread_create(&t, 0, w, 0); if (n) start(n - 1); }\nint main(void) { start(3); return 0; }\n",
    );
    assert!(has_self_candidate(&recursive, "counter"), "{recursive:?}");
}

/// A thread spawned from inside a thread that is itself spawned in a loop is
/// as many threads as its parent is.
#[test]
fn a_spawn_inside_a_repeating_thread_repeats() {
    let payload = scan(
        "int counter;\nvoid *leaf(void *a) { counter++; return 0; }\nvoid *parent(void *a) { pthread_t t; pthread_create(&t, 0, leaf, 0); return 0; }\nint main(void)\n{\n    pthread_t t[4];\n    int i;\n    for (i = 0; i < 4; i++)\n        pthread_create(&t[i], 0, parent, 0);\n    return 0;\n}\n",
    );
    assert_eq!(entry(&payload, "leaf")["may_repeat"], true, "{payload:?}");
    assert!(has_self_candidate(&payload, "counter"), "{payload:?}");
}

/// The control for the three above: a helper called once, outside any loop,
/// starts one thread. Its header shares a line with its brace, where its own
/// name reads as a call of itself; counted as one, every function written that
/// way would look recursive and this would report a race that is not there.
#[test]
fn a_creation_helper_called_once_does_not_repeat() {
    let payload = scan(
        "int counter;\npthread_t t;\nvoid *w(void *a) { counter++; return 0; }\nvoid start(void) { pthread_create(&t, 0, w, 0); }\nint main(void) { start(); return 0; }\n",
    );
    let spawned = entry(&payload, "w");
    assert_eq!(spawned["spawner_may_repeat"], false, "{spawned:?}");
    assert_eq!(spawned["may_repeat"], false, "{spawned:?}");
    assert!(candidates(&payload).is_empty(), "{payload:?}");
}

/// A creation wrapper whose start routine is a parameter resolves its entry to
/// the parameter, so the routine's body is unattributed. Unattributed was never
/// repeating, so a body run by two threads was reported as one that cannot
/// race with itself.
#[test]
fn a_thread_started_through_a_wrapper_parameter_may_repeat() {
    let payload = scan(
        "int counter;\nvoid spawn(void *(*fn)(void *)) { pthread_t t; pthread_create(&t, 0, fn, 0); }\nvoid *w(void *a) { counter++; return 0; }\nint main(void) { spawn(w); spawn(w); return 0; }\n",
    );
    let write = events(&payload)
        .iter()
        .find(|event| event["memory_zone"] == "counter")
        .expect("the write to counter");
    assert_eq!(write["threads"], json!(["<unattributed>"]), "{write:?}");
    assert_eq!(write["thread_may_repeat"], true, "{write:?}");
    assert!(has_self_candidate(&payload, "counter"), "{payload:?}");
}

/// A GCC atomic builtin's address argument was read as a plain READ, because
/// the assignment test never fires inside a call. Two threads incrementing one
/// counter atomically then looked like two readers, and an atomic increment
/// against a plain read looked like two readers too, so the real race in the
/// second case was dropped.
#[test]
fn an_atomic_builtin_is_an_atomic_access() {
    let source = "int counter;\nvoid *t1(void *a) { __atomic_fetch_add(&counter, 1, __ATOMIC_SEQ_CST); return 0; }\nvoid *t2(void *a) { __sync_fetch_and_add(&counter, 1); return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }\n";
    let payload = scan(source);
    assert_eq!(
        access_kinds(&payload, "counter"),
        BTreeSet::from(["ATOMIC_RMW"]),
        "{payload:?}"
    );
    assert!(candidates(&payload).is_empty(), "{payload:?}");

    let mixed = scan(
        "int counter;\nvoid *t1(void *a) { __atomic_fetch_add(&counter, 1, __ATOMIC_SEQ_CST); return 0; }\nvoid *t2(void *a) { int seen = counter; return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }\n",
    );
    let found = candidates(&mixed);
    assert_eq!(found.len(), 1, "{mixed:?}");
    assert_eq!(found[0]["kinds"], json!(["ATOMIC_RMW", "READ"]), "{found:?}");
}

/// C11 stdatomic calls: a load is an atomic read and a store an atomic write,
/// and the value argument beside the address is still an ordinary read.
#[test]
fn a_stdatomic_call_is_an_atomic_access() {
    let payload = scan(
        "int flag;\nint value;\nvoid *t1(void *a) { atomic_store(&flag, value); return 0; }\nvoid *t2(void *a) { if (atomic_load(&flag)) { return 0; } return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }\n",
    );
    assert_eq!(
        access_kinds(&payload, "flag"),
        BTreeSet::from(["ATOMIC_READ", "ATOMIC_WRITE"]),
        "{payload:?}"
    );
    assert_eq!(access_kinds(&payload, "value"), BTreeSet::from(["READ"]), "{payload:?}");
    assert!(candidates(&payload).is_empty(), "{payload:?}");
}

/// A global declared atomic is accessed atomically however it is spelled, and
/// "_Atomic(int)" used to be read as a prototype and lose the global. A name
/// that merely starts with "atomic_" is not a type.
#[test]
fn a_global_declared_atomic_is_accessed_atomically() {
    let payload = scan(
        "_Atomic int hits;\natomic_int other;\n_Atomic(int) third;\nint atomic_count;\nvoid *w(void *a) { hits++; other = 1; third += 2; atomic_count++; return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, w, 0); pthread_create(&b, 0, w, 0); return 0; }\n",
    );
    for zone in ["hits", "other", "third"] {
        assert_eq!(
            access_kinds(&payload, zone),
            BTreeSet::from(["ATOMIC_WRITE"]),
            "{zone}: {payload:?}"
        );
    }
    assert_eq!(
        access_kinds(&payload, "atomic_count"),
        BTreeSet::from(["WRITE"]),
        "{payload:?}"
    );
    let zones_raced: BTreeSet<&str> = candidates(&payload)
        .iter()
        .filter_map(|candidate| candidate["memory_zone"].as_str())
        .collect();
    assert_eq!(zones_raced, BTreeSet::from(["atomic_count"]), "{payload:?}");
}

/// SV-COMP marks atomic sections with "__VERIFIER_atomic_begin()" and
/// "__VERIFIER_atomic_end()", and whole functions by a "__VERIFIER_atomic"
/// name prefix. Both are held as one pseudo-lock, which is evidence like any
/// other lock and never a verdict.
#[test]
fn a_verifier_atomic_section_is_a_pseudo_lock() {
    let payload = scan(
        "int shared;\nvoid __VERIFIER_atomic_inc(void) { shared = shared + 1; }\nvoid *t1(void *a) { __VERIFIER_atomic_begin(); shared = 2; __VERIFIER_atomic_end(); shared = 3; return 0; }\nvoid *t2(void *a) { __VERIFIER_atomic_inc(); return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }\n",
    );
    let atomic_fn: Vec<&Value> = events(&payload)
        .iter()
        .filter(|e| e["function"] == "__VERIFIER_atomic_inc")
        .collect();
    assert!(!atomic_fn.is_empty(), "{payload:?}");
    for event in atomic_fn {
        assert_eq!(event["lockset"], json!(["<atomic>"]), "{event:?}");
    }
    let in_t1: Vec<&Value> = events(&payload)
        .iter()
        .filter(|e| e["function"] == "t1" && e["memory_zone"] == "shared")
        .collect();
    assert_eq!(in_t1.len(), 2, "{payload:?}");
    assert_eq!(in_t1[0]["lockset"], json!(["<atomic>"]), "{in_t1:?}");
    assert_eq!(in_t1[1]["lockset"], json!([]), "{in_t1:?}");
    assert!(!candidates(&payload).is_empty(), "the pseudo-lock is evidence, not a verdict");
}

/// A semaphore handle passed to sem_wait was read as a READ of a global, and
/// the semaphore was no lock at all, so the write it guards held nothing.
#[test]
fn a_semaphore_is_a_lock_and_its_handle_is_not_an_access() {
    let payload = scan(
        "sem_t s;\nint shared;\nvoid *t1(void *a)\n{\n    sem_wait(&s);\n    shared = 1;\n    sem_post(&s);\n    return 0;\n}\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t1, 0); return 0; }\n",
    );
    assert_eq!(
        access_kinds(&payload, "s"),
        BTreeSet::from(["LOCK", "UNLOCK"]),
        "{payload:?}"
    );
    assert_eq!(lockset_at_line(&payload, "shared", 6), json!(["s"]), "{payload:?}");
}

/// A read-held rwlock excludes writers and not readers, so it is evidence for
/// nothing between two accesses that both hold it for reading, a write
/// included. A write-held one is evidence like a mutex.
#[test]
fn a_read_held_rwlock_is_not_evidence_between_two_readers() {
    let read_side = scan(
        "int shared;\nvoid *t1(void *a) { pthread_rwlock_rdlock(&rw); shared = 1; pthread_rwlock_unlock(&rw); return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t1, 0); return 0; }\n",
    );
    let write = events(&read_side)
        .iter()
        .find(|event| event["memory_zone"] == "shared")
        .expect("the write");
    assert_eq!(write["lockset"], json!(["rw"]), "{write:?}");
    assert_eq!(write["read_lockset"], json!(["rw"]), "{write:?}");
    assert!(!candidates(&read_side).is_empty(), "{read_side:?}");
    for candidate in candidates(&read_side) {
        assert_eq!(candidate["lock_evidence"], Value::Null, "{candidate:?}");
    }

    let write_side = scan(
        "int shared;\nvoid *t1(void *a) { pthread_rwlock_wrlock(&rw); shared = 1; pthread_rwlock_unlock(&rw); return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t1, 0); return 0; }\n",
    );
    let found = candidates(&write_side);
    assert!(!found.is_empty(), "{write_side:?}");
    assert_eq!(
        found[0]["lock_evidence"]["common_lexical_locks"],
        json!(["rw"]),
        "{found:?}"
    );
}

/// Timed acquisitions can fail by timing out, so they follow the trylock rule;
/// a spin lock is a lock.
#[test]
fn a_timed_lock_is_never_held_and_a_spin_lock_is() {
    let payload = scan(
        "int shared;\nint other;\nvoid f(void)\n{\n    pthread_mutex_timedlock(&m, &ts);\n    shared = 1;\n    pthread_spin_lock(&sp);\n    other = 1;\n    pthread_spin_unlock(&sp);\n}\n",
    );
    assert_eq!(lockset_at_line(&payload, "shared", 6), json!([]), "{payload:?}");
    assert_eq!(lockset_at_line(&payload, "other", 8), json!(["sp"]), "{payload:?}");
}

/// pthread_cond_wait releases its mutex, which is the second argument, and
/// takes it again on return while every other lock is still held, so that is a
/// second acquisition of the order edge into it.
#[test]
fn a_condition_wait_reacquires_its_mutex_in_the_lock_order() {
    let payload = scan(
        "void f(void)\n{\n    pthread_mutex_lock(&a);\n    pthread_mutex_lock(&m);\n    pthread_cond_wait(&c, &m);\n    pthread_mutex_unlock(&m);\n    pthread_mutex_unlock(&a);\n}\n",
    );
    let order = payload["lock_order"].as_array().expect("lock order");
    assert_eq!(order.len(), 1, "{order:?}");
    assert_eq!(order[0]["from"], "a", "{order:?}");
    assert_eq!(order[0]["to"], "m", "{order:?}");
    assert_eq!(order[0]["site_count"], 2, "{order:?}");
    let wait = events(&payload)
        .iter()
        .find(|event| event["kind"] == "COND_WAIT")
        .expect("the wait event");
    assert_eq!(wait["memory_zone"], "m", "{wait:?}");
    assert_eq!(wait["lockset"], json!(["a", "m"]), "{wait:?}");
}

/// The lock order list held one entry per acquisition site with no bound. A
/// pair is one entry now, with its sites and their count.
#[test]
fn a_lock_order_edge_is_listed_once_with_its_sites() {
    let payload = scan(
        "void f(void)\n{\n    pthread_mutex_lock(&a);\n    pthread_mutex_lock(&b);\n    pthread_mutex_unlock(&b);\n    pthread_mutex_lock(&b);\n    pthread_mutex_unlock(&b);\n    pthread_mutex_unlock(&a);\n}\n",
    );
    let order = payload["lock_order"].as_array().expect("lock order");
    assert_eq!(order.len(), 1, "{order:?}");
    assert_eq!(order[0]["site_count"], 2, "{order:?}");
    assert_eq!(order[0]["sites"].as_array().expect("sites").len(), 2, "{order:?}");
    assert_eq!(order[0]["source"]["line"], 4, "{order:?}");
    assert_eq!(payload["lock_order_count"], 1, "{payload:?}");
    assert_eq!(payload["lock_order_complete"], true, "{payload:?}");
}

/// The lock order is capped with the events, and a cut graph says so, because
/// a cycle among the dropped edges is one nothing reports.
#[test]
fn a_capped_lock_order_says_it_is_incomplete() {
    let payload = scan_in(
        "void f(void) { pthread_mutex_lock(&a); pthread_mutex_lock(&b); pthread_mutex_unlock(&b); pthread_mutex_unlock(&a); }\nvoid g(void) { pthread_mutex_lock(&c); pthread_mutex_lock(&d); pthread_mutex_unlock(&d); pthread_mutex_unlock(&c); }\n",
        1,
        2_000,
        false,
    );
    assert_eq!(payload["lock_order"].as_array().expect("order").len(), 1, "{payload:?}");
    assert_eq!(payload["lock_order_sites_omitted"], 1, "{payload:?}");
    assert_eq!(payload["lock_order_complete"], false, "{payload:?}");
}

/// Two threads taking two locks in opposite orders is the textbook deadlock,
/// and the edges were listed with nothing reading them as a cycle.
#[test]
fn opposite_lock_orders_in_two_threads_are_a_deadlock_candidate() {
    let payload = scan(
        "void *t1(void *x) { pthread_mutex_lock(&a); pthread_mutex_lock(&b); pthread_mutex_unlock(&b); pthread_mutex_unlock(&a); return 0; }\nvoid *t2(void *x) { pthread_mutex_lock(&b); pthread_mutex_lock(&a); pthread_mutex_unlock(&a); pthread_mutex_unlock(&b); return 0; }\nint main(void) { pthread_t p, q; pthread_create(&p, 0, t1, 0); pthread_create(&q, 0, t2, 0); return 0; }\n",
    );
    let found = payload["deadlock_candidates"].as_array().expect("deadlocks");
    assert_eq!(found.len(), 1, "{payload:?}");
    assert_eq!(found[0]["locks"].as_array().expect("locks").len(), 2, "{found:?}");
    assert_eq!(found[0]["edges"].as_array().expect("edges").len(), 2, "{found:?}");
    assert_eq!(found[0]["status"], "potential", "{found:?}");
}

/// The same cycle taken by one thread that runs once is an order it uses both
/// ways at different times, which cannot deadlock against itself.
#[test]
fn opposite_lock_orders_in_one_thread_that_runs_once_are_not_a_deadlock() {
    let payload = scan(
        "void *t1(void *x) { pthread_mutex_lock(&a); pthread_mutex_lock(&b); pthread_mutex_unlock(&b); pthread_mutex_unlock(&a); pthread_mutex_lock(&b); pthread_mutex_lock(&a); pthread_mutex_unlock(&a); pthread_mutex_unlock(&b); return 0; }\nint main(void) { pthread_t p; pthread_create(&p, 0, t1, 0); return 0; }\n",
    );
    assert_eq!(payload["lock_order"].as_array().expect("order").len(), 2, "{payload:?}");
    assert_eq!(payload["deadlock_candidates"], json!([]), "{payload:?}");
}

/// A lock taken while it is lexically held is reported as a double lock.
#[test]
fn a_lock_taken_while_held_is_a_double_lock() {
    let payload = scan(
        "void f(void)\n{\n    pthread_mutex_lock(&m);\n    pthread_mutex_lock(&m);\n    pthread_mutex_unlock(&m);\n    pthread_mutex_unlock(&m);\n}\n",
    );
    let doubled = payload["double_lock"].as_array().expect("double_lock");
    assert_eq!(doubled.len(), 1, "{payload:?}");
    assert_eq!(doubled[0]["lock"], "m", "{doubled:?}");
}

/// A thread entry that reaches its closing brace holding a lock never releases
/// it. A helper that returns holding one is a lock wrapper and is not reported.
#[test]
fn a_thread_entry_ending_with_a_lock_held_is_reported() {
    let payload = scan(
        "int shared;\nvoid take(void) { pthread_mutex_lock(&w); }\nvoid *t1(void *a)\n{\n    pthread_mutex_lock(&m);\n    shared = 1;\n    return 0;\n}\nint main(void) { pthread_t p; pthread_create(&p, 0, t1, 0); take(); return 0; }\n",
    );
    let unreleased = payload["unreleased_lock"].as_array().expect("unreleased_lock");
    assert_eq!(unreleased.len(), 1, "{payload:?}");
    assert_eq!(unreleased[0]["entry"], "t1", "{unreleased:?}");
    assert_eq!(unreleased[0]["locks"], json!(["m"]), "{unreleased:?}");
    assert_eq!(unreleased[0]["source"]["line"], 8, "{unreleased:?}");
}

/// The early-return idiom: a guard that unlocks and returns leaves the lock
/// held on the path that continues. Intersecting the guard's block dropped it,
/// so every access after the guard was reported as holding nothing.
#[test]
fn an_unlock_before_an_early_return_does_not_release_the_path_after_it() {
    let payload = scan(
        r#"
int shared;
int f(int err)
{
    pthread_mutex_lock(&m);
    if (err) {
        pthread_mutex_unlock(&m);
        return -1;
    }
    shared = 1;
    pthread_mutex_unlock(&m);
    return 0;
}
"#,
    );
    assert_eq!(lockset_at_line(&payload, "shared", 10), json!(["m"]), "{payload:?}");
}

/// A conditional return is not the end of the block around it, so the block
/// still intersects. Reading the line above the brace alone would have taken
/// "return" for the block's last statement.
#[test]
fn a_conditional_return_does_not_end_its_block() {
    let payload = scan(
        r#"
int shared;
int f(int c, int d)
{
    pthread_mutex_lock(&m);
    if (c) {
        pthread_mutex_unlock(&m);
        if (d)
            return 0;
    }
    shared = 1;
    return 0;
}
"#,
    );
    assert_eq!(lockset_at_line(&payload, "shared", 11), json!([]), "{payload:?}");
}

/// A path that unlocks and breaks out of a loop lands after the loop, not after
/// the block it broke out of, so the code after the loop does not hold the lock
/// while the rest of the loop body does.
#[test]
fn an_unlock_before_a_break_reaches_the_code_after_the_loop() {
    let payload = scan(
        r#"
int shared;
int other;
void f(int c, int x)
{
    pthread_mutex_lock(&m);
    while (c) {
        if (x) {
            pthread_mutex_unlock(&m);
            break;
        }
        other = 1;
    }
    shared = 1;
}
"#,
    );
    assert_eq!(lockset_at_line(&payload, "other", 12), json!(["m"]), "{payload:?}");
    assert_eq!(lockset_at_line(&payload, "shared", 14), json!([]), "{payload:?}");
}

/// A "continue" inside a switch lands at the loop around it, not after the
/// switch. Merging it after the switch dropped m there, so an access between
/// the switch and the loop's end was reported as holding nothing although the
/// only path that released m never reaches it.
#[test]
fn a_continue_inside_a_switch_lands_at_the_loop() {
    let braced = scan(
        r#"
int shared;
void f(int c, int x)
{
    while (c) {
        pthread_mutex_lock(&m);
        switch (x) {
        case 1: {
            pthread_mutex_unlock(&m);
            continue;
        }
        }
        shared = 1;
        pthread_mutex_unlock(&m);
    }
}
"#,
    );
    assert_eq!(lockset_at_line(&braced, "shared", 13), json!(["m"]), "{braced:?}");

    let bare = scan(
        r#"
int shared;
void f(int c, int x)
{
    while (c) {
        pthread_mutex_lock(&m);
        switch (x) {
        case 1:
            pthread_mutex_unlock(&m);
            continue;
        }
        shared = 1;
        pthread_mutex_unlock(&m);
    }
}
"#,
    );
    assert_eq!(lockset_at_line(&bare, "shared", 12), json!(["m"]), "{bare:?}");
}

/// A path that unlocks and jumps forward lands at the label, where it is
/// merged with the path that fell through.
#[test]
fn an_unlock_before_a_goto_reaches_the_label() {
    let payload = scan(
        r#"
int shared;
int other;
void f(int e)
{
    pthread_mutex_lock(&m);
    if (e) {
        pthread_mutex_unlock(&m);
        goto out;
    }
    shared = 1;
out:
    other = 1;
}
"#,
    );
    assert_eq!(lockset_at_line(&payload, "shared", 11), json!(["m"]), "{payload:?}");
    assert_eq!(lockset_at_line(&payload, "other", 13), json!([]), "{payload:?}");
}

/// What this pass cannot see is listed. A lockset crosses a call now, so
/// "interprocedural locksets" is no longer one of them; what is left is that
/// one entry lockset serves every calling context, and that a lock argument
/// this pass cannot name is not renamed into a callee.
#[test]
fn what_a_lockset_cannot_cross_is_listed_as_unsupported() {
    let payload = scan("int shared;\nvoid f(void) { shared = 1; }\n");
    let unsupported = payload["evidence"]["unsupported"].as_array().expect("unsupported");
    assert!(!unsupported.contains(&json!("interprocedural locksets")), "{unsupported:?}");
    for entry in [
        "context-sensitive locksets",
        "lock arguments that are not a plain global or parameter",
        "calls through function pointers",
    ] {
        assert!(unsupported.contains(&json!(entry)), "{entry}: {unsupported:?}");
    }
}

/// Two threads, each taking two locks through wrappers in opposite orders.
const WRAPPED_ABBA: &str = r#"
pthread_mutex_t a, b;
void lock_a(void) { pthread_mutex_lock(&a); }
void unlock_a(void) { pthread_mutex_unlock(&a); }
void lock_b(void) { pthread_mutex_lock(&b); }
void unlock_b(void) { pthread_mutex_unlock(&b); }
void *t1(void *x) { lock_a(); lock_b(); unlock_b(); unlock_a(); return 0; }
void *t2(void *x) { lock_b(); lock_a(); unlock_a(); unlock_b(); return 0; }
int main(void) { pthread_t p, q; pthread_create(&p, 0, t1, 0); pthread_create(&q, 0, t2, 0); return 0; }
"#;

fn order_pairs(payload: &Value) -> BTreeSet<(String, String)> {
    payload["lock_order"]
        .as_array()
        .expect("lock order")
        .iter()
        .map(|edge| (edge["from"].as_str().unwrap_or_default().to_string(), edge["to"].as_str().unwrap_or_default().to_string()))
        .collect()
}

/// A lock taken in a wrapper was dropped at the wrapper's closing brace, so the
/// textbook deadlock written through lock_a() and lock_b() gave no order edge
/// and no deadlock candidate: the "no deadlock here" this pass must not say.
#[test]
fn opposite_orders_through_lock_wrappers_are_a_deadlock_candidate() {
    let payload = scan(WRAPPED_ABBA);
    let pairs = order_pairs(&payload);
    assert!(pairs.contains(&("a".into(), "b".into())), "{pairs:?}");
    assert!(pairs.contains(&("b".into(), "a".into())), "{pairs:?}");
    let found = payload["deadlock_candidates"].as_array().expect("deadlocks");
    assert_eq!(found.len(), 1, "{payload:?}");
    assert_eq!(found[0]["locks"].as_array().expect("locks").len(), 2, "{found:?}");
    let summaries = payload["lock_summaries"].as_array().expect("lock_summaries");
    let lock_a = summaries.iter().find(|s| s["function"] == "lock_a").expect("lock_a summary");
    assert_eq!(lock_a["acquires"], json!([{"lock": "a", "mode": "exclusive"}]), "{lock_a:?}");
    let unlock_a = summaries.iter().find(|s| s["function"] == "unlock_a").expect("unlock_a summary");
    assert_eq!(unlock_a["releases"], json!([{"lock": "a"}]), "{unlock_a:?}");
    assert_eq!(payload["lock_summaries_converged"], true, "{payload:?}");
}

/// The wrapper's acquisition is visible after the call, and its unlock
/// wrapper's release is too.
#[test]
fn a_lock_taken_in_a_wrapper_is_held_after_the_call() {
    let payload = scan(
        "int shared;\nint other;\nvoid lock_m(void) { pthread_mutex_lock(&m); }\nvoid unlock_m(void) { pthread_mutex_unlock(&m); }\nvoid f(void)\n{\n    lock_m();\n    shared = 1;\n    unlock_m();\n    other = 1;\n}\n",
    );
    assert_eq!(lockset_at_line(&payload, "shared", 8), json!(["m"]), "{payload:?}");
    assert_eq!(lockset_at_line(&payload, "other", 10), json!([]), "{payload:?}");
}

/// A wrapper taking the mutex as a parameter is summarised by parameter, and
/// each call site renames it to its argument.
#[test]
fn opposite_orders_through_a_parameterized_wrapper_are_a_deadlock_candidate() {
    let payload = scan(
        r#"
pthread_mutex_t a, b;
void L(pthread_mutex_t *m) { pthread_mutex_lock(m); }
void U(pthread_mutex_t *m) { pthread_mutex_unlock(m); }
void *t1(void *x) { L(&a); L(&b); U(&b); U(&a); return 0; }
void *t2(void *x) { L(&b); L(&a); U(&a); U(&b); return 0; }
int main(void) { pthread_t p, q; pthread_create(&p, 0, t1, 0); pthread_create(&q, 0, t2, 0); return 0; }
"#,
    );
    let pairs = order_pairs(&payload);
    assert_eq!(pairs, BTreeSet::from([("a".into(), "b".into()), ("b".into(), "a".into())]), "{payload:?}");
    assert_eq!(payload["deadlock_candidates"].as_array().expect("deadlocks").len(), 1, "{payload:?}");
    let summaries = payload["lock_summaries"].as_array().expect("lock_summaries");
    let wrapper = summaries.iter().find(|s| s["function"] == "L").expect("L summary");
    assert_eq!(wrapper["acquires"], json!([{"parameter": 0, "name": "m", "mode": "exclusive"}]), "{wrapper:?}");
    assert_eq!(payload["lock_arguments_unresolved"], 0, "{payload:?}");
}

/// An argument this pass cannot name is counted, and its acquisition is not
/// claimed as held.
#[test]
fn a_lock_argument_that_is_not_a_plain_name_is_unresolved() {
    let payload = scan(
        "int shared;\nstruct s { pthread_mutex_t m; } *obj;\nvoid L(pthread_mutex_t *m) { pthread_mutex_lock(m); }\nvoid f(void)\n{\n    L(&obj->m);\n    shared = 1;\n}\n",
    );
    assert_eq!(payload["lock_arguments_unresolved"], 1, "{payload:?}");
    assert_eq!(lockset_at_line(&payload, "shared", 7), json!([]), "{payload:?}");
}

/// A helper called only with a lock held ran with an empty lockset, so its
/// access was reported as holding nothing while every caller held m.
#[test]
fn an_access_in_a_helper_always_called_under_a_lock_holds_it() {
    let payload = scan(
        r#"
int shared;
void helper(void)
{
    shared = 1;
}
void *t1(void *x) { pthread_mutex_lock(&m); helper(); pthread_mutex_unlock(&m); return 0; }
void *t2(void *x) { pthread_mutex_lock(&m); helper(); pthread_mutex_unlock(&m); return 0; }
int main(void) { pthread_t p, q; pthread_create(&p, 0, t1, 0); pthread_create(&q, 0, t2, 0); return 0; }
"#,
    );
    assert_eq!(lockset_at_line(&payload, "shared", 5), json!(["m"]), "{payload:?}");
    let entries = payload["entry_locksets"].as_array().expect("entry_locksets");
    assert_eq!(entries, &vec![json!({"function": "helper", "locks": ["m"]})], "{payload:?}");
}

/// One call site without the lock is a path into the helper that holds
/// nothing, so the helper's access holds nothing either.
#[test]
fn a_helper_called_once_without_the_lock_is_unprotected() {
    let payload = scan(
        r#"
int shared;
void helper(void)
{
    shared = 1;
}
void *t1(void *x) { pthread_mutex_lock(&m); helper(); pthread_mutex_unlock(&m); return 0; }
void *t2(void *x) { helper(); return 0; }
int main(void) { pthread_t p, q; pthread_create(&p, 0, t1, 0); pthread_create(&q, 0, t2, 0); return 0; }
"#,
    );
    assert_eq!(lockset_at_line(&payload, "shared", 5), json!([]), "{payload:?}");
    assert_eq!(payload["entry_locksets"], json!([]), "{payload:?}");
}

/// A helper whose address is taken has a caller this pass cannot see, so it
/// inherits nothing even when every direct call holds the lock.
#[test]
fn a_helper_whose_address_is_taken_inherits_nothing() {
    let payload = scan(
        r#"
int shared;
void helper(void)
{
    shared = 1;
}
void (*hook)(void) = helper;
void *t1(void *x) { pthread_mutex_lock(&m); helper(); pthread_mutex_unlock(&m); return 0; }
int main(void) { pthread_t p; pthread_create(&p, 0, t1, 0); return 0; }
"#,
    );
    assert_eq!(lockset_at_line(&payload, "shared", 5), json!([]), "{payload:?}");
}

/// A lock held by the caller orders before every lock the callee takes.
#[test]
fn a_lock_taken_in_a_callee_is_ordered_after_the_callers_lock() {
    let payload = scan(
        "void inner(void) { pthread_mutex_lock(&b); pthread_mutex_unlock(&b); }\nvoid outer(void) { pthread_mutex_lock(&a); inner(); pthread_mutex_unlock(&a); }\n",
    );
    let pairs = order_pairs(&payload);
    assert_eq!(pairs, BTreeSet::from([("a".into(), "b".into())]), "{payload:?}");
}

/// Recursion, direct and mutual, through wrappers that lock on one path and
/// unlock on another, still ends with a complete scan and settled summaries.
#[test]
fn recursive_lock_wrappers_terminate() {
    let payload = scan(
        r#"
int shared;
void r(int n) { if (n) { r(n - 1); return; } pthread_mutex_lock(&a); }
void p(int n);
void q(int n) { pthread_mutex_unlock(&a); if (n) p(n - 1); pthread_mutex_lock(&b); }
void p(int n) { pthread_mutex_lock(&a); q(n); pthread_mutex_unlock(&b); }
void *t1(void *x) { r(3); p(2); shared = 1; return 0; }
int main(void) { pthread_t t; pthread_create(&t, 0, t1, 0); return 0; }
"#,
    );
    assert_eq!(payload["scan_complete"], true, "{payload:?}");
    // The plain summary step alternates between two answers on p and q; the
    // monotone rounds after it settle, rather than giving up on every summary.
    assert_eq!(payload["lock_summaries_converged"], true, "{payload:?}");
    let summaries = payload["lock_summaries"].as_array().expect("lock_summaries");
    let r = summaries.iter().find(|s| s["function"] == "r");
    assert!(r.is_none(), "r locks a on one path only, so it acquires nothing: {summaries:?}");
    assert!(!events(&payload).is_empty(), "{payload:?}");
}

/// A lock wrapper called while holding a lock is one acquisition. The call
/// site records the edge from the summary, and the wrapper's own body used to
/// record it again from its inherited entry lockset, so one acquisition showed
/// as two sites.
#[test]
fn a_lock_wrapper_called_under_a_lock_records_its_edge_once() {
    let payload = scan(
        "void lock_m(void)\n{\n    pthread_mutex_lock(&m);\n}\n\nvoid f(void)\n{\n    pthread_mutex_lock(&a);\n    lock_m();\n    pthread_mutex_unlock(&m);\n    pthread_mutex_unlock(&a);\n}\n",
    );
    let order = payload["lock_order"].as_array().expect("lock order");
    let edge = order
        .iter()
        .find(|e| e["from"] == "a" && e["to"] == "m")
        .unwrap_or_else(|| panic!("a -> m is the one order here: {order:?}"));
    assert_eq!(edge["site_count"], 1, "{edge:?}");
    assert_eq!(edge["source"]["line"], 9, "recorded at the call: {edge:?}");
}

/// Two read locks never block each other, so a cycle every acquisition of
/// which is a read lock was reported as a deadlock that cannot happen. A
/// reader can still queue behind a writer, so the same cycle stays a candidate
/// as soon as either lock is taken for writing anywhere, even with nothing
/// else held, and when one side of an edge is a write lock.
#[test]
fn a_cycle_of_read_locks_alone_is_not_a_deadlock_candidate() {
    let rd = |first: &str, second: &str| {
        format!("pthread_rwlock_rdlock(&{first}); pthread_rwlock_rdlock(&{second}); pthread_rwlock_unlock(&{second}); pthread_rwlock_unlock(&{first});")
    };
    let program = |t1: &str, t2: &str, extra: &str| {
        format!(
            "void *t1(void *x) {{ {t1} return 0; }}\nvoid *t2(void *x) {{ {t2} return 0; }}\nvoid *t3(void *x) {{ {extra} return 0; }}\nint main(void) {{ pthread_t p, q, r; pthread_create(&p, 0, t1, 0); pthread_create(&q, 0, t2, 0); pthread_create(&r, 0, t3, 0); return 0; }}\n"
        )
    };
    let readers = scan(&program(&rd("a", "b"), &rd("b", "a"), ""));
    assert_eq!(readers["lock_order"].as_array().expect("order").len(), 2, "{readers:?}");
    assert_eq!(readers["deadlock_candidates"], json!([]), "{readers:?}");

    let writer = "pthread_rwlock_wrlock(&a); pthread_rwlock_unlock(&a);";
    let queued = scan(&program(&rd("a", "b"), &rd("b", "a"), writer));
    let found = queued["deadlock_candidates"].as_array().expect("deadlocks");
    assert_eq!(found.len(), 1, "a writer elsewhere: {queued:?}");

    let mixed = "pthread_rwlock_wrlock(&b); pthread_rwlock_rdlock(&a); pthread_rwlock_unlock(&a); pthread_rwlock_unlock(&b);";
    let one_writer = scan(&program(&rd("a", "b"), mixed, ""));
    let found = one_writer["deadlock_candidates"].as_array().expect("deadlocks");
    assert_eq!(found.len(), 1, "a write lock on one edge: {one_writer:?}");
}

/// A failed compare-exchange writes the current value into its "expected"
/// argument, with a plain store: that object is not atomic. It was read as a
/// plain READ, so a thread reading the same global beside it was no race.
#[test]
fn a_compare_exchange_writes_its_expected_argument() {
    for call in [
        "atomic_compare_exchange_strong(&cur, &expected, 1)",
        "atomic_compare_exchange_weak_explicit(&cur, &expected, 1, memory_order_seq_cst, memory_order_seq_cst)",
        "__atomic_compare_exchange_n(&cur, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)",
        "__atomic_compare_exchange(&cur, &expected, &desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)",
    ] {
        let payload = scan(&format!(
            "int cur;\nint expected;\nint desired;\nvoid *t1(void *a) {{ {call}; return 0; }}\nvoid *t2(void *a) {{ int seen = expected; return 0; }}\nint main(void) {{ pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }}\n"
        ));
        assert_eq!(access_kinds(&payload, "cur"), BTreeSet::from(["ATOMIC_RMW"]), "{call}: {payload:?}");
        assert_eq!(
            access_kinds(&payload, "expected"),
            BTreeSet::from(["READ", "WRITE"]),
            "{call}: {payload:?}"
        );
        let raced: BTreeSet<&str> = candidates(&payload)
            .iter()
            .filter_map(|candidate| candidate["memory_zone"].as_str())
            .collect();
        assert!(raced.contains("expected"), "{call}: {payload:?}");
    }

    // The value forms take "expected" by value and write nothing back.
    let by_value = scan(
        "int cur;\nint expected;\nvoid *t1(void *a) { __sync_val_compare_and_swap(&cur, expected, 1); return 0; }\nvoid *t2(void *a) { int seen = expected; return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, t1, 0); pthread_create(&b, 0, t2, 0); return 0; }\n",
    );
    assert_eq!(access_kinds(&by_value, "expected"), BTreeSet::from(["READ"]), "{by_value:?}");
}

/// Only the stdatomic type names make an object atomic. A user typedef that
/// happens to start with "atomic_" is an ordinary type, and reading it as
/// atomic paired its writes as atomic against atomic, which never conflicts.
#[test]
fn a_user_type_named_atomic_is_not_atomic() {
    let payload = scan(
        "typedef int atomic_counter_t;\natomic_counter_t hits;\natomic_uint_least32_t ticks;\natomic_flag ready;\nvoid *w(void *a) { hits++; ticks++; ready = 1; return 0; }\nint main(void) { pthread_t a, b; pthread_create(&a, 0, w, 0); pthread_create(&b, 0, w, 0); return 0; }\n",
    );
    assert_eq!(access_kinds(&payload, "hits"), BTreeSet::from(["WRITE"]), "{payload:?}");
    for zone in ["ticks", "ready"] {
        assert_eq!(
            access_kinds(&payload, zone),
            BTreeSet::from(["ATOMIC_WRITE"]),
            "{zone}: {payload:?}"
        );
    }
    let raced: BTreeSet<&str> = candidates(&payload)
        .iter()
        .filter_map(|candidate| candidate["memory_zone"].as_str())
        .collect();
    assert_eq!(raced, BTreeSet::from(["hits"]), "{payload:?}");
}

/// A lock reached through a parameter, such as "m->inner", is one no call site
/// can name. Its acquisition was dropped and its release cleared the caller's
/// held set, both without a trace in lock_arguments_unresolved, so the count
/// that says how much the summaries could not apply read zero.
#[test]
fn a_lock_reached_through_a_parameter_is_unresolved_at_the_call() {
    let payload = scan(
        "int shared;\nstruct s { pthread_mutex_t inner; } *obj;\nvoid L(struct s *m) { pthread_mutex_lock(&m->inner); }\nvoid U(struct s *m) { pthread_mutex_unlock(&m->inner); }\nvoid f(void)\n{\n    pthread_mutex_lock(&g);\n    L(obj);\n    U(obj);\n    shared = 1;\n}\n",
    );
    assert_eq!(payload["lock_arguments_unresolved"], 2, "{payload:?}");
    assert_eq!(lockset_at_line(&payload, "shared", 10), json!([]), "{payload:?}");
}
