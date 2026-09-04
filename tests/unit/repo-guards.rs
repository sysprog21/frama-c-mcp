use std::collections::{BTreeMap, BTreeSet};
use serde_json::json;

use frama_c_mcp::mcp::server::*;
use frama_c_mcp::mcp::server::receipt::strip_generated_label;
use frama_c_mcp::mcp::server::checkgaps::{
    ast_diagnostic_gaps, incomplete_code, AST_WARNING_ALLOWLIST, CHECK_SCHEMA,
};
use frama_c_mcp::mcp::server::selfcheck;

/// The check payload's frozen vocabulary, in the three places it is written.
///
/// The incomplete codes are a published contract: agents branch on them,
/// README tabulates them and docs/architecture.md freezes the schema string.
/// They were thirteen string literals with nothing connecting the emitters to
/// the documents, and the set drifted twice before anyone noticed. Deriving
/// both tables from the documents and comparing against the one list in the
/// source is what makes a code added in one place and not the others fail
/// here.
///
/// Parsed rather than counted, because the item that asked for this freeze
/// restated a number and was out of date by the time it was read.
#[test]
fn incomplete_codes_match_their_documentation() {
    // A marker rather than prose. The first version of this split README on a
    // sentence, and editing that sentence to add a link broke the test in the
    // same commit that wrote it.
    const MARKER: &str = "<!-- incomplete-codes -->";

    // Both documents are ours, so the parse insists on the shape instead of
    // sieving whatever looks code-shaped: the code is the first cell of the row
    // and is written in backticks. That drops the header and the separator on
    // their own, and a row written some other way goes missing from the set
    // rather than being quietly accepted, which the comparison below reports.
    fn table_codes(markdown: &str) -> std::collections::BTreeSet<String> {
        markdown
            .split(MARKER)
            .nth(1)
            .expect("marker before the table")
            .lines()
            .skip_while(|line| !line.starts_with('|'))
            .take_while(|line| line.starts_with('|'))
            .filter_map(|row| {
                let cell = row.split('|').nth(1)?.trim();
                cell.strip_prefix('`')?.strip_suffix('`').map(str::to_string)
            })
            .collect()
    }

    let source: std::collections::BTreeSet<String> =
        incomplete_code::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(source.len(), incomplete_code::ALL.len(), "duplicate in ALL");

    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("read README.md");
    assert_eq!(
        table_codes(&readme),
        source,
        "README's code table disagrees with incomplete_code::ALL"
    );

    // The table is in README once, not in two documents. It used to be in a
    // second reference page as well, and keeping three copies in step is the
    // drift this test exists against; one document and one source list is the
    // smallest pair that still catches it.
    //
    // The architecture page carries the compatibility history instead, so a
    // schema bump in the code with no row explaining it fails here too.
    let architecture = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/architecture.md"
    ))
    .expect("read docs/architecture.md");
    assert!(
        architecture.contains(&format!("| `{CHECK_SCHEMA}` |")),
        "docs/architecture.md has no compatibility-history row for {CHECK_SCHEMA}"
    );
}

/// A category leaves the unclassified aggregate only through the allowlist,
/// and a row that says nothing is a mute list rather than an allowlist: this
/// server would be calling a warning benign without saying why.
#[test]
fn ast_warning_allowlist_entries_explain_their_silence() {
    assert!(
        AST_WARNING_ALLOWLIST
            .iter()
            .all(|(category, reason)| !category.trim().is_empty() && !reason.trim().is_empty()),
        "{AST_WARNING_ALLOWLIST:?}"
    );

    // What a row does, proved against a stub rather than against the empty
    // const above, which would pass either way.
    let reload = json!({"ast_reload_health": {"parse_diagnostics": {
        "categories": {
            "kernel:asm:clobber": {"count": 1, "count_unit": "sites"},
            "kernel:annot:unknown": {"count": 3, "count_unit": "sites"},
            "kernel:typing:implicit-function-declaration": {"count": 1, "count_unit": "sites"},
        },
    }}});

    let mut silent = Vec::new();
    ast_diagnostic_gaps(&mut silent, &reload, &[("kernel:annot:unknown", "why")]);
    let aggregate = silent
        .iter()
        .find(|item| item["code"] == incomplete_code::AST_UNCLASSIFIED_WARNING)
        .expect("the unallowlisted category still reports");
    assert_eq!(
        aggregate["categories"],
        json!({"kernel:typing:implicit-function-declaration":
            {"count": 1, "count_unit": "sites"}})
    );

    // And nowhere else: the soundness code beside it is untouched. Found before
    // it is compared, because two absent entries are also equal and would let a
    // renamed category pass this as if it had rendered.
    let mut loud = Vec::new();
    ast_diagnostic_gaps(&mut loud, &reload, &[]);
    let clobber = |items: &[serde_json::Value]| {
        items
            .iter()
            .find(|item| item["code"] == incomplete_code::AST_ASM_CLOBBER)
            .cloned()
            .expect("kernel:asm:clobber must render as its own code")
    };
    assert_eq!(clobber(&silent), clobber(&loud));
}

/// A generated hash label is stripped from a clause before the receipt keeps
/// it, and nothing else is.
///
/// The label is fresh per injection, so leaving it in would make two identical
/// contracts compare unequal, which is the opposite of what putting the text
/// in a receipt is for. A user-written label that merely looks similar must
/// survive: it is part of what the author wrote.
#[test]
fn generated_labels_are_stripped_from_receipt_contracts() {
    // Shape of an injected clause, with and without the trailing user label.
    assert_eq!(strip_generated_label("an_ffed752e_Req0: x >= 0"), "x >= 0");
    assert_eq!(strip_generated_label("re_0123abcd: x >= 0"), "x >= 0");

    // Driven off generate_hash_label rather than a second copy of its prefix
    // table, so teaching it a new kind cannot leave the stripper behind: a
    // prefix it does not know survives into the receipt as part of the clause,
    // and every run's fresh hash then reads as a changed contract.
    for kind in [
        "requires",
        "ensures",
        "assigns",
        "loop_invariant",
        "loop_assigns",
        "loop_variant",
        "assert",
        "no_such_kind",
    ] {
        let label = generate_hash_label(kind);
        assert_eq!(
            strip_generated_label(&format!("{label}_Ens0: \\result >= 0")),
            "\\result >= 0",
            "{kind}"
        );
    }

    // Not generated: keep the whole text. A contract's own named clause is
    // content, and dropping it would report a different contract than the one
    // that was proved.
    assert_eq!(strip_generated_label("positive: x >= 0"), "positive: x >= 0");
    assert_eq!(strip_generated_label("an_short: x >= 0"), "an_short: x >= 0");
    assert_eq!(
        strip_generated_label("zz_ffed752e: x >= 0"),
        "zz_ffed752e: x >= 0"
    );
    assert_eq!(
        strip_generated_label("an_nothexdg: x >= 0"),
        "an_nothexdg: x >= 0"
    );

    // No label at all, and a predicate that happens to contain a colon.
    assert_eq!(strip_generated_label("  x >= 0  "), "x >= 0");
    assert_eq!(
        strip_generated_label("\\forall integer i: 0 <= i"),
        "\\forall integer i: 0 <= i"
    );
}

/// An output path stays inside the working directory.
///
/// Measured before it was restricted: an absolute "/tmp/pwned.c" and a
/// "../../../../tmp/pwned2.c" both wrote with the server's privileges. See
/// resolve_output_path for why this tool is the one that can.
#[test]
fn output_paths_cannot_leave_the_working_directory() {
    let cwd = std::env::current_dir().expect("cwd");

    // The documented workflow. README's example writes out/annotated.c, and a
    // parent that does not exist yet has to resolve, which is why the
    // normalization is lexical before it touches the filesystem.
    let inside = resolve_output_path("out/annotated.c").expect("relative path inside cwd");
    assert_eq!(inside, cwd.join("out/annotated.c"));

    // Interior traversal is fine as long as it lands inside.
    assert_eq!(
        resolve_output_path("sub/./dir/../x.c").expect("interior traversal"),
        cwd.join("sub/x.c")
    );

    // An absolute path inside the tree is the same place, so it is allowed.
    let absolute = cwd.join("abs-inside.c");
    assert_eq!(
        resolve_output_path(absolute.to_str().expect("utf8")).expect("absolute inside"),
        absolute
    );

    // The shapes that used to write anywhere, each paired with the check that
    // is supposed to stop it. Asserting the reason and not just the refusal is
    // what keeps the two checks separately alive: they overlap on most inputs,
    // and a test that only asserts "refused" passes with either one deleted.
    // One more ".." than the cwd is deep, so this climbs past the root wherever
    // the checkout lives; a fixed pile of them would quietly fall back to the
    // lexical check on a deeper path.
    let above_root = "../".repeat(cwd.components().count() + 1) + "tmp/x.c";
    for (escape, reason) in [
        ("/tmp/pwned.c".to_string(), "resolved outside it"),
        ("../shallow-escape.c".to_string(), "resolved outside it"),
        (above_root, "climbs above the filesystem root"),
    ] {
        let error = resolve_output_path(&escape)
            .expect_err(&format!("{escape} should be refused"))
            .to_string();
        assert!(
            error.contains("output must stay inside the working directory"),
            "{escape}: {error}"
        );
        assert!(
            error.contains(reason),
            "{escape} refused for the wrong reason: {error}"
        );
    }
}

/// A symlink inside the tree cannot be used to write outside it.
///
/// The lexical check above cannot see this: the text of
/// "linked/escape.c" never leaves the root. Only resolving the
/// deepest existing ancestor does, which is why the two checks are separate
/// and why this one needs a root it can plant a symlink in.
#[cfg(unix)]
#[test]
fn a_symlink_cannot_carry_an_output_path_out_of_the_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&root).expect("root");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::create_dir_all(root.join("real")).expect("real");
    std::os::unix::fs::symlink(&outside, root.join("linked")).expect("symlink");
    std::os::unix::fs::symlink(root.join("real"), root.join("inner")).expect("inner symlink");

    // Where the symlink lands is the whole question: one inside the root
    // resolves, so this refuses by destination rather than refusing symlinks.
    assert!(resolve_output_path_in(&root, "inner/out.c").is_ok());

    let error = resolve_output_path_in(&root, "linked/escape.c")
        .expect_err("a symlink out of the root must be refused")
        .to_string();
    assert!(
        error.contains("a symlink on the path leaves the working directory"),
        "{error}"
    );
}

/// The E-ACSL wrapper a caller may name is one of the two this server knows.
///
/// Why the rule exists is on require_known_e_acsl_tool. This pins the
/// predicate itself, so a rule change fails here naming the input that broke
/// it; the lifecycle test covers the same rule at the tool boundary.
#[test]
fn only_a_known_e_acsl_wrapper_can_be_named() {
    // Spelled out once, because the loop below is vacuous against whatever the
    // const happens to hold. Dropping a name would otherwise pass everywhere
    // and surface only on an install that ships the other spelling.
    assert_eq!(E_ACSL_WRAPPERS, ["e-acsl-gcc", "e-acsl-gcc.sh"]);

    for known in E_ACSL_WRAPPERS {
        assert!(require_known_e_acsl_tool(known).is_ok(), "{known}");
    }

    // A path is refused rather than resolved. The point is to launch the
    // installed wrapper, so even a plausible-looking one is not accepted.
    for refused in [
        "/usr/bin/curl",
        "./e-acsl-gcc",
        "/opt/frama-c/bin/e-acsl-gcc",
        "../e-acsl-gcc.sh",
        "e-acsl-gcc ",
        "",
    ] {
        let error = require_known_e_acsl_tool(refused)
            .expect_err(&format!("{refused:?} should be refused"))
            .to_string();
        assert!(error.contains("tool must be one of"), "{refused:?}: {error}");
    }
}

/// No em dash survives on a comment line.
///
/// House style, and it is enforced here rather than left to review because a
/// half-swept convention is worse than either whole one: the reader cannot
/// tell whether a dash is a deliberate exception or an oversight. Only U+2014
/// is checked; the U+2500 box-drawing runs that head sections in
/// tests/test-integration.rs are a different character and stay.
///
/// Lines whose first non-space is a comment marker, which is every comment in
/// this tree. A trailing comment after code and a block comment are not
/// checked, and widening to them is not worth what it costs: this tree carries
/// C fixtures in raw strings whose ACSL is full of slash-star, so telling a
/// Rust comment from fixture text needs a lexer rather than a test. CLAUDE.md
/// states the narrower rule.
///
/// The backticks are deliberately NOT enforced here. Measured on 2026-08-12:
/// 661 backticked comment lines across 22 files, 16 percent of every comment
/// in the tree, of which 27 carry a pair that spans two lines, which is the
/// shape a blanket rewrite mangles. That is a standing rule applied on touch,
/// not a sweep.
#[test]
fn no_em_dash_in_a_rust_comment() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for dir in ["src", "tests"] {
        source_files(&root.join(dir), "rs", &mut sources);
    }

    let mut offenders = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        for (number, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") && line.contains('\u{2014}') {
                offenders.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    assert!(offenders.is_empty(), "em dash in a comment: {offenders:?}");
}

/// No function in src/ runs past the ceiling CLAUDE.md sets.
///
/// The length rule was prose alone until this test, and prose went stale: the
/// document claimed nothing exceeded 250 while check_payload had reached 289.
/// A rule the tree is measured against is a rule; a rule stated in a file no
/// checkout even has is a wish.
///
/// 300 rather than 250, and the number moved because the measurement said so.
/// The five functions over 200 are all sequential payload assembly whose steps
/// feed the next one, which is the shape CLAUDE.md already says not to split,
/// and check_payload at 289 is that shape and not a function doing several
/// things. Splitting it would buy helpers with one caller apiece and three
/// values threaded between them.
///
/// The measurement is a brace at the function's own indentation, not a parse.
/// It is inexact and cannot be otherwise, because no gate runs cargo fmt here
/// and it rewrites most of src when asked, so a closing brace sits where the
/// author left it rather than where a formatter would put it.
///
/// It is built to under-report rather than to cry wolf, and each way it can go
/// wrong lands on that side. A declaration with no body, a form of pub this
/// does not strip, and a brace this cannot find all skip the function instead
/// of inventing a length for it. So does an overshoot: when the search runs
/// past a close it failed to recognize, it meets the next declaration at the
/// same indentation and gives up, rather than reporting this function plus
/// whatever followed it. That case used to report the sum, which is why
/// closes_at exists as well, to keep the overshoot rare in the first place.
///
/// One hole is left, and it stays open because closing it needs the lexer this
/// deliberately is not. A fn declaration written inside a block comment or a
/// raw string reads here as a real one, and could then be measured against a
/// brace that is not its own. Measured on this tree: src/ holds one block
/// comment and no raw string carrying Rust, so nothing reaches it today, and
/// the C fixtures that would are under tests/, which this does not read.
///
/// So the ceiling is a backstop for the reviewer rather than a substitute: a
/// function doing two unrelated things at 180 lines is still wrong and this
/// test will never say so.
#[test]
fn no_function_in_src_runs_past_the_length_ceiling() {
    const CEILING: usize = 300;

    let mut files = Vec::new();
    source_files(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        "rs",
        &mut files,
    );

    let mut offenders = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let lines: Vec<&str> = text.lines().collect();
        for (start, line) in lines.iter().enumerate() {
            let Some(name) = function_name(line) else { continue };
            let indent = &line[..line.len() - line.trim_start().len()];
            let close = format!("{indent}}}");
            let Some(end) =
                (start + 1..lines.len()).find(|&i| closes_at(lines[i], &close)) else {
                continue;
            };

            // A sibling declaration at this indentation before the close means
            // the search ran past the real one, so the length would be this
            // function plus whatever followed it. Skip instead of reporting a
            // number that was never measured on one function.
            if (start + 1..end).any(|i| {
                function_name(lines[i]).is_some()
                    && lines[i].len() - lines[i].trim_start().len() == indent.len()
            }) {
                continue;
            }
            let length = end - start + 1;
            if length > CEILING {
                offenders.push(format!(
                    "{}:{} {name} is {length} lines",
                    path.display(),
                    start + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "over the {CEILING} line ceiling: {offenders:?}"
    );
}

/// The name of the function a line declares, if it declares one.
///
/// Deliberately blind to a declaration inside a string or a comment: those do
/// not reach an opening brace at their own indentation, so they find no closing
/// line and are skipped by the caller rather than needing to be excluded here.
/// Three levels of control flow, and this is what counts them.
///
/// CLAUDE.md has stated the rule for a long time and said in the same breath
/// that it could not be checked, because telling a deep branch from a deep
/// JSON literal needs a parser rather than a column count. That is true of a
/// column count and false of this: a level is opened only by a line whose
/// first token is if, for, while, match or loop and which ends in an opening
/// brace, so the payload assembly the rule deliberately exempts is invisible
/// to it. Measured when it was written, 508 lines in src sit at indentation
/// depth six or more and none of them are branches.
///
/// Depth is popped by indentation before it is pushed, which is what makes
/// "} else if cond {" a continuation rather than a fourth level: it closes the
/// block it is chained to before opening its own.
///
/// It under-reports, on purpose, in the two cases worth naming. A construct
/// written across several lines, with the brace not on the first of them, is
/// not counted, and neither is a branch inside a closure passed to something.
/// Both would need the parser the old note was talking about. What is left
/// still caught seventeen functions the day it was added.
///
/// It reads only line comments, so it would over-report in one direction the
/// paragraph above does not cover: a branch-shaped line ending in a brace,
/// written inside a block comment or a multi-line string literal, counts as a
/// real level and could fail a compliant function. Telling those apart needs
/// the same parser, and src carries no instance of either, its two "/*" both
/// sitting inside line comments and its files holding no raw strings. Measured
/// rather than assumed, and worth re-measuring before that changes.
#[test]
fn no_function_in_src_nests_control_flow_past_three() {
    const LEVELS: usize = 3;

    let mut files = Vec::new();
    source_files(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        "rs",
        &mut files,
    );

    let mut offenders = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let mut function = "";
        let mut open: Vec<usize> = Vec::new();
        let mut worst = 0usize;
        let mut worst_line = 0usize;
        let mut report = |function: &str, worst: usize, worst_line: usize| {
            if worst > LEVELS && !function.is_empty() {
                offenders.push(format!(
                    "{}:{worst_line} {function} nests {worst} deep",
                    path.display()
                ));
            }
        };
        for (number, line) in text.lines().enumerate() {
            if let Some(name) = function_name(line) {
                report(function, worst, worst_line);
                function = name;
                open.clear();
                worst = 0;
                worst_line = 0;
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            let indent = line.len() - trimmed.len();
            while open.last().is_some_and(|&outer| indent <= outer) {
                open.pop();
            }
            if !opens_a_branch(trimmed) || !line.trim_end().ends_with('{') {
                continue;
            }
            open.push(indent);
            if open.len() > worst {
                worst = open.len();
                worst_line = number + 1;
            }
        }
        report(function, worst, worst_line);
    }

    assert!(
        offenders.is_empty(),
        "control flow nested past {LEVELS} levels:\n{}\n\nA fourth live \
         branch inside three others is a function doing too much. Extract the \
         inner work, or invert a condition to return early. Raising LEVELS is \
         not the fix: the number is the rule.",
        offenders.join("\n")
    );
}

/// No macro in src aborts the process.
///
/// This server holds a Frama-C child, a socket, and a session's conclusions; a
/// panic takes all three down and answers the caller with a closed pipe rather
/// than an error they can act on. Every failure here already has a channel,
/// McpError upstream and FramaCError downstream, so reaching for a panicking
/// macro is a decision rather than an accident, and the decision is no.
///
/// Zero rather than a ceiling, deliberately. A ceiling is a measurement, and a
/// guard carrying one is a number the next person edits to get their build
/// green. Zero is a policy, so there is nothing to bump: a new panic has to
/// argue with this comment.
///
/// unwrap and expect are not counted here. They panic too, and the eight in
/// src today are all either a literal regex behind a OnceLock or a stated
/// invariant, which is a judgement per site rather than a number, so it stays
/// a review question. Line comments are skipped; a macro named inside a block
/// comment or a string literal would be counted, and src contains no instance
/// of either.
#[test]
fn no_macro_in_src_aborts_the_process() {
    const FORBIDDEN: &[&str] = &["panic!", "todo!", "unimplemented!", "unreachable!"];

    let mut files = Vec::new();
    source_files(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        "rs",
        &mut files,
    );

    let mut offenders = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for macro_name in FORBIDDEN {
                if line.contains(macro_name) {
                    offenders.push(format!("{}:{} {macro_name}", path.display(), number + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these abort the process instead of answering the caller: {offenders:?}"
    );
}

/// Whether a line's first token opens a control-flow block.
///
/// The leading brace of "} else if" and "} while" is skipped, so a chained
/// branch is recognised as the construct it is. "else {" alone opens no new
/// level: it is the other half of an if that was already counted.
fn opens_a_branch(trimmed: &str) -> bool {
    let rest = trimmed.strip_prefix('}').unwrap_or(trimmed).trim_start();
    let rest = rest.strip_prefix("else ").unwrap_or(rest);

    // The trailing space is what keeps "if_" style identifiers out: a keyword
    // is only a keyword when something follows it, and "loop {" satisfies that
    // as much as "loop while_ready" does.
    ["if ", "for ", "while ", "match ", "loop "]
        .iter()
        .any(|keyword| rest.starts_with(keyword))
}

fn function_name(line: &str) -> Option<&str> {
    let rest = line.trim_start();
    let mut rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    for prefix in ["default ", "const ", "async ", "unsafe ", "extern \"C\" "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')?;
    Some(&rest[..end])
}

/// Whether a line is the closing brace of a block opened at this indentation.
///
/// Not an equality test. A brace carrying trailing whitespace or a trailing
/// comment is still that brace, and treating it as anything else sends the
/// search on to the next sibling's close, which inflates the length of a
/// function that is not over anything. Measured on this tree: giving
/// parse_proved_goals a commented close took it from 17 lines to 26.
fn closes_at(line: &str, close: &str) -> bool {
    let Some(rest) = line.strip_prefix(close) else { return false };
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with("//")
}

/// Walk every file whose extension is the one asked for, under a directory.
///
/// Recursive, and every caller wants it that way: a scan that reads one
/// directory level answers about the tree it was pointed at rather than the
/// tree, and goes quiet instead of failing when a file moves down one.
///
/// It panics on a directory it cannot read, where it used to return what it
/// had. Every caller is a guard, and a guard that reports on the part of the
/// tree it happened to reach is the failure mode these tests exist against;
/// the non-empty assertions at the call sites do not catch it, because one
/// readable directory at the top satisfies them.
///
/// Each directory is walked in sorted order, so the appended run is ordered
/// too. read_dir order is arbitrary, and every caller is a guard whose report
/// a human reads, so the order is part of the contract rather than something
/// each call site remembers to restore afterwards.
fn source_files(dir: &std::path::Path, extension: &str, out: &mut Vec<std::path::PathBuf>) {
    let mut entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .map(|entry| {
            entry.unwrap_or_else(|err| panic!("read an entry of {}: {err}", dir.display())).path()
        })
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            source_files(&path, extension, out);
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
}

/// The retry counts a goal as flipped only when the first pass timed out on
/// that same goal and the second pass proved it.
///
/// Written by hand because the flip cannot be staged against a real prover: it
/// needs a goal that proves in more than the first timeout and less than double
/// it, which is a fact about the machine. The live test drives the plumbing
/// with a goal no prover discharges, so it only ever reaches the empty case.
#[test]
fn a_flip_is_a_goal_that_timed_out_and_then_proved() {
    let timed_out = BTreeSet::from(["slow_assert".to_string(), "hard_assert".to_string()]);
    let retried = vec![
        json!({"wpo": "slow_assert", "name": "Assertion", "property": "#p1", "status": "VALID"}),
        json!({"wpo": "hard_assert", "name": "Assertion", "property": "#p2", "status": "TIMEOUT"}),
        // Valid, but it never timed out, so the retry did not turn it around.
        json!({"wpo": "easy_assert", "name": "Assertion", "property": "#p3", "status": "VALID"}),
    ];

    let report = timeout_retry_report(&timed_out, &retried, 4, 8);

    assert_eq!(report["attempted"], true);
    assert_eq!(report["timeout_seconds"]["first_pass"], 4);
    assert_eq!(report["timeout_seconds"]["retry"], 8);
    assert_eq!(report["timed_out_first_pass"], 2);
    assert_eq!(report["still_unproved"], 1);
    let flipped = report["flipped"].as_array().expect("flipped is an array");
    assert_eq!(flipped.len(), 1, "{report:?}");
    assert_eq!(flipped[0]["wpo_id"], "slow_assert");
    assert_eq!(flipped[0]["property"], "#p1");
}

/// Every command CI runs, as one text: the workflows plus the scripts in .ci/.
///
/// The guards below read the commands CI runs, and those commands live in two
/// places now. The long shell blocks moved out of ci.yml into .ci/ so they
/// could be formatted, shellcheck-able and runnable by hand, which left the
/// step that runs them saying nothing but a path. A parser reading only the
/// YAML would then see a release job that stages no assets and a lane that
/// pins no test by name, and would report all clear having compared nothing.
///
/// The same lesson as ci_gates learned one directory over, when the artifact
/// scan lived in a second workflow file: read the directory, so a script
/// appearing in it is a non-event rather than a hole.
fn ci_command_text(root: &std::path::Path) -> String {
    let mut text = String::new();
    for dir in [".github/workflows", ".ci"] {
        let dir = root.join(dir);
        for path in sorted_files(&dir, &["yml", "yaml", "sh"]) {
            text.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            text.push('\n');
        }
    }

    assert!(
        text.contains("cargo test"),
        "no workflow or .ci script was read, so every guard reading this would \
         pass on an empty requirement set"
    );
    text
}

/// Every file in a directory with one of these extensions, sorted.
///
/// read_dir order is arbitrary and a guard that reports what it found is read
/// by a human, so the sort is part of the contract rather than a nicety.
fn sorted_files(dir: &std::path::Path, exts: &[&str]) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| exts.iter().any(|want| ext == *want))
        })
        .collect();
    paths.sort();
    paths
}

/// Every Frama-C request this server calls is named in a self_check table.
///
/// self_check's tables were a hand-copied mirror of the call sites, and the
/// copy had drifted: measured on 2026-08-29, 79 distinct request names were
/// called outside selfcheck.rs and 11 appeared in no table, so self_check could
/// report a healthy install while the request behind a tool was missing.
///
/// Naming a request does not mean probing it. Five of those 11 must not be
/// probed, and UNPROBED_REQUESTS records each with its reason, which is the
/// point: "deliberately not probed" and "forgotten" used to look identical from
/// here.
#[test]
fn every_frama_c_request_is_named_in_a_probe_table() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    source_files(&root.join("src"), "rs", &mut sources);
    assert!(!sources.is_empty(), "found no sources to scan");

    let known: std::collections::HashSet<&str> =
        frama_c_mcp::mcp::server::selfcheck::known_request_names()
            .into_iter()
            .collect();
    assert!(known.len() > 50, "the probe tables look empty: {}", known.len());

    let mut missing: Vec<String> = Vec::new();
    for path in &sources {
        // selfcheck.rs is where the tables live, so its own literals are the
        // answer rather than the question.
        if path.ends_with("selfcheck.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for name in request_names_in(&text) {
            if !known.contains(name.as_str()) {
                missing.push(format!("{}: {name}", path.display()));
            }
        }
    }
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "these requests are called but named in no self_check table, so self_check \
         cannot tell a missing one from a working one: {missing:?}"
    );

    // And the other direction. UNPROBED_REQUESTS claims each of its entries is
    // called and deliberately not probed; an entry whose call site has gone
    // makes that claim about nothing, and the table starts agreeing with itself
    // instead of with the code. That is the fault this whole guard exists
    // against, and it is free to close here.
    let called: std::collections::HashSet<String> = sources
        .iter()
        .filter(|path| !path.ends_with("selfcheck.rs"))
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|text| request_names_in(&text))
        .collect();
    let stale: Vec<&str> = frama_c_mcp::mcp::server::selfcheck::UNPROBED_REQUESTS
        .iter()
        .map(|&(request, _)| request)
        .filter(|request| !called.contains(*request))
        .collect();
    assert!(
        stale.is_empty(),
        "these are listed as deliberately unprobed but nothing calls them any more; \
         drop them from UNPROBED_REQUESTS: {stale:?}"
    );
}

/// Frama-C request-name literals in a Rust source.
///
/// A name is "kernel." or "plugins." followed by dotted segments, inside double
/// quotes. Matched by hand rather than with a regex because the shape is fixed
/// and this file has no other use for the dependency.
fn request_names_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (index, _) in text.match_indices('"') {
        let rest = &text[index + 1..];
        let Some(end) = rest.find('"') else { continue };
        let candidate = &rest[..end];
        if !(candidate.starts_with("kernel.") || candidate.starts_with("plugins.")) {
            continue;
        }
        if candidate.contains(' ') || !candidate.contains('.') {
            continue;
        }
        if candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            found.push(candidate.to_string());
        }
    }
    found
}

/// Every workflow file, sorted.
///
/// The directory rather than ci.yml by name, which is the lesson
/// ci_command_text
/// above records: the artifact scan once lived in a second workflow file and a
/// guard reading one file by name reported all clear having compared nothing.
fn workflow_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let dir = root.join(".github/workflows");
    let paths = sorted_files(&dir, &["yml", "yaml"]);
    assert!(!paths.is_empty(), "{}: no workflow files", dir.display());
    paths
}

/// Every job in every workflow, with the file each came from.
///
/// The two guards that ask "which job does X" both want this, and spelling it
/// twice was two shapes for one question in a single commit.
fn all_workflow_jobs(root: &std::path::Path) -> Vec<(std::path::PathBuf, String, String)> {
    workflow_files(root)
        .into_iter()
        .flat_map(|path| {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            workflow_jobs(&text).into_iter().map(move |(name, body)| (path.clone(), name, body))
        })
        .collect()
}

/// The entries of a YAML flow list, "[a, b]", unquoted.
///
/// Two guards parse one of these and they had drifted before they were two
/// days old: the matrix parse strips quotes and the needs parse did not, so a
/// needs written ["build"] would have compared a quoted name against a bare one
/// and reported every job as ungating.
fn flow_list(text: &str) -> Vec<String> {
    let Some(inner) = text.split_once('[').and_then(|(_, rest)| rest.split_once(']')) else {
        return Vec::new();
    };
    inner
        .0
        .split(',')
        .map(|entry| entry.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// A workflow's jobs, as name and body.
///
/// One definition, for the reason step_command below records: three copies of
/// one parsing rule was three chances to fix it in two places. This file had
/// four copies of this one by 2026-08-28, and every caller now goes through
/// this one. The copies differed in which trap they fell into: two read a
/// comment line as a job, so "  # release:" named one, and two tested the raw
/// line for a closing colon, so a header carrying a trailing comment stopped
/// being a header and its job merged into the one above it.
///
/// Only inside the jobs: mapping. Indentation alone cannot say what a job is:
/// the on: trigger keys push: and pull_request: sit at the same two spaces, so
/// a scan without that check collected them as jobs and gave the first one the
/// whole top-of-file comment block as its body. Harmless while that comment
/// says nothing a caller greps for, and a trap the day it does.
fn workflow_jobs(text: &str) -> Vec<(String, String)> {
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        // Before the column test, not after: a comment at column zero is not a
        // key, and treating it as one ended the scan and dropped every job
        // below it. ci.yml has no such comment today, which is the only reason
        // nothing failed.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_jobs = line.trim_end() == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }

        // A trailing comment does not stop a line from naming a job, and YAML
        // allows one. Testing the raw line for a closing colon made " build: #
        // note" fail the test, which merged that job into its predecessor and
        // let a caller searching one body read two jobs as one. The spacing in
        // that example is the point and is not reflowed: two spaces of YAML
        // indent, two before the comment marker. Found by a control that added
        // such a comment; the guard it broke was failing green.
        let header = match line.split_once(" #") {
            Some((before, _)) => before,
            None => line,
        }
        .trim_end();
        let is_job_header =
            line.starts_with("  ") && !line.starts_with("   ") && header.ends_with(':');
        if is_job_header {
            jobs.push((header.trim().trim_end_matches(':').to_string(), String::new()));
        } else if let Some((_, body)) = jobs.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    jobs
}

/// workflow_jobs reads jobs, and reads nothing else as one.
///
/// The property lived as a stray assertion inside the cppo guard, which is
/// where the parser used to be inlined. It belongs to the parser: the on:
/// trigger keys push: and pull_request: sit at the same two spaces a job name
/// does, so a scan that does not track the jobs: mapping collects them, and a
/// caller then greps a body that is really the top-of-file comment block.
#[test]
fn workflow_jobs_reads_jobs_and_not_trigger_keys() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let jobs = all_workflow_jobs(root);

    assert!(!jobs.is_empty(), "no workflow job was read, so this guard compared nothing");
    let stray: Vec<&String> = jobs
        .iter()
        .map(|(_, name, _)| name)
        .filter(|name| ["push", "pull_request", "schedule", "workflow_dispatch"].contains(&name.as_str()))
        .collect();
    assert!(stray.is_empty(), "the job scan collected an on: trigger key as a job: {stray:?}");
}

/// The command a workflow step runs, or the line unchanged when it runs none.
///
/// A step is either "run: <command>" on one line or a command inside a
/// "run: |" block, and ci.yml uses both. Three tests parse steps, and each one
/// learned that separately and the expensive way: ci_named_tests_still_exist
/// matched only the block form and so skipped a step pinning a test that had
/// been renamed away, ci_gates dropped the one-line pure-Rust step out of the
/// gate set entirely, and ci_runs_every_test_target reported test-integration
/// as run by nobody the moment that step no longer needed a block. Three copies
/// of one rule is three chances to fix it in two places, and a drift between
/// them puts the parser gap back without any of the three failing.
fn step_command(line: &str) -> &str {
    let command = line.trim().trim_start_matches("- ");
    command.strip_prefix("run:").unwrap_or(command).trim()
}

/// Every test CI names by hand still exists, and is really a test.
///
/// "cargo test --test X some_name" exits 0 with "0 passed" when the filter
/// matches nothing, so a renamed test turns its CI step into one that passes by
/// running nothing. Measured: folding run_eva renamed a test the workflow
/// pinned, and four reviewers plus a grep of src, tests and docs all missed it,
/// because the surviving reference lives in .github and nothing reads that.
///
/// Checked against the target the step actually names, and only against a
/// function carrying a test attribute. A first version searched every file
/// under tests/ for the string "fn <name>(", which codex pointed out passes on
/// a comment, a helper, or a test living in a different target than the one
/// being filtered: a guard against passing by not running, that could itself
/// pass without running anything. The parse is asserted to have found steps for
/// that same reason: an empty result must not read as all clear.
#[test]
fn ci_named_tests_still_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow = ci_command_text(root);

    /// Every .rs file under a directory, read whole.
    fn rust_sources(dir: &std::path::Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
        let mut sources = Vec::new();
        for path in entries.flatten().map(|entry| entry.path()) {
            if path.is_dir() {
                sources.extend(rust_sources(&path));
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                sources.push(std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
        sources
    }

    /// A function by this name, declared directly under a test attribute.
    fn declares_test(source: &str, name: &str) -> bool {
        let signature = format!("fn {name}(");
        let lines: Vec<&str> = source.lines().map(str::trim_start).collect();
        lines.iter().enumerate().any(|(index, line)| {
            let line = line.strip_prefix("pub ").unwrap_or(line);
            let line = line.strip_prefix("async ").unwrap_or(line);
            if !line.starts_with(&signature) {
                return false;
            }

            // Back over the attribute and doc block above, stopping at the
            // first line that is not part of it. Bounding the scan by a line
            // count instead would be a guess about how documented a test gets.
            lines[..index]
                .iter()
                .rev()
                .take_while(|above| {
                    above.starts_with('#') || above.starts_with("//") || above.is_empty()
                })
                .any(|above| above.starts_with("#[test]") || above.starts_with("#[tokio::test"))
        })
    }

    // The target each step filters, and the name it pins.
    let pinned: Vec<(&str, &str)> = workflow
        .lines()
        .filter_map(|line| {
            let mut words =
                step_command(line).strip_prefix("cargo test ")?.split_whitespace();

            // --test need not come first. ci.yml already writes "cargo test
            // --test X --release", and the mirror ordering "cargo test
            // --release --test X" parsed as nothing, so a step pinning a test
            // that had been renamed away passed this guard by being skipped by
            // it.
            if !words.any(|word| word == "--test") {
                return None;
            }
            let (target, filter) = (words.next()?, words.next());

            // No filter, or an option where one would be: the step runs the
            // whole target and has no name to go stale.
            Some((target, filter.filter(|word| !word.starts_with('-'))?))
        })
        .collect();
    assert!(
        !pinned.is_empty(),
        "no ci.yml step parsed as a test pinned by name, so this test checked \
         nothing: the workflow moved and the parser did not"
    );

    let mut missing = Vec::new();
    for (target, filter) in pinned {
        // A target is its own root file plus, when it has one, the directory of
        // modules beside it. `unit` keeps its parts under tests/unit/, and
        // reading only tests/unit.rs would find a list of `mod` lines and
        // report every name CI pins there as missing.
        let mut sources = vec![
            std::fs::read_to_string(root.join("tests").join(format!("{target}.rs")))
                .unwrap_or_default(),
        ];
        sources.extend(rust_sources(&root.join("tests").join(target)));
        if !sources.iter().any(|source| declares_test(source, filter)) {
            missing.push(format!("{target} {filter}"));
        }
    }

    assert!(
        missing.is_empty(),
        "ci.yml names tests that do not exist in the target it filters, so those \
         steps run nothing: {missing:?}"
    );
}

/// Every pub item in src/ is named somewhere else in src/ or tests/.
///
/// This exists because dead_code cannot see these any more. Publishing the
/// internals so the unit tests could move out of the crate made every one of
/// them a pub item in a pub mod, and the lint does not fire on those: it
/// assumes an external consumer. So the published items lost the check that a
/// helper whose last caller went away gets reported, while the ones that
/// stayed private kept it, and nothing anywhere said which half you were in.
///
/// It read pub fn only until 2026-08-30, which was 313 of the 482 published
/// items. The eight keywords below take it to 453, closing a gap of 140 pub
/// structs, consts, enums and types that were in neither half, covered by no
/// lint and by no guard. A count is the wrong instrument for that gap, because
/// it moves with every commit and a gate pinning it becomes a number people
/// bump. Naming the orphan is the instrument, and it costs one keyword list.
///
/// The remaining 29 are pub mod, deliberately out. A module is named by every
/// path that reaches through it and by the #[path] attribute above it, so it
/// can never be orphaned by this scan and would only pad the list.
///
/// Name-based and therefore approximate in one direction only: a name that
/// appears in a comment or a string counts as a use, so this under-reports
/// rather than crying wolf. That is the right way round for a guard nobody
/// asked for, and it still catches the case that matters, which is an item no
/// longer written down anywhere but its own definition.
#[test]
fn every_published_item_has_a_user() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut sources = Vec::new();
    source_files(&root.join("src"), "rs", &mut sources);
    let src_count = sources.len();
    source_files(&root.join("tests"), "rs", &mut sources);
    assert!(src_count > 0 && sources.len() > src_count, "found no sources to scan");

    // A file that cannot be read is a failure and not a file to skip: dropping
    // one under src/ loses its definitions, and dropping one under tests/ turns
    // the uses written there into orphan reports on items that are fine.
    let texts: Vec<(std::path::PathBuf, String)> = sources
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            (path, text)
        })
        .collect();

    const PUBLISHED: &[&str] =
        &["fn", "struct", "enum", "type", "const", "static", "trait", "union"];

    // Definition sites, and every other mention of the name anywhere.
    let mut defined: Vec<(&str, String, String)> = Vec::new();
    for (path, text) in &texts {
        if !path.starts_with(root.join("src")) {
            continue;
        }
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub ") else {
                continue;
            };

            // "pub async fn" and "pub unsafe fn" carry the keyword a token
            // further in.
            let rest = rest
                .strip_prefix("async ")
                .or_else(|| rest.strip_prefix("unsafe "))
                .unwrap_or(rest);
            let Some((keyword, rest)) = rest.split_once(' ') else {
                continue;
            };
            let Some(keyword) = PUBLISHED.iter().copied().find(|known| *known == keyword) else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
                .collect();

            // "pub const fn" would read as a const named fn, and "pub static
            // mut" as a static named mut. Neither form is in the tree, and this
            // says so precisely if one arrives, rather than recording an item
            // called "fn" and sending the reader hunting. A leading modifier
            // that is not itself a keyword below, "pub extern \"C\" fn", is
            // dropped by the filter that follows instead.
            assert!(
                !PUBLISHED.contains(&name.as_str()) && name != "mut",
                "{}: \"pub {keyword} {name}\" is a modifier form this scan does not read",
                path.display()
            );
            if !name.is_empty() {
                defined.push((keyword, name, format!("{}", path.display())));
            }
        }
    }
    assert!(defined.len() > 400, "parsed {} pub items, the scan broke", defined.len());

    // Split once and stop at the first hit. Counting every use of every name
    // re-split the whole corpus per item, which was most of this suite's
    // runtime, and the answer only ever asks whether one exists.
    let corpus: Vec<&str> = texts.iter().flat_map(|(_, text)| text.lines()).collect();

    let mut orphans = Vec::new();
    for (keyword, name, where_defined) in &defined {
        let definition = format!("{keyword} {name}");
        let used = corpus
            .iter()
            .any(|line| line.contains(name.as_str()) && !line.contains(definition.as_str()));
        if !used {
            orphans.push(format!("pub {keyword} {name} ({where_defined})"));
        }
    }
    orphans.sort();
    orphans.dedup();

    assert!(
        orphans.is_empty(),
        "these pub items are named nowhere but their own definition, and dead_code \
         can no longer report them: {orphans:?}"
    );
}

/// CI installs a Frama-C the server will call supported.
///
/// The pair drifted once already and nothing noticed: capabilities told every
/// agent the server was "Validated against Frama-C 31.0 (Gallium)" for the six
/// days after CI, CLAUDE.md and README moved to 33.0. A hardcoded sentence has
/// no way to be wrong loudly, so the sentence is derived and this checks the
/// number it derives from.
///
/// The comparison is the floor, not equality. MIN_FRAMA_C_VERSION is the oldest
/// version accepted rather than the only one, so requiring the matrix to equal
/// it would fail the day CI moves to a Frama-C the code itself calls supported,
/// which is a guard failing on the case it exists to allow.
///
/// The matrix parse is asserted non-empty for the other direction: a workflow
/// this stops recognising would otherwise report all clear having compared
/// nothing.
#[test]
fn ci_frama_c_version_matches_supported_minimum() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow =
        std::fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci.yml");

    let matrix: Vec<String> = workflow
        .lines()
        .filter(|line| line.trim().starts_with("frama-c-version:"))
        .flat_map(flow_list)
        .collect();

    assert!(
        !matrix.is_empty(),
        "no frama-c-version matrix found in ci.yml, so this guard compared nothing"
    );
    for version in &matrix {
        let parsed = selfcheck::frama_c_version(version)
            .unwrap_or_else(|| panic!("no version number in the ci.yml matrix entry {version:?}"));
        assert!(
            parsed >= selfcheck::MIN_FRAMA_C_VERSION,
            "ci.yml installs Frama-C {version} but the supported floor is {}, so \
             self_check would call a version CI tests unsupported",
            selfcheck::min_frama_c_version()
        );
    }

    // The three shell gates pin proved-goal counts, so they match an exact
    // version where the constant is only a floor. That difference is fine until
    // they disagree: a matrix the scripts refuse means CI installs a Frama-C
    // its own gates will not run against, and the floor above cannot see it
    // because the floor is satisfied.
    for script in [
        "scripts/check-tutorial-corpus.sh",
        "scripts/check-abs-int-fixtures.sh",
        "scripts/check-wp-model-fixtures.sh",

        // Refuses an unsupported matrix value before ten minutes of opam
        // install, and so pins the same version the gates above do.
        ".ci/check-frama-c-matrix-version.sh",
    ] {
        let text = std::fs::read_to_string(root.join(script)).expect(script);

        // Whole version strings on both sides, not majors. Comparing majors let
        // a matrix of 33.1 pass against a gate whose case arm is 33.0, which is
        // verbatim the mismatch this half exists to catch.
        let accepted: Vec<String> = text
            .lines()
            .find(|line| line.trim_end().ends_with(") ;;"))
            .map(|line| {
                line.trim()
                    .trim_end_matches(") ;;")
                    .split('|')
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !accepted.is_empty(),
            "no version case found in {script}, so this guard compared nothing"
        );
        for version in &matrix {
            assert!(
                accepted.contains(version),
                "ci.yml installs Frama-C {version}.x and {script} accepts {accepted:?}, \
                 so the full lane would install a Frama-C its own gate refuses"
            );
        }
    }
}

/// CI compiles the plug-in against the oldest Frama-C the tree claims to
/// support.
///
/// The floor is a claim about a build, and for one commit it was a claim
/// nothing made: the opam constraint and README moved to 32.1 while the only
/// lane installing Frama-C stayed on 33.0, so the "#if FRAMAC_MAJOR" arms for
/// the older kernel were never compiled by anything. They did not compile, and
/// the tree said 32.1 was supported for as long as nobody tried.
///
/// Matched as "frama-c.<floor>" inside an opam install command rather than
/// anywhere in the file, so a version named only in a comment or a cache key
/// does not satisfy it.
#[test]
fn ci_builds_the_plugin_on_the_supported_floor() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // ci_command_text rather than the raw YAML: CI moves long shell blocks into
    // .ci/, and a reader of the YAML alone sees a step naming nothing but a
    // path. Four other guards in this file already go through it.
    let workflow = ci_command_text(root);

    let floor = format!("frama-c.{}", selfcheck::min_frama_c_version());
    let installs: Vec<&str> = workflow
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("opam install") && line.contains("frama-c."))
        .collect();

    assert!(
        !installs.is_empty(),
        "no opam install of frama-c found in ci.yml, so this guard compared nothing"
    );
    assert!(
        installs.iter().any(|line| line.contains(&floor)),
        "the supported floor is {}, but no CI step installs {floor}; the older \
         arm of every version conditional in ast-utils/src would go uncompiled. \
         Found: {installs:?}",
        selfcheck::min_frama_c_version()
    );

    // The preprocessor that reads those conditionals is a build tool nothing
    // else pulls in. A lane that builds the plug-in without cppo fails at the
    // first module carrying a directive, which reads as a broken plug-in rather
    // than a missing package.
    //
    // Whether, not where. cppo is deliberately installed by its own step in the
    // lane that caches its switch, because folding it into the cached install
    // would mean a new cache key and a new cache key discards a whole Frama-C
    // build. Requiring it on the same line as frama-c would forbid that. Per
    // job, not per file. cppo is a build tool nothing else pulls in, so every
    // lane that builds the plug-in needs its own install of it. Two weaker
    // shapes both pass while a lane goes without: searching the whole file for
    // "opam install" and for "cppo" separately is satisfied by a cache key, a
    // step name, or a comment, and even requiring both on one line is satisfied
    // by whichever other lane still installs it.
    let jobs = all_workflow_jobs(root);
    let plugin_builders: Vec<&(std::path::PathBuf, String, String)> =
        jobs.iter().filter(|(_, _, body)| body.contains("dune build")).collect();
    assert!(
        !plugin_builders.is_empty(),
        "no ci.yml job runs dune build, so this guard compared nothing"
    );
    for (_, name, body) in plugin_builders {
        assert!(
            body.lines()
                .map(str::trim)
                .any(|line| line.contains("opam install") && line.contains("cppo")),
            "ci.yml job {name} builds the plug-in but installs no cppo, which \
             ast-utils/src/dune runs over the modules carrying version \
             conditionals"
        );
    }

    // The install step is skipped on a cache hit, so the key decides what the
    // lane actually restores. Asserted as presence of the floor's own key
    // rather than by filtering keys on a hardcoded major and checking the rest:
    // that shape stops matching anything the day the floor moves, and then
    // fails "compared nothing" on exactly the change it exists to allow.
    let floor_key = format!("frama-c-{}", selfcheck::min_frama_c_version());
    assert!(
        workflow
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("key:") && line.contains(&floor_key)),
        "no opam cache key names {floor_key}, so a cache hit would restore a \
         switch holding a different Frama-C than the lane installs"
    );
}

/// Every integration test target is run by CI.
///
/// A target nothing runs is worse than no target: it reads as coverage, it
/// keeps being edited, and it says nothing. Measured on 2026-08-13, three of
/// five were in that state, 51 tests between them, all three touched the day
/// before. Two of the three were not in the gate list in CLAUDE.md either, so
/// following the documentation did not run them and neither did the machine.
///
/// Pairs with ci_named_tests_still_exist, which catches the other direction: a
/// step naming a test that has gone. This one catches a target no step names.
#[test]
fn ci_runs_every_test_target() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow = ci_command_text(root);

    // Word by word off the command lines, not a substring of the file: a
    // comment mentioning the target would satisfy a contains, and so would a
    // longer target name that starts with this one. "any" leaves the iterator
    // just past the flag, so the next word is the target the step names.
    //
    // Both spellings of a step, as ci_named_tests_still_exist and ci_gates
    // already read them: a command inside a "run: |" block, and the one-line
    // "run: <command>" form. This read only the block form, so when the steps
    // needing nothing but a test lost their surrounding block, it reported
    // test-integration as run by nobody. Only that one, because every other
    // target is still named inside some block, and that is the shape of the
    // near miss worth recording: a parser gap shows up on one target rather
    // than obviously on all of them. It fails in the safe direction, reading a
    // step it cannot see as a target CI skips, but it was refusing the shorter
    // spelling of a step that does run.
    let run_by_ci = |target: &str| {
        workflow.lines().any(|line| {
            let Some(rest) = step_command(line).strip_prefix("cargo test ") else {
                return false;
            };
            let mut words = rest.split_whitespace();
            words.any(|word| word == "--test") && words.next() == Some(target)
        })
    };

    let files = std::fs::read_dir(root.join("tests"))
        .expect("tests dir")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"));

    let mut unrun = Vec::new();
    for path in files {
        let Some(target) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        // Not a target: the shared harness is compiled into the others.
        if target != "harness" && !run_by_ci(target) {
            unrun.push(target.to_string());
        }
    }
    // read_dir order is arbitrary, and a failure message is read by a human.
    unrun.sort();

    assert!(
        unrun.is_empty(),
        "these test targets exist and CI never runs them, so they prove nothing: {unrun:?}"
    );
}

/// Every literal "frama-c-mcp-<target>.tar.gz" in a text.
///
/// Literal, so the spelling the build job packages under, which is assembled
/// from a matrix expression, is skipped: that one cannot go stale and so there
/// is nothing in it to check. A span that ran past a line ending picked up
/// whitespace and is discarded for the same reason, since the two halves came
/// from different lines and never named one file.
fn tarball_names(text: &str) -> std::collections::BTreeSet<String> {
    const PREFIX: &str = "frama-c-mcp-";
    const SUFFIX: &str = ".tar.gz";

    let mut names = std::collections::BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        rest = &rest[start..];
        let Some(end) = rest.find(SUFFIX) else { break };
        let name = &rest[..end + SUFFIX.len()];
        if !name.contains('$') && !name.contains(char::is_whitespace) {
            names.insert(name.to_string());
        }
        rest = &rest[PREFIX.len()..];
    }
    names
}

/// The released tarballs are named the same in the matrix, the release job and
/// README.
///
/// Three copies of one list. The build matrix decides the targets, the release
/// job names each asset so a rename fails before anything is published, and
/// README tells a person which URL to fetch. The release job's copy is checked
/// against the artifacts at run time, so it cannot ship the wrong set; README's
/// copy is checked by nothing, and a renamed target would leave it pointing at
/// a download that 404s while every gate stayed green.
///
/// This is the same shape as tool_router_matches_the_documented_surface and
/// incomplete_codes_match_their_documentation: a contract between code and a
/// document, pinned rather than trusted.
///
/// Both sets are asserted non-empty first. A parse that stops recognising
/// either file would otherwise compare nothing against nothing and report all
/// clear.
#[test]
fn released_tarball_names_match_the_build_matrix() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // The matrix is in the YAML and the staged names are in
    // .ci/stage-release-assets.sh, so this needs both halves.
    let workflow = ci_command_text(root);
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");

    // The matrix rows are the source of truth: a target exists because a row
    // builds it. Rows written as an expression belong to some other key, such
    // as the toolchain's target list, and name no artifact.
    let targets: Vec<&str> = workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("target: "))
        .filter(|target| !target.contains("${{"))
        .collect();
    assert!(
        !targets.is_empty(),
        "no build matrix target parsed from ci.yml, so this guard compared nothing"
    );

    let expected: std::collections::BTreeSet<String> =
        targets.iter().map(|target| format!("frama-c-mcp-{target}.tar.gz")).collect();

    let in_workflow = tarball_names(&workflow);
    assert!(
        !in_workflow.is_empty(),
        "no asset name parsed from ci.yml, so this guard compared nothing"
    );
    assert_eq!(
        in_workflow, expected,
        "the release job stages a different set of assets than the build matrix \
         produces, so a push to main would fail at Stage assets"
    );

    let in_readme = tarball_names(&readme);
    assert!(
        !in_readme.is_empty(),
        "no download URL parsed from README.md, so this guard compared nothing"
    );
    assert_eq!(
        in_readme, expected,
        "README documents a different set of downloads than CI publishes, so a \
         reader following it would fetch a URL that does not exist"
    );
}

/// Every gate CI runs, as the gate name this repository uses for it.
///
/// Split out because two tests need it and they check different halves: one
/// that the runner covers CI, one that the documents cover the runner.
fn ci_gates(root: &std::path::Path) -> Vec<String> {
    let workflow = ci_command_text(root);

    let mut required: Vec<String> = Vec::new();
    for line in workflow.lines() {
        if let Some(gate) = gate_of(step_command(line)) {
            required.push(gate);
        }
    }
    required.sort();
    required.dedup();

    // Counted by kind, because the kinds fail independently. A parser that
    // stops recognising cargo lines still collects the scripts, so a bare total
    // stayed comfortably above any threshold while seeing no test at all, which
    // is how this missed its own control the first time.
    let suites = required.iter().filter(|gate| gate.starts_with("--test")).count();
    assert!(
        suites >= 3 && required.iter().any(|gate| gate == "--test unit"),
        "the workflow parser stopped recognising cargo test lines: {required:?}"
    );

    // The two lint gates by name, because they are the two that can leave the
    // set without any suite count moving. Measured: extracting the shell block
    // into .ci/check-shell-formatting.sh and writing the binary as "$bin"
    // removed the literal gate_of matches on, so shfmt silently left this set
    // and the two tests built on it went from checking it to not. Nothing went
    // red. A gate that disappears has to fail here rather than be discovered by
    // reading the file it used to be in.
    for lint in ["shfmt", "cargo clippy"] {
        assert!(
            required.iter().any(|gate| gate == lint),
            "{lint} is in no workflow or .ci script, so nothing can fail a push \
             on it: {required:?}"
        );
    }

    required
}

/// The whole-suite gate a CI command runs, if it runs one.
fn gate_of(command: &str) -> Option<String> {
    if command.starts_with("scripts/") {
        return Some(command.to_string());
    }
    if command.ends_with("dune runtest") {
        return Some("dune runtest".to_string());
    }

    // The two lint gates. Neither is a cargo test, and leaving them out is how
    // clippy came to run in scripts/run-gates.sh and in no workflow at all,
    // where nothing could fail a push on it. The shfmt step spans several lines
    // of a "run: |" block, so it is matched on the invocation rather than on
    // the whole command.
    if command.contains("shfmt -d") {
        return Some("shfmt".to_string());
    }
    if command.starts_with("cargo clippy") {
        return Some("cargo clippy".to_string());
    }

    // The release build, because two suites spawn the binary from disk rather
    // than the harness cargo just built. Leaving it out of the list made the
    // list fail on a clean checkout and, worse, pass against a stale binary
    // while testing the code as it was before the change.
    if command.starts_with("cargo build --release") {
        return Some("cargo build --release".to_string());
    }

    // As in ci_named_tests_still_exist: --test is not always the first word,
    // and requiring it there dropped whole gates from the set this compares
    // against the documents.
    let mut words = command.strip_prefix("cargo test ")?.split_whitespace();
    if !words.any(|word| word == "--test") {
        return None;
    }
    let gate = format!("--test {}", words.next()?);

    // Nothing after the target, or an option where a name would be: the step
    // runs the whole target rather than filtering it to one test.
    words.next().is_none_or(|word| word.starts_with('-')).then_some(gate)
}

/// The dependency advisory scan is still in a workflow, with the permission it
/// needs.
///
/// gate_of below recognises a cargo command or a scripts/ path, so this one is
/// invisible to every guard around it: it is a uses: step, and it is the one
/// check deliberately absent from scripts/run-gates.sh because its verdict
/// comes from a database rather than from the tree. Nothing would fail if it
/// were deleted, which is the shape this file already has four guards for.
///
/// The permission is checked inside the job that runs the action, because the
/// two are one thing. The action reports by creating a check run and the
/// workflow floor is contents: read, so the job running it needs checks: write
/// of its own. Asserting the two independently over the whole file was the
/// first version and it did not say that: the permission could move to any
/// other job, or to a job that runs nothing, and the guard stayed green while
/// the step lost what it needs.
#[test]
fn ci_still_scans_dependencies_for_advisories() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // A line predicate rather than a rewritten body, and comment blindness only
    // where it is needed. documented_gate_list_covers_ci reads a fenced block
    // rather than a whole document for the same reason: the comment above the
    // permissions block explains why artifact-scans grants checks: write, so a
    // whole-text search left the guard green with the permission deleted. The
    // permission test below needs no such care, since a comment line cannot
    // equal "checks: write" once trimmed.
    let runs = |body: &String, needle: &str| {
        body.lines().any(|line| !line.trim_start().starts_with('#') && line.contains(needle))
    };

    let jobs = all_workflow_jobs(root);
    let scanning: Vec<&(std::path::PathBuf, String, String)> =
        jobs.iter().filter(|(_, _, body)| runs(body, "rustsec/audit-check@")).collect();
    assert_eq!(
        scanning.len(),
        1,
        "expected exactly one job to run an advisory scan, found these. None means \
         a vulnerable dependency lands green: {:?}",
        scanning.iter().map(|(_, name, _)| name).collect::<Vec<_>>()
    );

    let (path, name, body) = scanning[0];
    assert!(
        body.lines().any(|line| line.trim() == "checks: write"),
        "{}: job {name} runs the advisory action and does not grant itself \
         checks: write. The workflow floor is contents: read, so the action \
         cannot create the check run it reports through:\n{body}",
        path.display()
    );
}

/// Every lane gates the release.
///
/// A job that runs and is not among the release job's needs can be red while
/// the rolling tag is republished, which is a green badge over a binary nothing
/// vouched for. Measured on 2026-08-28: release needs five jobs while CLAUDE.md
/// described four, having dropped plugin-floor, so the document did not say
/// that
/// a Frama-C 32.1 build failure blocks a release. No guard can read that
/// document, since it is never checked in, so this pins the fact rather than
/// the
/// prose.
///
/// A job that deliberately does not gate a release will fail here. That is the
/// intent: it is a decision worth writing down rather than one worth inferring
/// from an absence.
#[test]
fn the_release_waits_for_every_lane() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let jobs = all_workflow_jobs(root);

    // The release job's own needs, read out of its body, so a needs belonging
    // to some other job cannot stand in for the one being checked.
    let releases: Vec<&(std::path::PathBuf, String, String)> =
        jobs.iter().filter(|(_, name, _)| name == "release").collect();
    assert_eq!(
        releases.len(),
        1,
        "expected exactly one release job across the workflows, found {}",
        releases.len()
    );
    let (path, _, release) = releases[0];

    let needs = release
        .lines()
        .find(|line| line.trim_start().starts_with("needs:"))
        .unwrap_or_else(|| panic!("{}: the release job declares no needs", path.display()));
    let listed = flow_list(needs);
    assert!(
        !listed.is_empty(),
        "{}: the release needs is empty or not a flow list, so this guard \
         compared nothing: {needs}",
        path.display()
    );

    let ungating: Vec<&String> = jobs
        .iter()
        .filter(|(job_path, name, _)| {
            job_path == path && name != "release" && !listed.contains(name)
        })
        .map(|(_, name, _)| name)
        .collect();
    assert!(
        ungating.is_empty(),
        "{}: these jobs run and the release does not wait for them, so each can \
         be red while the rolling tag is republished: {ungating:?}. Add them to \
         needs, or record why they do not gate a release",
        path.display()
    );
}

/// The stdio suite runs under the same RUST_LOG in CI and in the runner.
///
/// src/main.rs builds its subscriber from the environment, and EnvFilter admits
/// ERROR only when RUST_LOG is unset, so the recovered-race warn that
/// scripts/check-stdio-refusal.sh counts exists only when this variable is set.
/// Drop it from either caller and the script prints "0 recovered" for every
/// run,
/// which is exactly what a healthy run prints. That is the silent-drift shape
/// this file already has several tests about, and it arrived with the two
/// callers rather than by drift between them.
#[test]
fn the_stdio_suite_runs_under_one_log_level() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    const DIRECTIVE: &str = "RUST_LOG: frama_c_mcp=warn";
    const RUNNER: &str = "RUST_LOG=frama_c_mcp=warn";

    let stdio: Vec<(std::path::PathBuf, String, String)> = all_workflow_jobs(root)
        .into_iter()
        .filter(|(_, _, body)| body.contains("--test test-mcp-stdio"))
        .collect();
    assert_eq!(stdio.len(), 1, "expected one job to run the stdio suite, found {}", stdio.len());
    assert!(
        stdio[0].2.lines().any(|line| line.trim() == DIRECTIVE),
        "the workflow job running the stdio suite does not set {DIRECTIVE}, so its \
         log carries no recovered-race warn and check-stdio-refusal.sh reports \
         zero for every run"
    );

    let runner =
        std::fs::read_to_string(root.join("scripts/run-gates.sh")).expect("run-gates.sh");
    assert!(
        runner.lines().any(|line| {
            line.trim_start().starts_with("want stdio")
                && line.contains(RUNNER)
                && line.contains("--test test-mcp-stdio")
        }),
        "scripts/run-gates.sh runs the stdio suite without {RUNNER}, so a local run \
         cannot reproduce what CI scans"
    );
}

/// scripts/run-gates.sh runs every gate CI runs.
///
/// The runner is what the documents send a person to, so a gate CI has and the
/// runner lacks is one that running the runner will not catch. Measured on
/// 2026-08-19: clippy was in the runner and in no workflow, and the shfmt step
/// was in ci.yml and not in the runner, so neither one was a superset of the
/// other and following either left a gate unrun.
#[test]
fn run_gates_runs_every_ci_gate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(root.join("scripts/run-gates.sh")).expect("run-gates.sh");

    // The dispatch lines, not the whole file, for the reason
    // documented_gate_list_covers_ci reads a fenced block rather than a
    // document: a comment naming a gate satisfies a whole-file search while
    // nothing runs it. This file's own comments name shfmt and clippy, so the
    // first version of this test passed on a runner that had dropped both.
    let runner: String =
        script.lines().filter(|line| line.trim_start().starts_with("want ")).collect();
    assert!(
        runner.contains("--test unit"),
        "no dispatch line was read, so this test would pass on an empty runner"
    );

    let missing: Vec<String> = ci_gates(root)
        .into_iter()
        .filter(|gate| !runner.contains(gate.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "CI runs these and scripts/run-gates.sh does not, so the runner the \
         documents point at is not the gate set: {missing:?}"
    );
}

/// The gate list in the documentation covers everything CI runs over a whole
/// suite.
///
/// That list is what a person follows before saying a change is green, so a
/// gate missing from it is one nobody runs by hand. Measured on 2026-08-13:
/// "dune runtest" was absent, and the whole OCaml plug-in suite went unrun for
/// a session that edited the plug-in twice. It passed, which is luck, not
/// method.
///
/// A document may instead delegate, by naming scripts/run-gates.sh in its test
/// block. That is only honest because run_gates_runs_every_ci_gate pins the
/// runner against CI; without that test, delegation would let a document say
/// nothing and pass. README delegates, so that pairing is what carries this
/// today rather than a list read here.
///
/// CLAUDE.md carried the other copy and was read here too, until it stopped
/// being part of the repository. A checkout has no such file, so this panicked
/// on a missing path rather than comparing anything, and the panic was
/// invisible on a machine where the file happens to exist.
///
/// Only whole-suite commands. CI also runs single tests by name as smoke
/// checks, and those are not gates; ci_named_tests_still_exist covers them.
#[test]
fn documented_gate_list_covers_ci() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let required = ci_gates(root);

    // The fenced block under the test heading, not the whole file. Prose
    // elsewhere naming a gate satisfies a whole-file search without anyone
    // being told to run it, which is how the first version of this passed its
    // own control: the paragraph explaining the gap mentioned "dune runtest".
    //
    // Every document in this list must exist, so a typo or a renamed file fails
    // here rather than quietly checking one fewer copy.
    let gate_lists: Vec<(&str, String)> = ["README.md"]
        .into_iter()
        .map(|name| {
            let text = std::fs::read_to_string(root.join(name)).expect(name);
            let block = text
                .split_once("## test")
                .or_else(|| text.split_once("## Testing"))
                .and_then(|(_, rest)| rest.split_once("```bash"))
                .and_then(|(_, rest)| rest.split_once("```"))
                .map(|(block, _)| block.to_string())
                .unwrap_or_else(|| panic!("{name} has no bash block under its test heading"));
            (name, block)
        })
        .collect();

    // Delegation, not a second copy. README sends a person to the runner
    // instead of restating twelve commands, and run_gates_runs_every_ci_gate is
    // what makes that equivalent to restating them.
    let missing: Vec<(&str, &String)> = gate_lists
        .iter()
        .filter(|(_, list)| !list.contains("scripts/run-gates.sh"))
        .flat_map(|(name, list)| {
            required
                .iter()
                .filter(move |gate| !list.contains(gate.as_str()))
                .map(move |gate| (*name, gate))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "CI runs these and the gate list in that document does not mention them, so \
         nobody runs them by hand: {missing:?}"
    );
}

/// The ast-utils requests self_check expects are the requests its plug-in
/// registers.
///
/// AST_UTILS_REQUESTS is hand-written because it also states each request's
/// probe behaviour. The plug-in is the authority for the name and the command
/// verb, so those two columns are compared here; the probed flag is this
/// server's own policy and stays unguarded. The Rust side is read from the
/// crate rather than parsed back out of selfcheck.rs, which is what leaves the
/// text scanning to the OCaml half and keeps this test free of Frama-C.
#[test]
fn ast_utils_requests_match_plugin_registrations() {
    const PREFIX: &str = "plugins.ast-utils.";

    let expected = selfcheck::AST_UTILS_REQUESTS
        .iter()
        .map(|&(request, kind, _)| {
            let name = request.strip_prefix(PREFIX).unwrap_or_else(|| {
                panic!("AST_UTILS_REQUESTS holds a request from another domain: {request}")
            });
            let kind = match kind {
                selfcheck::ProbeKind::Get => "`GET",
                selfcheck::ProbeKind::Set => "`SET",
                selfcheck::ProbeKind::Exec => "`EXEC",
            };
            (name.to_string(), kind.to_string())
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        expected.len(),
        selfcheck::AST_UTILS_REQUESTS.len(),
        "AST_UTILS_REQUESTS names a request twice, so self_check probes it twice"
    );

    // Every module, not just the one that registers everything today: a
    // registration moved into a sibling would otherwise leave both sides quiet.
    // Recursive for the same reason, even though dune's "modules :standard"
    // reads one directory: a subdirectory needs its own dune file to build at
    // all, and a scan that trusts that has to be re-read every time the build
    // description changes.
    let mut sources = Vec::new();
    source_files(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ast-utils/src"),
        "ml",
        &mut sources,
    );
    assert!(!sources.is_empty(), "no plug-in sources to scan");

    let mut actual: BTreeMap<String, (String, String)> = BTreeMap::new();
    for path in &sources {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let text = strip_ocaml_comments(&source);
        let lines = text.lines().collect::<Vec<_>>();
        let registrations = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains("Server.Request.register"));
        for (at, _) in registrations {
            // The kind and the name sit two and three lines below the call
            // today, and six is slack. A registration that puts either further
            // out panics rather than going quiet, which is the whole value of
            // the window being fixed. It is fixed rather than cut at the next
            // registration because the registrations stand tens of lines apart;
            // a pair closer than six would let the first read the second's
            // fields and then blame the table for a name registered twice.
            let window = &lines[at..lines.len().min(at + 7)];
            let field = |label: &str| {
                window.iter().find_map(|line| line.split_once(label)).map(|(_, rest)| rest)
            };
            let site = format!("{}:{}", path.display(), at + 1);
            let name = field("~name:\"")
                .and_then(|rest| rest.split_once('"'))
                .unwrap_or_else(|| panic!("{site}: registration has no ~name within six lines"))
                .0;

            // One token, not the rest of the line: a registration that put the
            // kind and the name on one line would otherwise read as a kind of
            // "`GET ~name:..." and blame the table for the mismatch.
            let kind = field("~kind:")
                .and_then(|rest| rest.split_whitespace().next())
                .unwrap_or_else(|| panic!("{site}: registration has no ~kind within six lines"));

            // Both sites, because which one loses the insert is decided by path
            // order rather than by which one is new, and blaming the older file
            // sends the reader somewhere that has been correct for months.
            if let Some((_, first)) =
                actual.insert(name.to_string(), (kind.to_string(), site.clone()))
            {
                panic!("{site}: {name} is also registered at {first}");
            }
        }
    }
    assert!(!actual.is_empty(), "no plug-in registrations parsed");

    // Both directions and the disagreement in one match, so the cases are
    // visibly exhaustive rather than three filters that have to add up.
    let drift = expected
        .keys()
        .chain(actual.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|name| match (expected.get(name), actual.get(name)) {
            (Some(table), Some((plugin, site))) if table != plugin => Some(format!(
                "{name} is in the table as {table} and registered as {plugin} at {site}"
            )),
            (Some(table), None) => {
                Some(format!("{name} is in the table as {table} and registered nowhere"))
            }
            (None, Some((plugin, site))) => {
                Some(format!("{name} is registered as {plugin} at {site} and in no table"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        drift.is_empty(),
        "AST_UTILS_REQUESTS has drifted from the plug-in: {drift:#?}"
    );
}

/// Blank out OCaml comment bodies, keeping the line structure.
///
/// Comments nest, and a registration commented out rather than deleted still
/// reads as a registration to a substring scan, which is the drift this file
/// exists to catch arriving as a clean run. A "(*" inside a string literal
/// would open a comment that is not there; nothing in the plug-in writes one,
/// and telling the two apart needs a lexer.
fn strip_ocaml_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if rest.starts_with("(*") {
            depth += 1;
        } else if depth > 0 && rest.starts_with("*)") {
            depth -= 1;
        } else {
            out.push(if depth > 0 && c != '\n' { ' ' } else { c });
            rest = &rest[c.len_utf8()..];
            continue;
        }
        out.push_str("  ");
        rest = &rest[2..];
    }
    out
}

/// The tool surface is exactly what README documents.
///
/// A `#[tool]` attribute binds to whatever function follows it, so inserting a
/// helper between the attribute and its handler silently moves the tool: the
/// handler stops being a tool and the helper becomes one under the handler's
/// description. That happened while splitting run_wp, and nothing in this
/// suite noticed, because every other test calls the handlers directly rather
/// than through the router.
///
/// Compared against README rather than against a list written here, for the
/// reason incomplete_codes_match_their_documentation gives: a list in the test
/// is a second copy to keep in step, and it goes stale in exactly the commit
/// that renames a tool in both the router and the test while leaving the
/// documentation behind.
#[test]
fn tool_router_matches_the_documented_surface() {
    // The Tools table names its tools in the second cell, several per row, each
    // in backticks. The parse insists on that shape, so a row written some
    // other way goes missing from the set and the comparison reports it, rather
    // than being quietly accepted.
    fn documented_tools(markdown: &str) -> std::collections::BTreeSet<String> {
        let table = markdown
            .split("## Tools")
            .nth(1)
            .expect("README has a Tools section");
        table
            .lines()
            .skip_while(|line| !line.starts_with('|'))
            .take_while(|line| line.starts_with('|'))
            .filter_map(|line| line.split('|').nth(2))
            .flat_map(|cell| cell.split(','))
            .filter_map(|entry| {
                let entry = entry.trim();
                entry
                    .strip_prefix('`')
                    .and_then(|entry| entry.strip_suffix('`'))
                    .map(str::to_string)
            })
            .collect()
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let documented = documented_tools(&readme);

    // Against the router rather than a literal. The set comparison below is the
    // real check; this one catches a README parse that silently matched
    // nothing, and it should not itself be a number to bump.

    assert_eq!(
        documented.len(),
        FramaCMcpServer::tool_router().list_all().len(),
        "parsed {documented:?}"
    );

    let registered = FramaCMcpServer::tool_router()
        .list_all()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(registered, documented);
}


/// A job that runs a script out of the tree checks the tree out first.
///
/// This exists because moving shell out of ci.yml into .ci/ turned steps that
/// needed nothing into steps that need the repository, and the release job had
/// no checkout: its comment said "No checkout: nothing here reads the tree",
/// which was true when it was written and false the moment its shell became two
/// files. Nothing caught it. It is not reachable from a pull request either,
/// since the job is gated on a push to main, so the first evidence would have
/// been a release that did not happen.
///
/// The checkout also has to be the job's first step, not merely somewhere
/// before the script. actions/checkout cleans the workspace by default, so a
/// checkout after actions/download-artifact deletes the artifacts the release
/// is assembled from, and a job that fails that way still has a checkout and
/// still runs its scripts. All five jobs already put it first, so this pins a
/// convention rather than imposing one.
#[test]
fn jobs_running_repo_scripts_check_out_the_repo() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut offenders = Vec::new();
    let mut checked = 0;
    for path in workflow_files(root) {
        let workflow = std::fs::read_to_string(&path).unwrap_or_default();

        // Steps run in file order and workflow_jobs keeps a body in that order,
        // so a linear scan of each body is enough to know whether the checkout
        // came first. A YAML parser would be better and is not worth a
        // dependency for six jobs.
        for (job, body) in workflow_jobs(&workflow) {
            let mut checkout_at = None;
            let mut runs_repo_script = false;
            let mut step = 0usize;

            for line in body.lines() {
                let indent = line.len() - line.trim_start().len();
                let trimmed = line.trim();

                // Steps sit at six spaces. Counting every "- " would also count
                // the build matrix's include entries, which are not steps.
                if indent == 6 && trimmed.starts_with("- ") {
                    step += 1;
                }
                if trimmed.contains("actions/checkout") && checkout_at.is_none() {
                    checkout_at = Some(step);
                }
                if (trimmed.contains(".ci/") || trimmed.contains("scripts/"))
                    && !trimmed.starts_with('#')
                {
                    runs_repo_script = true;
                }
            }

            if !runs_repo_script {
                continue;
            }
            checked += 1;
            match checkout_at {
                Some(1) => {}
                Some(at) => offenders.push(format!(
                    "{job}: checks out at step {at} rather than first, so an earlier \
                     step's workspace writes are cleaned away"
                )),
                None => offenders.push(format!("{job}: runs a repo script with no checkout")),
            }
        }
    }

    assert!(
        checked >= 3,
        "no job was found running a repo script, so this guard compared nothing: \
         the workflow moved and the parser did not"
    );
    assert!(
        offenders.is_empty(),
        "these jobs run a script out of the tree without checking it out first, \
         so the step fails with no such file: {offenders:?}"
    );
}
