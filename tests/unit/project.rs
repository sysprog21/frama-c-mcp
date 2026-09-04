use frama_c_mcp::mcp::server::*;

use frama_c_mcp::mcp::server::project::*;
use serde_json::json;
use std::path::Path;

fn with_defines(defines: &[&str]) -> ProjectLoadOptions {
    ProjectLoadOptions {
        defines: defines.iter().map(|d| d.to_string()).collect(),
        ..Default::default()
    }
}

fn with_include_paths(paths: &[&str]) -> ProjectLoadOptions {
    ProjectLoadOptions {
        include_paths: paths.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    }
}

fn with_isystem_paths(paths: &[&str]) -> ProjectLoadOptions {
    ProjectLoadOptions {
        isystem_paths: paths.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    }
}

fn with_force_includes(headers: &[&str]) -> ProjectLoadOptions {
    ProjectLoadOptions {
        force_includes: headers.iter().map(|h| h.to_string()).collect(),
        ..Default::default()
    }
}

#[test]
fn plain_and_valued_defines_are_accepted() {
    assert!(validate_project_options(&with_defines(&["NDEBUG", "_Atomic=", "N=4"])).is_ok());
}

#[test]
fn ordinary_paths_and_headers_are_accepted() {
    assert!(validate_project_options(&with_include_paths(&["include", "../vendor/inc"])).is_ok());
    assert!(validate_project_options(&with_force_includes(&["builtins.h", "sys/types.h"])).is_ok());
}

#[test]
fn system_include_paths_use_the_same_safe_grammar() {
    let valid = with_isystem_paths(&["include", "../vendor/inc"]);
    let injected = with_isystem_paths(&["$(touch pwned)"]);
    assert!(validate_project_options(&valid).is_ok());
    assert!(validate_project_options(&injected).is_err());
}

/// The log shape is verbatim Frama-C 33: tag and location on one line, text
/// indented on the next. The feedback line and the untagged "[kernel] Parsing"
/// line are both in the sample because both are in every real log.
fn sample_log() -> String {
    let mut log = String::from("[kernel] Parsing a.c (with preprocessing)\n");
    log.push_str("[kernel:pp:compilation-db] using compilation database:\n  a.json\n");
    for line in 1..=21 {
        log.push_str(&format!(
            "[kernel:asm:clobber] src/a.c:{line}: Warning: \n  Clobber list contains \"memory\" argument.\n"
        ));
    }
    for (line, name) in [(30, "one"), (31, "one"), (32, "two")] {
        log.push_str(&format!(
            "[kernel:attrs:unknown] src/a.c:{line}: Warning: \n  Ignoring unknown attribute: {name}\n"
        ));
    }
    log.push_str("[kernel:typing:implicit-function-declaration] /abs/b.c:40: Warning: \n  Calling undeclared function f. Old style K&R code?\n");
    log
}

#[test]
fn ast_parse_diagnostics_counts_only_warning_tags_and_bounds_samples() {
    let log = sample_log();
    let health = ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
    let categories = &health["categories"];

    assert_eq!(categories["kernel:asm:clobber"]["count"], 21);
    assert_eq!(categories["kernel:asm:clobber"]["count_unit"], "sites");
    assert_eq!(
        categories["kernel:asm:clobber"]["locations"].as_array().unwrap().len(),
        20
    );
    assert_eq!(categories["kernel:asm:clobber"]["locations_omitted"], 1);

    // Three warnings, two names. The unit says which of those it reports.
    assert_eq!(categories[ATTRS_UNKNOWN]["count"], 2);
    assert_eq!(
        categories[ATTRS_UNKNOWN]["count_unit"],
        "distinct_attribute_names"
    );

    assert_eq!(
        categories["kernel:typing:implicit-function-declaration"]["count"],
        1
    );

    // A tag without the Warning token is feedback, and an untagged line is
    // neither.
    assert!(categories.get("kernel:pp:compilation-db").is_none());
    assert!(categories.get("kernel").is_none());
}

/// A relative location resolves against the child's working directory and an
/// absolute one is left alone, because Frama-C prints both and neither form
/// matches the argument the caller passed.
#[test]
fn ast_parse_diagnostics_resolves_locations_against_the_child_directory() {
    let log = sample_log();
    let health = ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
    let clobber = &health["categories"]["kernel:asm:clobber"]["locations"][0];
    assert_eq!(clobber["file"], "/work/src/a.c");
    assert_eq!(clobber["line"], 1);
    let implicit =
        &health["categories"]["kernel:typing:implicit-function-declaration"]["locations"][0];
    assert_eq!(implicit["file"], "/abs/b.c");
    assert_eq!(implicit["line"], 40);
}

/// Both soundness categories are keys even when nothing fired, so a caller
/// reads a zero rather than a missing key.
#[test]
fn ast_parse_diagnostics_reports_zero_for_a_clean_parse() {
    let log = "[kernel] Parsing clean.c (with preprocessing)\n";
    let health = ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
    assert_eq!(health["categories"]["kernel:asm:clobber"]["count"], 0);
    assert_eq!(health["categories"][ATTRS_UNKNOWN]["count"], 0);
}

/// The offsets select the boot parse out of a log that has since grown. Only
/// the named window is counted; bytes on either side are another AST's.
#[test]
fn ast_parse_diagnostics_counts_only_the_named_window() {
    let boot = "[kernel:asm:clobber] a.c:1: Warning: \n  Clobber list contains \"memory\" argument.\n";
    let later = "[kernel:asm:clobber] b.c:9: Warning: \n  Clobber list contains \"memory\" argument.\n";
    let log = format!("{boot}{later}");
    let health = ast_parse_diagnostics(log.as_bytes(), boot.len() as u64, Path::new("/work"));
    assert_eq!(health["categories"]["kernel:asm:clobber"]["count"], 1);

    // Out-of-range offsets clamp rather than panic.
    let all = ast_parse_diagnostics(log.as_bytes(), u64::MAX, Path::new("/work"));
    assert_eq!(all["categories"]["kernel:asm:clobber"]["count"], 2);
    let empty = ast_parse_diagnostics(log.as_bytes(), 0, Path::new("/work"));
    assert_eq!(empty["categories"]["kernel:asm:clobber"]["count"], 0);
}

/// A bracket in a directory name is not a category, on either side of the tag.
///
/// Both orderings are here because each broke the other anchor: taking the
/// first bracket on the line read "[v1]" as the category when the path came
/// first, and taking the last read it as the category when the path came after
/// the tag, which dropped the warning entirely rather than misfiling it.
#[test]
fn ast_parse_diagnostics_ignores_brackets_outside_the_tag() {
    let clobber = "  Clobber list contains \"memory\" argument.";
    for (label, line) in [
        ("path before the tag", "src/[v1]/a.c:3: [kernel:asm:clobber] Warning: "),
        ("path after the tag", "[kernel:asm:clobber] src/[v1]/a.c:3: Warning: "),
    ] {
        let log = format!("{line}\n{clobber}\nsrc/[v1]/b.c:4: Warning: something untagged\n");
        let health =
            ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
        assert_eq!(
            health["categories"]["kernel:asm:clobber"]["count"], 1,
            "{label}: {health}"
        );
        assert_eq!(
            health["categories"]["kernel:asm:clobber"]["locations"][0]["file"],
            "/work/src/[v1]/a.c",
            "{label}"
        );
        assert!(health["categories"].get("v1").is_none(), "{label}");
    }
}

#[test]
fn ast_parse_diagnostics_ignores_colon_containing_bracketed_paths() {
    let log = "src/[team:api]/a.c:3: [kernel:asm:clobber] Warning: \n  Clobber list contains \"memory\" argument.\n";
    let health =
        ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));

    assert_eq!(health["categories"]["kernel:asm:clobber"]["count"], 1);
    assert_eq!(
        health["categories"]["kernel:asm:clobber"]["locations"][0]["file"],
        "/work/src/[team:api]/a.c"
    );
    assert!(health["categories"].get("team:api").is_none(), "{health}");
}

/// A path that carries the "Warning:" token itself. The marker search has to
/// keep going until it finds one with a tag before it, because stopping at the
/// first left a head with no tag in it and dropped the warning: the count is
/// the soundness claim, so losing it is worse than resolving its location to
/// the directory the path was cut at.
#[test]
fn ast_parse_diagnostics_reads_a_line_whose_path_carries_the_marker() {
    for (label, line) in [
        ("path before the tag", "src/Warning:x/a.c:3: [kernel:asm:clobber] Warning: "),
        ("path after the tag", "[kernel:asm:clobber] src/Warning:x/a.c:3: Warning: "),
    ] {
        let log = format!("{line}\n  Clobber list contains \"memory\" argument.\n");
        let health = ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
        assert_eq!(health["categories"][ASM_CLOBBER]["count"], 1, "{label}: {health}");
    }
}

/// An unmatched "[" in the path pairs with the tag's own closing bracket, so
/// the scan has to resume after the bracket it rejected rather than after the
/// one it borrowed. Resuming past the "]" stepped over the tag and dropped the
/// warning, which is the failure that hides a soundness finding rather than
/// misfiling it.
#[test]
fn ast_parse_diagnostics_reads_a_tag_after_an_unmatched_bracket() {
    let log = "src/[dir/a.c:3: [kernel:asm:clobber] Warning: \n  Clobber list contains \"memory\" argument.\n";
    let health = ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));

    assert_eq!(health["categories"][ASM_CLOBBER]["count"], 1, "{health}");
    assert_eq!(
        health["categories"][ASM_CLOBBER]["locations"][0]["file"],
        "/work/src/[dir/a.c"
    );
}

/// The same segment at the head of a relative path, where the left side is a
/// field boundary too and only the character after the bracket separates a
/// path from a tag.
#[test]
fn ast_parse_diagnostics_ignores_a_bracketed_path_that_opens_the_line() {
    let log = "[team:api]/a.c:3: [kernel:asm:clobber] Warning: \n  Clobber list contains \"memory\" argument.\n";
    let health = ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));

    assert_eq!(health["categories"]["kernel:asm:clobber"]["count"], 1, "{health}");
    assert_eq!(
        health["categories"]["kernel:asm:clobber"]["locations"][0]["file"],
        "/work/[team:api]/a.c"
    );
    assert!(health["categories"].get("team:api").is_none(), "{health}");
}

/// Frama-C puts the attribute name on the tag line when it fits and wraps it
/// onto the next when it does not, and which happens is a function of the path
/// length against the margin.
///
/// Measured on Frama-C 33: "a.c:1" keeps "__q__" on the tag line, while the
/// same attribute reported under a path like this repository's fixtures wraps.
/// Reading only the wrapped form counted zero attributes for every project
/// with short paths, and every fixture here has a long one, so nothing caught
/// it.
#[test]
fn ast_parse_diagnostics_reads_an_attribute_name_on_either_line() {
    let wrapped = "[kernel:attrs:unknown] tests/fixtures/long-enough-to-wrap.c:3: Warning: \n  Ignoring unknown attribute: __wrapped__\n";
    let inline = "[kernel:attrs:unknown] a.c:1: Warning: Ignoring unknown attribute: __q__\n";

    for (label, log, name, line) in [
        ("wrapped", wrapped, "__wrapped__", 3),
        ("same line", inline, "__q__", 1),
    ] {
        let health =
            ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
        let entry = &health["categories"][ATTRS_UNKNOWN]["locations"][0];
        assert_eq!(health["categories"][ATTRS_UNKNOWN]["count"], 1, "{label}");
        assert_eq!(entry["attribute"], name, "{label}");
        assert_eq!(entry["location"]["line"], line, "{label}");
    }

    // Both spellings in one log are still two names and two counts.
    let log = format!("{wrapped}{inline}");
    let health =
        ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));
    assert_eq!(health["categories"][ATTRS_UNKNOWN]["count"], 2, "{health}");
}

/// A warning between an attribute's tag line and its name ends the wrap.
///
/// The name is still counted, because the count is the soundness claim and an
/// unpinned location is a worse answer than none rather than a reason to drop
/// the finding. What must not happen is the name inheriting the earlier
/// warning's location and pointing at the wrong file.
#[test]
fn an_interrupted_attribute_keeps_its_count_and_loses_only_its_location() {
    let log = "[kernel:attrs:unknown] src/a.c:3: Warning: \n               [kernel:asm:clobber] src/b.c:9: Warning: \n               \x20 Clobber list contains \"memory\" argument.\n               \x20 Ignoring unknown attribute: __orphan__\n";
    let health =
        ast_parse_diagnostics(log.as_bytes(), log.len() as u64, Path::new("/work"));

    assert_eq!(health["categories"][ATTRS_UNKNOWN]["count"], 1, "{health}");
    let entry = &health["categories"][ATTRS_UNKNOWN]["locations"][0];
    assert_eq!(entry["attribute"], "__orphan__", "{health}");
    assert_eq!(
        entry["location"], json!({"unresolved": true}),
        "src/a.c:3 belongs to the clobber's neighbour, not to this name: {health}"
    );
    assert_eq!(health["categories"]["kernel:asm:clobber"]["count"], 1, "{health}");
}

/// A window this server could not read reports no category at all. A zero
/// would be a claim that the front end dropped nothing, which is the one thing
/// an unreadable log cannot establish.
#[test]
fn an_unreadable_parse_log_is_not_a_clean_parse() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join("never-written.stdout.log");
    let record = unreadable_parse_log(&missing, &std::io::Error::from(std::io::ErrorKind::NotFound));

    assert_eq!(record["categories"], json!({}));
    assert!(
        record["unavailable"]
            .as_str()
            .is_some_and(|reason| reason.contains("never-written.stdout.log")),
        "{record}"
    );

    // And check reads it as a finding rather than as silence. Silence would let
    // a verdict of "proved" stand on the one shape where nothing established
    // that the analyzed program is the compiled one.
    let reload = json!({"ast_reload_health": {"parse_diagnostics": record}});
    let mut items = Vec::new();
    checkgaps::ast_diagnostic_gaps(&mut items, &reload, &[]);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(
        items[0]["code"],
        checkgaps::incomplete_code::AST_PARSE_DIAGNOSTICS_UNAVAILABLE
    );
    assert!(
        items[0]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("never-written.stdout.log")),
        "{items:?}"
    );

    // And it is the whole answer: a record with no categories has nothing to
    // say about any of them, so no zero row follows it.
    let clean = json!({"ast_reload_health": {"parse_diagnostics": {"categories": {
        "kernel:asm:clobber": {"count": 0, "count_unit": "sites"},
    }}}});
    let mut items = Vec::new();
    checkgaps::ast_diagnostic_gaps(&mut items, &clean, &[]);
    assert!(items.is_empty(), "{items:?}");
}

#[test]
fn header_bearing_sources_do_not_reuse_parse_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.c");
    let included = dir.path().join("included.c");
    std::fs::write(&plain, "int f(void) { return 0; }\n").unwrap();
    std::fs::write(&included, "# include \"header.h\"\nint f(void) { return 0; }\n").unwrap();

    // A comment can precede the directive on its own line, so a scan anchored
    // to the first character of the line reads this as header-free.
    let commented = dir.path().join("commented.c");
    std::fs::write(&commented, "/**/#include \"header.h\"\nint f(void) { return 0; }\n").unwrap();

    // The same directive written with the digraph and with the trigraph. Both
    // are the preprocessor pulling in bytes the digest does not cover, and
    // neither carries a "#".
    let digraph = dir.path().join("digraph.c");
    std::fs::write(&digraph, "%:include \"header.h\"\nint f(void) { return 0; }\n").unwrap();
    let trigraph = dir.path().join("trigraph.c");
    std::fs::write(&trigraph, "??=include \"header.h\"\nint f(void) { return 0; }\n").unwrap();

    assert!(!files_may_include(&[plain.display().to_string()]));
    assert!(files_may_include(&[included.display().to_string()]));
    assert!(files_may_include(&[commented.display().to_string()]));
    assert!(files_may_include(&[digraph.display().to_string()]));
    assert!(files_may_include(&[trigraph.display().to_string()]));
    assert!(files_may_include(&[dir.path().join("missing.c").display().to_string()]));
}

// -cpp-extra-args is shell-evaluated by Frama-C, so these fields are shell
// input. The whitespace ban that came before the allowlist did not stop a
// payload that carries no whitespace. reload_project with each of these created
// a file on disk before is_cpp_arg_char existed.
#[test]
fn a_shell_command_substitution_define_is_rejected() {
    assert!(validate_project_options(&with_defines(&["X=$(touch${IFS}/tmp/x)"])).is_err());
    assert!(validate_project_options(&with_defines(&["X=`id`"])).is_err());
}

#[test]
fn shell_metacharacters_are_rejected_in_every_cpp_field() {
    // No whitespace in any of these; each is a distinct shell vector.
    for bad in ["$IFS", "a;id", "a|id", "a&b", "a>b", "a<b", "$(id)"] {
        assert!(
            validate_project_options(&with_defines(&[bad])).is_err(),
            "defines accepted {bad:?}"
        );
        assert!(
            validate_project_options(&with_include_paths(&[bad])).is_err(),
            "include_paths accepted {bad:?}"
        );
        assert!(
            validate_project_options(&with_force_includes(&[bad])).is_err(),
            "force_includes accepted {bad:?}"
        );
    }
}

#[test]
fn a_define_with_whitespace_is_rejected() {
    // It would arrive downstream as two flags, since -cpp-extra-args holds one
    // whitespace-separated string.
    assert!(validate_project_options(&with_defines(&["N = 4"])).is_err());
}

#[test]
fn a_define_written_as_a_flag_is_rejected() {
    // Naming the mistake beats silently stripping it: "-D-foo" and "-Dbar" mean
    // different things and only the caller knows which was meant.
    assert!(validate_project_options(&with_defines(&["-D_Atomic="])).is_err());
}

fn with_machdep(machdep: &str) -> ProjectLoadOptions {
    ProjectLoadOptions {
        machdep: Some(machdep.to_string()),
        ..Default::default()
    }
}

fn with_compilation_database(path: &str) -> ProjectLoadOptions {
    ProjectLoadOptions {
        compilation_database: Some(path.to_string()),
        ..Default::default()
    }
}

#[test]
fn machdep_and_compilation_database_reject_a_leading_dash() {
    // Both become their own argv token beside the three preprocessor lists, so
    // a value the caller wrote as a flag is the same mistake there as here.
    assert!(validate_project_options(&with_machdep("gcc_x86_64")).is_ok());
    assert!(validate_project_options(&with_machdep("-machdep")).is_err());
    assert!(validate_project_options(&with_machdep("")).is_err());

    assert!(validate_project_options(&with_compilation_database("build/compile_commands.json")).is_ok());
    assert!(validate_project_options(&with_compilation_database("-json-compilation-database")).is_err());
    assert!(validate_project_options(&with_compilation_database("")).is_err());
}

#[test]
fn custom_machdep_paths_are_accepted() {
    // Every name "frama-c -machdep help" lists on this Frama-C, so the rule is
    // not tighter than the thing it validates.
    for name in [
        "avr_16", "avr_8", "gcc_rv64", "gcc_x86_16", "gcc_x86_32", "gcc_x86_64", "macos_arm",
        "msvc_x86_64", "ppc_32", "x86_16", "x86_32", "x86_64",
    ] {
        assert!(
            validate_project_options(&with_machdep(name)).is_ok(),
            "{name} is a supported machine and must validate"
        );
    }

    // Frama-C detects a custom machdep file from its contents, not its suffix.
    for accepted in [
        "machdeps/custom.yaml",
        "machdep_arm-none-eabi.YAML",
        "./custom-machdep",
        "/abs/path/to/custom machdep",
    ] {
        assert!(
            validate_project_options(&with_machdep(accepted)).is_ok(),
            "{accepted} is the documented file form and must validate"
        );
    }

    // The one case this test adds. The empty string is already covered by
    // machdep_and_compilation_database_reject_a_leading_dash above.
    assert!(
        validate_project_options(&with_machdep("-machdeps/custom")).is_err(),
        "a machdep path written as a flag must be rejected"
    );

    // A database path is whatever the caller's tree is called. Refusing a space
    // here would be this validator inventing a restriction, not closing one.
    assert!(validate_project_options(&with_compilation_database("my build/compile_commands.json")).is_ok());
}

#[test]
fn an_empty_define_is_rejected() {
    assert!(validate_project_options(&with_defines(&[""])).is_err());
}

/// What makes a file set ineligible for the cached parse record: anything
/// whose bytes reach beyond the files the caller named.
///
/// The scan is deliberately crude and errs toward declining. An include
/// spelled inside a comment or a dead conditional costs a recount; an include
/// missed would let this server claim a count it cannot stand behind.
#[test]
fn a_file_set_that_reaches_past_its_own_bytes_declines_the_cached_record() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let write = |name: &str, body: &str| {
        let path = tmp.path().join(name);
        std::fs::write(&path, body).expect("write fixture");
        path.to_str().expect("utf-8 path").to_string()
    };

    let plain = write("plain.c", "int f(void) { return 0; }\n");
    assert!(!files_may_include(std::slice::from_ref(&plain)));

    for (name, body) in [
        ("direct.c", "#include <stdio.h>\nint f(void) { return 0; }\n"),
        ("local.c", "#include \"own.h\"\nint f(void) { return 0; }\n"),
        ("indented.c", "  #  include <stdio.h>\nint f(void) { return 0; }\n"),
    ] {
        let file = write(name, body);
        assert!(files_may_include(&[file]), "{name} reaches past its bytes");
    }

    // One include anywhere in the set is the whole set.
    let with_include = write("mixed.c", "#include <stdio.h>\n");
    assert!(files_may_include(&[plain.clone(), with_include]));

    // A file that cannot be read is not a file whose bytes are known.
    let missing = tmp.path().join("gone.c").to_str().unwrap().to_string();
    assert!(files_may_include(&[missing]));

    // Any directive, not only an include. "#/**/include" is a legal spelling
    // and telling it from a define needs the line stripped of comments first,
    // so the scan does not try: a define costs a recount it did not need, which
    // is cheaper than a missed include costing a stale claim.
    for name in ["#define N 1\n", "#/**/include <stdio.h>\n", "#if 0\n#endif\n"] {
        let file = write("directive.c", name);
        assert!(files_may_include(&[file]), "{name:?}");
    }
}

/// The digest follows the bytes, so it separates an edit from a re-read and
/// separates two paths that happen to hold the same text.
#[test]
fn the_source_digest_moves_with_the_bytes_and_with_the_names() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("a.c");
    let name = |p: &std::path::Path| p.to_str().expect("utf-8 path").to_string();

    std::fs::write(&path, "int f(void) { return 0; }\n").expect("write");
    let first = loaded_source_digest(&[name(&path)], None);
    assert_eq!(first, loaded_source_digest(&[name(&path)], None), "re-read");

    std::fs::write(&path, "int f(void) { return 1; }\n").expect("rewrite");
    assert_ne!(first, loaded_source_digest(&[name(&path)], None), "edit in place");

    // Same bytes written again is a different state, because an edit and a
    // restore between two reads hash the same and the identity has to see the
    // round trip. Conditional on the write actually moving the modification
    // time, which is the same limit the identity has: a filesystem that stamps
    // both writes identically cannot distinguish them and neither can this.
    let written = |p: &std::path::Path| std::fs::metadata(p).unwrap().modified().unwrap();
    let before = written(&path);
    let restored = loaded_source_digest(&[name(&path)], None);
    std::fs::write(&path, "int f(void) { return 1; }\n").expect("rewrite the same bytes");
    if written(&path) != before {
        assert_ne!(restored, loaded_source_digest(&[name(&path)], None), "rewritten");
    }

    // Same bytes under another name is another file set: Frama-C is handed the
    // path, and the path is what it parses.
    let twin = tmp.path().join("b.c");
    std::fs::copy(&path, &twin).expect("copy");
    assert_ne!(
        loaded_source_digest(&[name(&path)], None),
        loaded_source_digest(&[name(&twin)], None)
    );
}

/// A machdep is in the identity, because Frama-C reads a YAML file there as
/// readily as a builtin name, and those bytes are outside the file set.
///
/// A builtin name is not a path, so it hashes as the failure to open it, which
/// is stable and costs a project that names one nothing. A file that is edited,
/// or that is deleted after the process loaded it, moves the digest, which is
/// what sends the next reload to a new process instead of reusing a record
/// taken under a machine model that is no longer on disk.
#[test]
fn the_machdep_is_part_of_the_parse_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("a.c");
    std::fs::write(&source, "int f(void) { return 0; }\n").expect("write");
    let files = [source.to_str().expect("utf-8 path").to_string()];

    let builtin = loaded_source_digest(&files, Some("gcc_x86_64"));
    assert_eq!(builtin, loaded_source_digest(&files, Some("gcc_x86_64")), "re-read");
    assert_ne!(builtin, loaded_source_digest(&files, None), "no machdep at all");

    let custom = tmp.path().join("custom.yaml");
    std::fs::write(&custom, "machdep:\n  sizeof_int: 4\n").expect("write machdep");
    let custom = custom.to_str().expect("utf-8 path").to_string();
    let loaded = loaded_source_digest(&files, Some(&custom));

    std::fs::write(&custom, "machdep:\n  sizeof_int: 8\n").expect("edit machdep");
    assert_ne!(loaded, loaded_source_digest(&files, Some(&custom)), "edited");

    std::fs::remove_file(&custom).expect("remove machdep");
    assert_ne!(loaded, loaded_source_digest(&files, Some(&custom)), "deleted");
}

#[test]
fn a_missing_header_is_named_in_either_preprocessor_voice() {
    // Taken from a real run, follow-on lines included. Frama-C echoes the whole
    // failed preprocessor command after the diagnostic, and that echo carries
    // "-include prelude.h" and a quoted source path. It is inert here only
    // because it says neither "file not found" nor "No such file or directory",
    // which is a property of the echo rather than of the scan: a widened
    // matcher that keyed on a quoted name, or on ".h" alone, would answer
    // "prelude.h" and send a reader to a header that is present and fine.
    let clang = classify_parse_failure(
        "[kernel] Parsing src/core/sysroot.c (with preprocessing)\n\
         /abs/src/core/sysroot.c:14:10: fatal error: 'sys/mount.h' file not found\n\
            14 | #include <sys/mount.h>\n\
         1 error generated.\n\
         [kernel] User Error: failed to run: gcc -E -C -I. -nostdinc \
         -include prelude.h -include macos-libc.h -Isrc '/abs/src/core/sysroot.c' -o '/tmp/x.i'\n",
    );
    assert_eq!(clang.cause, "header_not_found");
    assert_eq!(clang.subject.as_deref(), Some("sys/mount.h"));

    let gcc = classify_parse_failure(
        "src/fs.c:12:10: fatal error: sys/event.h: No such file or directory\n",
    );
    assert_eq!(gcc.cause, "header_not_found");
    assert_eq!(gcc.subject.as_deref(), Some("sys/event.h"));

    // The hash and the directive may be separated: both forms are legal C and
    // both appear in echoed source, and a literal "#include" match drops them
    // into "other", the bucket that names no cause at all.
    for spelling in ["#include <config>", "# include <config>", "#\tinclude <config>"] {
        let spaced = classify_parse_failure(&format!(
            "src/app.c:4:10: fatal error: 'config' file not found\n    4 | {spelling}\n"
        ));
        assert_eq!(spaced.cause, "header_not_found", "{spelling}");
        assert_eq!(spaced.subject.as_deref(), Some("config"), "{spelling}");
    }

    let extensionless = classify_parse_failure(
        "src/app.c:4:10: fatal error: 'config' file not found\n\
            4 | #include <config>\n",
    );
    assert_eq!(extensionless.cause, "header_not_found");
    assert_eq!(extensionless.subject.as_deref(), Some("config"));
}

#[test]
fn an_unresolved_name_is_told_from_a_missing_header() {
    // The two need different answers: a stub can declare a name as the platform
    // declares it, and cannot model a header Frama-C's libc does not have.
    let block = classify_parse_failure(
        "[kernel] src/sysctl.c:40: user error: Cannot resolve variable KERN_PROC\n",
    );
    assert_eq!(block.cause, "undeclared_name");
    assert_eq!(block.subject.as_deref(), Some("KERN_PROC"));
}

#[test]
fn the_first_cause_wins_over_the_errors_it_causes() {
    // A missing header produces a run of unresolved names after it. Classifying
    // by the last, or by the most frequent, would rank the consequence above
    // the cause and send a reader to write stubs for names that would resolve
    // the moment the header did.
    let block = classify_parse_failure(
        "src/fs.c:12:10: fatal error: 'sys/attr.h' file not found\n\
         [kernel] user error: Cannot resolve variable ATTR_CMN_NAME\n\
         [kernel] user error: Cannot resolve variable ATTR_CMN_OBJTYPE\n",
    );
    assert_eq!(block.cause, "header_not_found");
    assert_eq!(block.subject.as_deref(), Some("sys/attr.h"));
}

#[test]
fn an_unrecognized_failure_quotes_rather_than_guesses() {
    let block = classify_parse_failure(
        "[kernel] src/odd.c:3: user error: syntax error near something new\n",
    );
    assert_eq!(block.cause, "other");
    assert_eq!(block.subject, None);
    assert!(block.message.contains("syntax error"));
}

fn blocked(cause: &'static str, subject: &str) -> ParseProbe {
    ParseProbe::Blocked(ParseBlock {
        cause,
        subject: Some(subject.to_string()),
        message: String::new(),
    })
}

#[test]
fn causes_are_ranked_by_how_many_files_each_blocks() {
    let probed = vec![
        ("a.c".to_string(), blocked("header_not_found", "sys/event.h")),
        ("b.c".to_string(), ParseProbe::Parsed),
        ("c.c".to_string(), blocked("header_not_found", "sys/event.h")),
        ("d.c".to_string(), blocked("undeclared_name", "KERN_PROC")),
        ("e.c".to_string(), blocked("header_not_found", "sys/event.h")),
    ];
    let payload = parse_surface_payload(&probed, false);
    assert_eq!(payload["files_total"], 5);
    assert_eq!(payload["files_parsed"], 1);
    assert_eq!(payload["files_blocked"], 4);

    let ranked = payload["blocked_by"].as_array().unwrap();
    assert_eq!(ranked[0]["subject"], "sys/event.h");
    assert_eq!(ranked[0]["files"], 3);
    assert_eq!(ranked[0]["example"], "a.c");
    assert_eq!(ranked[1]["subject"], "KERN_PROC");
    assert_eq!(ranked[1]["files"], 1);

    // The advice names the largest group and says which kind of gap it is,
    // because a stub answers one of them and cannot answer the other.
    let reason = payload["next_action"]["reason"].as_str().unwrap();
    assert!(reason.contains("sys/event.h"), "{reason}");

    // It must name both readings, since a header missing from the include path
    // and one Frama-C does not model look identical here.
    assert!(reason.contains("include path"), "{reason}");
    assert!(reason.contains("does not model"), "{reason}");

    // The per-file list is what makes this response large on a real tree, so it
    // is the part that waits to be asked for.
    assert!(payload.get("files").is_none());
    assert_eq!(
        parse_surface_payload(&probed, true)["files"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
}

#[test]
fn an_undeclared_name_is_advised_differently_from_a_header() {
    let probed = vec![("a.c".to_string(), blocked("undeclared_name", "KERN_PROC"))];
    let reason = parse_surface_payload(&probed, false)["next_action"]["reason"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(reason.contains("stub answers honestly"), "{reason}");
}

#[test]
fn a_fully_parsing_set_asks_for_nothing() {
    let probed = vec![
        ("a.c".to_string(), ParseProbe::Parsed),
        ("b.c".to_string(), ParseProbe::Parsed),
    ];
    let payload = parse_surface_payload(&probed, false);
    assert_eq!(payload["files_blocked"], 0);
    assert!(payload["blocked_by"].as_array().unwrap().is_empty());
    assert_eq!(payload["next_action"]["tool"], serde_json::Value::Null);
}

/// The producer, not a hand-built probe.
///
/// The payload test below was written first and passed while nothing emitted
/// this cause at all, because it constructs the ParseProbe itself. A test that
/// green-lights absent functionality is worse than no test, so this one calls
/// probe_parse and would fail if the guard were dropped. It needs no Frama-C:
/// the check happens before anything is spawned, which is the point of it.
#[tokio::test]
async fn probe_parse_answers_missing_file_without_spawning() {
    let probe = probe_parse(
        "__frama_c_mcp_missing_binary__",
        &[],
        "/nowhere/definitely-absent.c",
    )
    .await;
    match probe {
        ParseProbe::Blocked(block) => {
            assert_eq!(block.cause, "missing_file");
            assert!(block.message.contains("definitely-absent.c"), "{block:?}");
        }
        other => panic!("expected a missing_file block, got {other:?}"),
    }
}

#[test]
fn a_path_that_is_not_a_file_is_not_reported_as_a_parse_failure() {
    let probed = vec![(
        "/nowhere/absent.c".to_string(),
        ParseProbe::Blocked(ParseBlock {
            cause: "missing_file",
            subject: None,
            message: "/nowhere/absent.c is not a file".to_string(),
        }),
    )];
    let payload = parse_surface_payload(&probed, false);
    let reason = payload["next_action"]["reason"].as_str().unwrap();
    // It must not read as a modeling gap: nothing was measured for this path.
    assert!(reason.contains("not files"), "{reason}");
    assert!(!reason.contains("include path"), "{reason}");
}

/// The two shapes the hand-rolled parser this replaced got wrong.
///
/// It took the first quoted token on the line, which is the heuristic
/// missing_header_name's own doc comment exists to reject: Frama-C forwards a
/// preprocessor diagnostic inside a longer "failed to run" line that also
/// quotes the source and output paths, so the first quote is the compiler's
/// own argument. And it matched "user error" case-sensitively while Frama-C
/// writes "User Error:", which left the branch whose job is to quote what it
/// could not classify returning nothing at all.
#[test]
fn a_header_is_read_off_the_phrase_not_off_the_first_quote() {
    let folded = classify_parse_failure(
        "[kernel] User Error: failed to run: gcc -E '/abs/src/core/sysroot.c' \
         -o '/tmp/x.i': 'sys/mount.h' file not found\n",
    );
    assert_eq!(folded.cause, "header_not_found");
    assert_eq!(folded.subject.as_deref(), Some("sys/mount.h"));

    // Nothing classifiable, and the only diagnostic is capitalized.
    let quoted = classify_parse_failure("[kernel] User Error: something new here\n");
    assert_eq!(quoted.cause, "other");
    assert!(
        quoted.message.contains("something new here"),
        "the message must carry what could not be classified: {quoted:?}"
    );
}

// Frama-C puts the location on the "User Error:" line and the reason on the
// indented lines under it, so quoting one line names nothing. This is the
// branch whose whole job is to say what it could not classify.
#[test]
fn an_unclassified_failure_quotes_the_reason_not_just_the_location() {
    let output = "[kernel] Parsing src/syscall/sys.c (with preprocessing)\n\
                  [kernel] src/syscall/sys.c:86: User Error: \n  \
                  Cannot find field ru_maxrss in type struct rusage\n        \
                  _Static_assert(__builtin_offsetof(struct rusage,ru_maxrss) ==\n";
    let block = frama_c_mcp::mcp::server::project::classify_parse_failure(output);
    assert_eq!(block.cause, "other");
    assert!(block.message.contains("sys.c:86"), "{}", block.message);
    assert!(
        block.message.contains("Cannot find field ru_maxrss"),
        "the reason must survive: {}",
        block.message
    );
}

// The next unindented line is a new message, not more of this one.
#[test]
fn an_unclassified_failure_stops_at_the_next_message() {
    let output = "[kernel] a.c:1: User Error: \n  first reason\n[kernel] b.c:2: User Error: \n  second reason\n";
    let block = frama_c_mcp::mcp::server::project::classify_parse_failure(output);
    assert!(block.message.contains("first reason"), "{}", block.message);
    assert!(!block.message.contains("second reason"), "{}", block.message);
}
