use frama_c_mcp::mcp::server::*;

use frama_c_mcp::mcp::server::project::*;

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
