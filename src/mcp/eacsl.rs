//! Runtime verification through E-ACSL: instrument the loaded program, build
//! it, run it, and report what the assertions did.
//!
//! This is the one path in the server that executes the code under analysis
//! rather than reasoning about it, so it is kept apart from the requests that
//! only read. Everything here spawns something.

use super::*;

/// How much of a child's stdout or stderr is kept. Past this the output is cut
/// and the payload says so, because an instrumented program that fails in a
/// loop can print without bound.
const MAX_E_ACSL_OUTPUT_BYTES: usize = 256 * 1024;

/// What one child process produced, or the payload explaining why there is
/// nothing to read.
enum Captured {
    Ran {
        code: Option<i32>,
        success: bool,
        stdout: String,
        stderr: String,
        truncated: bool,
    },
    /// A spawn failure or a timeout. Already in the shape both steps report,
    /// because neither has anything of its own to add.
    NoOutput(serde_json::Value),
}

/// Run one child to completion under a timeout, capping what it printed.
///
/// The two steps below differ in how they read an exit code, so this returns
/// the raw facts rather than a verdict: the compiler's non-zero exit is an
/// error, while the instrumented program's is metadata, since E-ACSL reports a
/// violation by printing one.
async fn capture(
    mut command: tokio::process::Command,
    command_line: &[String],
    timeout: Duration,
) -> Captured {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    match tokio::time::timeout(timeout, command.output()).await {
        Ok(Ok(output)) => {
            let (stdout, stdout_truncated) =
                capped_lossy_string(&output.stdout, MAX_E_ACSL_OUTPUT_BYTES);
            let (stderr, stderr_truncated) =
                capped_lossy_string(&output.stderr, MAX_E_ACSL_OUTPUT_BYTES);
            Captured::Ran {
                code: output.status.code(),
                success: output.status.success(),
                stdout,
                stderr,
                truncated: stdout_truncated || stderr_truncated,
            }
        }
        Ok(Err(error)) => Captured::NoOutput(json!({
            "status": "error",
            "error": error.to_string(),
            "command": command_line,
            "raw_stdout": null,
            "raw_stderr": null,
            "truncated": false,
        })),
        Err(_) => Captured::NoOutput(json!({
            "status": "timeout",
            "timeout_seconds": timeout.as_secs(),
            "command": command_line,
            "raw_stdout": null,
            "raw_stderr": null,
            "truncated": false,
        })),
    }
}

/// The wrapper to drive, either the one named or whichever is installed.
///
/// Two spellings exist because installs differ. Both defaults are bare names
/// resolved through PATH, but a caller-supplied one is taken verbatim and is
/// handed to Command::new, so this function restricts nothing: it used to claim
/// it could not be pointed at an arbitrary executable, and that is the
/// run_e_acsl tool's guarantee rather than this function's.
///
/// require_known_e_acsl_tool is where the guarantee lives, at the MCP entry
/// point and before the project check. Here the name stays free on purpose,
/// because the only coverage the compile and run legs have is a unit test that
/// drives them with a stub script. Anything else that grows a caller has to
/// call that check first.
fn resolve_wrapper(tool: Option<&str>) -> Result<String, serde_json::Value> {
    tool.map(str::to_string)
        .or_else(|| {
            E_ACSL_WRAPPERS
                .into_iter()
                .find(|name| executable_in_path(name))
                .map(str::to_string)
        })
        .ok_or_else(|| {
            json!({
                "status": "unavailable",
                "reason": "neither e-acsl-gcc nor e-acsl-gcc.sh was found on PATH",
                "manual_tools": E_ACSL_WRAPPERS,
            })
        })
}

/// The wrapper's argument list for this project.
///
/// Err carries the payload for a project this path cannot build, which is a
/// machdep with no compiler equivalent: the answer has to name the boundary
/// rather than compile something that is not the program analyzed.
fn compile_args(
    frama_c_path: &str,
    files: &[String],
    project_options: &ProjectLoadOptions,
    driver: Option<&str>,
    output_exec: &Path,
) -> Result<Vec<String>, serde_json::Value> {
    let mut args = vec![
        "-c".to_string(),
        "-q".to_string(),
        "--assert-print-data".to_string(),
        "-I".to_string(),
        frama_c_path.to_string(),
        "-O".to_string(),
        output_exec.display().to_string(),
    ];

    // -E is what Frama-C preprocesses the sources with and -e is what the C
    // compiler builds the instrumented program with. They get the same defines
    // and include paths: a project that needs a -D to parse needs the same -D
    // to compile, and giving it to only one of them is how instrumentation
    // fails on a project that analyzed cleanly.
    //
    // -nostdinc is the exception, and it goes to the analyzer only. Frama-C's
    // modeled libc exists to be analyzed, not compiled: dropping the real
    // system headers from the gcc behind -e leaves the instrumented program
    // with no stdio, no stdlib and no E-ACSL runtime headers, so a project that
    // loads with nostdinc analyzes cleanly and then fails to build. The
    // -isystem set still goes to both, because a directory the caller named is
    // as likely to be the project's own as it is to be a model.
    if let Some(cpp_flags) = cpp_extra_args(project_options) {
        args.push("-E".to_string());
        args.push(cpp_flags);
    }
    if let Some(compile_flags) = cpp_extra_args(&ProjectLoadOptions {
        nostdinc: false,
        ..project_options.clone()
    }) {
        args.push("-e".to_string());
        args.push(compile_flags);
    }
    if let Some(machdep) = &project_options.machdep {
        match machdep.as_str() {
            "gcc_x86_64" => {
                args.push("--mbits".to_string());
                args.push("64".to_string());
            }
            "gcc_x86_32" => {
                args.push("--mbits".to_string());
                args.push("32".to_string());
            }
            _ => {
                return Err(json!({
                    "status": "unsupported",
                    "reason": format!("run_e_acsl supports runtime execution only for gcc_x86_64/gcc_x86_32 machdep, got {machdep}"),
                    "boundaries": e_acsl_runtime_boundaries(),
                }));
            }
        }
        args.push("-F".to_string());
        args.push(format!("-machdep {machdep}"));
    }
    if let Some(compilation_database) = &project_options.compilation_database {
        args.push("-F".to_string());
        args.push(format!("-compilation-db={compilation_database}"));
    }
    args.extend(files.iter().cloned());
    if let Some(driver) = driver {
        args.push(driver.to_string());
    }
    Ok(args)
}

/// Build the instrumented program.
async fn compile_step(
    tool: &str,
    args: Vec<String>,
    timeout: Duration,
) -> serde_json::Value {
    let mut command = tokio::process::Command::new(tool);
    command.args(&args);

    // After Command::args, which copies into the child's own list, so the
    // vector is free to move into the reported command line.
    let command_line = std::iter::once(tool.to_string())
        .chain(args)
        .collect::<Vec<_>>();
    match capture(command, &command_line, timeout).await {
        Captured::Ran {
            code,
            success,
            stdout,
            stderr,
            truncated,
        } => json!({
            "status": if success { "ok" } else { "error" },
            "code": code,
            "command": command_line,
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "truncated": truncated,
        }),
        Captured::NoOutput(payload) => payload,
    }
}

/// Run the instrumented program.
///
/// The verdict is read off the output rather than the exit code, because an
/// E-ACSL assertion failure prints and aborts, and a program can also exit
/// non-zero for reasons of its own that say nothing about its annotations.
async fn run_step(
    instrumented_exec: &Path,
    program_args: &[String],
    timeout: Duration,
) -> serde_json::Value {
    let command_line = std::iter::once(instrumented_exec.display().to_string())
        .chain(program_args.iter().cloned())
        .collect::<Vec<_>>();
    let mut command = tokio::process::Command::new(instrumented_exec);
    command.args(program_args);
    match capture(command, &command_line, timeout).await {
        Captured::Ran {
            code,
            stdout,
            stderr,
            truncated,
            ..
        } => {
            // Scanned in place. Both buffers run to the output cap, so joining
            // them to answer two substring questions copies half a megabyte on
            // every clean run; the parser below is the only reader that needs
            // them as one string.
            let clean_by_output = ![&stdout, &stderr]
                .iter()
                .any(|text| text.contains("Error:") || text.contains("Aborted"));
            json!({
                "status": if clean_by_output { "clean" } else { "violation" },
                "clean_by_output": clean_by_output,
                "success_criterion": "absence of Error: or Aborted in stdout/stderr; exit code is metadata only",
                "violation": if clean_by_output {
                    serde_json::Value::Null
                } else {
                    parse_e_acsl_violation(&format!("{stdout}\n{stderr}"))
                },
                "code": code,
                "command": command_line,
                "raw_stdout": stdout,
                "raw_stderr": stderr,
                "truncated": truncated,
            })
        }
        Captured::NoOutput(payload) => payload,
    }
}

/// Instrument, build, and run the loaded program, reporting what E-ACSL saw.
///
/// Every exit from here is a payload rather than an error, because "the
/// wrapper is not installed" and "the program aborted on an assertion" are
/// both answers to the question asked.
pub async fn run_e_acsl_counterexample(
    frama_c_path: &str,
    files: &[String],
    project_options: &ProjectLoadOptions,
    driver: Option<&str>,
    program_args: &[String],
    timeout_seconds: u64,
    tool: Option<&str>,
) -> serde_json::Value {
    if files.is_empty() {
        return json!({
            "status": "unavailable",
            "reason": "no source files available",
        });
    }
    let tool = match resolve_wrapper(tool) {
        Ok(tool) => tool,
        Err(payload) => return payload,
    };

    // A random O_EXCL name at mode 0700 rather than pid plus a clock reading.
    // What lands here is a compiled executable this function then runs, so the
    // directory has to be one nobody else can write into, which is why the mode
    // is asked for rather than left to the umask. The guard is bound for the
    // whole call, which is also what removes it.
    let out_dir = match private_temp_dir("frama-c-mcp-e-acsl-") {
        Ok(dir) => dir,
        Err(error) => {
            return json!({
                "status": "error",
                "error": format!("create temp dir: {error}"),
            });
        }
    };
    let output_exec = out_dir.path().join("run");
    let instrumented_exec = PathBuf::from(format!("{}.e-acsl", output_exec.display()));

    let args = match compile_args(
        frama_c_path,
        files,
        project_options,
        driver,
        &output_exec,
    ) {
        Ok(args) => args,
        Err(payload) => return payload,
    };

    let timeout = Duration::from_secs(timeout_seconds.max(1));
    let compile_payload = compile_step(&tool, args, timeout).await;
    if compile_payload["status"] != "ok" {
        return json!({
            "status": "compile_error",
            "compile": compile_payload,
            "run": null,
            "boundaries": e_acsl_runtime_boundaries(),
        });
    }

    // out_dir's guard is dropped when this function returns, on every path,
    // which is what the three hand-written removes here used to do one exit at
    // a time.
    let run_payload = run_step(&instrumented_exec, program_args, timeout).await;

    json!({
        "status": run_payload["status"].clone(),
        "compile": compile_payload,
        "run": run_payload,
        "boundaries": e_acsl_runtime_boundaries(),
    })
}
