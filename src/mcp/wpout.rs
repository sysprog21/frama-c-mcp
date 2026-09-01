//! Reading what the external tools printed.
//!
//! WP's -wp-print output, why3's session dumps and e-acsl's runtime report are
//! text formats owned by those tools, not by this server. They change when the
//! tool changes, which is a different clock from the MCP surface, so they are
//! parsed in one place rather than inline in the handlers that shell out.

use std::path::Path;
use std::sync::OnceLock;

use serde_json::json;


pub fn parse_proved_goals(output: &str) -> (Option<u64>, Option<u64>) {
    output
        .lines()
        .rev()
        .find_map(|line| {
            let (_, rest) = line.split_once("Proved goals:")?;
            let (proved, total) = rest.split_once('/')?;
            Some((
                proved.trim().parse::<u64>().ok(),
                total
                    .split_whitespace()
                    .next()
                    .and_then(|part| part.parse::<u64>().ok()),
            ))
        })
        .unwrap_or((None, None))
}

pub fn e_acsl_runtime_boundaries() -> serde_json::Value {
    json!({
        "coverage_warning": runtime_check_coverage_warning(),
        "assigns_clauses": "E-ACSL does not prove assigns clauses; use WP for frame conditions.",
        "integer_arithmetic": "ACSL integer arithmetic is checked with unbounded GMP semantics.",
        "executed_paths_only": "A clean run covers only the paths executed by this driver.",
    })
}

pub fn parse_e_acsl_violation(output: &str) -> serde_json::Value {
    // Once, like the others. Cold compared to the acsl.rs pair, kept the same
    // way so there is one shape to recognise rather than two.
    static LOCATION_RE: OnceLock<regex::Regex> = OnceLock::new();
    let location_re = LOCATION_RE
        .get_or_init(|| regex::Regex::new(r"^(.+):(\d+): Error: (.+) failed:$").expect("valid regex"));
    let mut function = None;
    let mut file = None;
    let mut line = None;
    let mut kind = None;
    let mut predicate_lines = Vec::new();
    let mut value_lines = Vec::new();
    let mut in_predicate = false;
    let mut in_values = false;

    for raw_line in output.lines() {
        let trimmed = raw_line.trim();
        if let Some((path, rest)) = trimmed.split_once(": In function '") {
            function = rest.strip_suffix('\'').map(str::to_string);
            file = Some(path.to_string());
            continue;
        }
        if let Some(captures) = location_re.captures(trimmed) {
            file = captures.get(1).map(|m| m.as_str().to_string());
            line = captures
                .get(2)
                .and_then(|m| m.as_str().parse::<u64>().ok());
            kind = captures.get(3).map(|m| m.as_str().to_string());
            in_predicate = false;
            in_values = false;
            continue;
        }
        if trimmed == "The failing predicate is:" {
            in_predicate = true;
            in_values = false;
            continue;
        }
        if trimmed == "With values at failure point:" {
            in_predicate = false;
            in_values = true;
            continue;
        }
        if in_predicate {
            if !trimmed.is_empty() {
                predicate_lines.push(trimmed.trim_end_matches('.').to_string());
            }
        } else if in_values && trimmed.starts_with("- ") {
            value_lines.push(trimmed.trim_start_matches("- ").to_string());
        }
    }

    json!({
        "function": function,
        "file": file,
        "line": line,
        "kind": kind,
        "predicate": predicate_lines.join("\n"),
        "values": value_lines,
    })
}

pub fn capped_lossy_string(bytes: &[u8], max_bytes: usize) -> (String, bool) {
    let truncated = bytes.len() > max_bytes;
    let slice = if truncated { &bytes[..max_bytes] } else { bytes };
    (String::from_utf8_lossy(slice).to_string(), truncated)
}

/// The Why3 dumps under "wp_out/typed", with how many the cap left behind.
///
/// Sorting happens before the cap, not after. The other order takes whatever
/// readdir happened to yield first, so which dumps an agent gets back for one
/// proof depends on directory layout rather than on the goal names, and two
/// runs over the same file can answer differently. Reading the dumps is a step
/// in diagnosing an unproved goal, so a set that shifts under a caller who
/// changed nothing is worse than a set that is short.
///
/// The dropped count is returned rather than discarded for the same reason the
/// per-file "truncated" flag exists: the caller cannot tell a proof with 16
/// dumps from one with 200 by looking at 16 of them.
pub fn collect_why3_dump_files(
    wp_out: &Path,
    max_files: usize,
    max_bytes: u64,
) -> (Vec<serde_json::Value>, usize) {
    let typed_dir = wp_out.join("typed");
    let Ok(entries) = std::fs::read_dir(&typed_dir) else {
        // Zero omitted because there is no total to subtract from, not because
        // the directory was read and found empty. The two are worth telling
        // apart, and the caller can: run_why3_dump reports "not_found" for an
        // empty result, which claims nothing about completeness. The count is
        // only ever a statement about a directory that was read.
        return (Vec::new(), 0);
    };
    let mut dumps = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let file_name = path.file_name()?.to_str()?.to_string();
            if !why3_dump_file_name(&file_name) {
                return None;
            }
            Some((file_name, path))
        })
        .collect::<Vec<_>>();
    dumps.sort_unstable();
    let total = dumps.len();
    dumps.truncate(max_files);

    // Metadata and contents are read after the cap: the files not being
    // reported are not worth an open either.
    let kept = dumps
        .into_iter()
        .filter_map(|(file_name, path)| {
            let size_bytes = std::fs::metadata(&path).ok()?.len();
            let content = if size_bytes <= max_bytes {
                std::fs::read_to_string(&path).ok()
            } else {
                None
            };
            Some(json!({
                "file_name": file_name,
                "path": path,
                "goal_id": why3_dump_goal_id(&file_name),
                "size_bytes": size_bytes,
                "truncated": size_bytes > max_bytes,
                "content": content,
            }))
        })
        .collect::<Vec<_>>();

    // Counted against what the directory held, not against the cap. A stat that
    // fails on a file readdir just listed drops it from the result too, and
    // subtracting only the cap would report a total the payload does not
    // contain, which is the arithmetic this count exists to make honest.
    let omitted = total - kept.len();
    (kept, omitted)
}

pub fn why3_dump_file_name(file_name: &str) -> bool {
    let Some(extension) = file_name.rsplit('.').next() else {
        return false;
    };
    file_name.contains("_Why3_") && matches!(extension, "why" | "psmt2" | "smt2")
}

pub fn why3_dump_goal_id(file_name: &str) -> String {
    let prefix = file_name.split("_Why3_").next().unwrap_or("");
    if prefix.starts_with("typed_") {
        prefix.to_string()
    } else {
        format!("typed_{prefix}")
    }
}

pub fn parse_wp_print_blocks(output: &str) -> Vec<serde_json::Value> {
    let mut blocks = Vec::new();
    let mut function = String::new();
    let mut current: Option<(String, String, Vec<String>)> = None;
    let mut pending_title: Option<(String, String)> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Function ") {
            if let Some((title_function, title)) = pending_title.take() {
                current = Some((title_function, title, Vec::new()));
            }
            if let Some(block) = current.take() {
                blocks.push(wp_print_block_json(block));
            }
            function = rest
                .split(" with behavior ")
                .next()
                .unwrap_or(rest)
                .trim()
                .to_string();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Goal ") {
            if let Some((title_function, title)) = pending_title.take() {
                current = Some((title_function, title, Vec::new()));
            }
            if let Some(block) = current.take() {
                blocks.push(wp_print_block_json(block));
            }
            let title = rest.trim_end_matches(':').trim().to_string();
            if trimmed.ends_with(':') {
                current = Some((function.clone(), title, Vec::new()));
            } else {
                pending_title = Some((function.clone(), title));
            }
            continue;
        }
        if let Some((_, title)) = pending_title.as_mut() {
            // A title WP folded across lines ends at the first line finishing
            // in a colon, and a bare ":" ends it without adding anything to it.
            let title_ends_here = if trimmed == ":" {
                true
            } else if trimmed.is_empty() {
                false
            } else {
                title.push(' ');
                title.push_str(trimmed.trim_end_matches(':').trim());
                trimmed.ends_with(':')
            };

            // Taken once the borrow above has ended. The two take().unwrap()
            // calls that used to sit inside it could not fire, since as_mut had
            // already proved the Some, but they left the reader deriving that
            // before ruling out a panic.
            if let Some((title_function, title)) =
                pending_title.take_if(|_| title_ends_here)
            {
                current = Some((title_function, title, Vec::new()));
            }
            continue;
        }
        // A bare ":" or a rule of dashes is separator rather than body.
        let separator = trimmed == ":" || trimmed.chars().all(|ch| ch == '-');
        if let Some((_, _, body)) = current.as_mut().filter(|_| !separator) {
            body.push(line.to_string());
        }
    }
    if let Some((title_function, title)) = pending_title {
        current = Some((
            title_function,
            title,
            current.map(|(_, _, body)| body).unwrap_or_default(),
        ));
    }
    if let Some(block) = current {
        blocks.push(wp_print_block_json(block));
    }
    blocks
}

pub fn wp_output_warnings(stdout: &str, stderr: &str) -> Vec<String> {
    stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| {
            line.contains("Warning:")
                || line.contains("Allocation, initialization and danglingness not yet implemented")
        })
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.contains("Missing RTE guards"))
        .map(str::to_string)
        .collect()
}

pub fn wp_print_block_json((function, title, body): (String, String, Vec<String>)) -> serde_json::Value {
    let kind = wp_print_kind(&title);
    let mut hypotheses = Vec::new();
    let mut conclusion = Vec::new();
    let mut in_conclusion = false;
    for line in body {
        let trimmed = line.trim();
        if trimmed.starts_with("Prover ") || trimmed.starts_with("[wp") {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Prove:") {
            in_conclusion = true;
            conclusion.push(rest.trim().to_string());
            continue;
        }
        if in_conclusion {
            if trimmed.is_empty() {
                continue;
            }
            conclusion.push(line.trim().to_string());
        } else if !trimmed.is_empty() {
            hypotheses.push(line);
        }
    }
    json!({
        "function": function,
        "title": title,
        "kind": kind,
        "source_line": wp_print_match_line(&title),
        "hypotheses": hypotheses,
        "sections": wp_print_sections(&hypotheses),
        "conclusion": conclusion.join("\n").trim(),
    })
}

pub fn wp_print_kind(title: &str) -> &'static str {
    let text = title.to_ascii_lowercase();
    if text.contains("pre-condition") {
        "requires"
    } else if text.contains("post-condition") {
        "ensures"
    } else if text.contains("assertion") {
        "assert"
    } else if text.contains("loop assigns") {
        "loop_assigns"
    } else if text.contains("assigns") {
        "assigns"
    } else if text.contains("invariant") {
        "loop_invariant"
    } else if text.contains("variant") {
        "loop_variant"
    } else if text.contains("complete behaviors") || text.contains("disjoint behaviors") {
        "behavior"
    } else if text.contains("termination-condition") {
        "termination"
    } else if text.contains("exit-condition") {
        "exit"
    } else {
        "unknown"
    }
}

pub fn wp_print_match_line(title: &str) -> Option<u64> {
    // Each pass consumes what it matched, and the second starts where the first
    // stopped rather than at the title again, so a "lines" run ahead of the
    // last "line" is not picked up a second time as the later match.
    fn collect_after(rest: &mut &str, needle: &str, lines: &mut Vec<u64>) {
        while let Some(index) = rest.find(needle) {
            *rest = &rest[index + needle.len()..];
            let digits = rest
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            if let Ok(line) = digits.parse() {
                lines.push(line);
            }
        }
    }

    let mut lines = Vec::new();
    let mut rest = title;
    collect_after(&mut rest, "line ", &mut lines);
    collect_after(&mut rest, "lines ", &mut lines);
    lines.into_iter().last()
}

pub fn wp_print_sections(hypotheses: &[String]) -> Vec<serde_json::Value> {
    let labels = ["Heap", "Pre-condition", "Invariant", "Then", "Else", "Residual"];
    hypotheses
        .iter()
        .filter_map(|line| {
            let trimmed = line.trim();
            labels.iter().find_map(|label| {
                if trimmed == format!("(* {label} *)") || trimmed == format!("{label} {{") {
                    return Some(json!({"label": label, "text": ""}));
                }
                trimmed.strip_prefix(&format!("{label}:")).map(|text| {
                    json!({
                        "label": label,
                        "text": text.trim(),
                    })
                })
            })
        })
        .collect()
}

pub fn attach_wp_print_blocks(vcs: &mut [serde_json::Value], blocks: &[serde_json::Value]) {
    for vc in vcs {
        let Some(function) = vc.get("function").and_then(|value| value.as_str()) else {
            continue;
        };
        let kind = vc_wp_print_kind(vc);
        let line = vc_source_line(vc);
        let same_kind = blocks
            .iter()
            .filter(|block| {
                block.get("function").and_then(|value| value.as_str()) == Some(function)
                    && block.get("kind").and_then(|value| value.as_str()) == Some(kind)
            })
            .collect::<Vec<_>>();
        let candidates = if let Some(line) = line {
            same_kind
                .iter()
                .copied()
                .filter(|block| {
                    block.get("source_line").and_then(|value| value.as_u64()) == Some(line)
                })
                .collect::<Vec<_>>()
        } else {
            same_kind
        };
        if candidates.len() == 1 {
            if let Some(obj) = vc.as_object_mut() {
                obj.insert("wp_print".to_string(), (*candidates[0]).clone());
            }
        }
    }
}

pub fn attach_why3_dumps(vcs: &mut [serde_json::Value], dumps: &[serde_json::Value]) {
    for vc in vcs {
        let ids = ["wpo_id", "wpo", "stable_goal_id"]
            .iter()
            .filter_map(|field| vc.get(field).and_then(|value| value.as_str()))
            .flat_map(|id| [id.to_string(), id.trim_start_matches("typed_").to_string()])
            .collect::<Vec<_>>();
        let matches = dumps
            .iter()
            .filter(|dump| {
                dump.get("goal_id")
                    .and_then(|value| value.as_str())
                    .is_some_and(|goal_id| {
                        ids.iter().any(|id| {
                            id == goal_id || id == goal_id.trim_start_matches("typed_")
                        })
                    })
            })
            .collect::<Vec<_>>();
        if !matches.is_empty() {
            if let Some(obj) = vc.as_object_mut() {
                obj.insert("why3_dumps".to_string(), json!(matches));
            }
        }
    }
}

pub fn vc_wp_print_kind(vc: &serde_json::Value) -> &str {
    if let Some(goal_kind) = vc.get("goal_kind").and_then(|value| value.as_str()) {
        if goal_kind == "user_assert" || goal_kind.starts_with("rte_") {
            return "assert";
        }
    }
    vc.get("related_acsl_clause")
        .or_else(|| vc.get("clause"))
        .and_then(|clause| clause.get("kind"))
        .and_then(|value| value.as_str())
        .map(|kind| match kind {
            "requires" | "ensures" | "assigns" => kind,
            "loop_invariant" | "loop_assigns" | "loop_variant" => kind,
            "complete" | "disjoint" | "behavior" => "behavior",
            "assert" | "assertion" => "assert",
            _ => "unknown",
        })
        .unwrap_or("unknown")
}

pub fn vc_source_line(vc: &serde_json::Value) -> Option<u64> {
    vc.get("source_location")
        .and_then(|loc| loc.get("line"))
        .and_then(|value| value.as_u64())
        .or_else(|| {
            vc.get("related_acsl_clause")
                .or_else(|| vc.get("clause"))
                .and_then(|clause| clause.get("loc"))
                .and_then(|loc| loc.get("line"))
                .and_then(|value| value.as_u64())
        })
}

pub fn runtime_check_coverage_warning() -> &'static str {
    "Runtime checks cover only executed paths and do not validate assigns clauses."
}
