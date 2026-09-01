//! How long this server waits, with each wait named once.
//!
//! These were bare Duration literals at their call sites. Several of them are
//! one policy spelled in more than one place, and a policy nothing names is a
//! policy nothing keeps consistent: the drain budget below carried a comment
//! saying it matched the proof budget "above", while the two were separate
//! literals that any edit could pull apart. It is now derived from the value it
//! claims to match, so the claim is enforced rather than asserted.
//!
//! Numbers that are genuinely local to one call are left where they are. This
//! module is for the ones that express a policy, or that are written more than
//! once.

use std::time::Duration;

/// Ceiling on one plugins.wp.startProofs EXEC.
pub const WP_PROOF_BUDGET: Duration = Duration::from_secs(600);

/// Ceiling on the wait for WP to finish, matching the startProofs EXEC budget.
/// Whichever runs out first, the caller learns about it.
pub const WP_DRAIN_BUDGET: Duration = WP_PROOF_BUDGET;

/// Ceiling on one plugins.eva.analysis.compute EXEC. The same number as the WP
/// budget today and for an unrelated reason, so it is its own name: EVA on a
/// large file and WP on a hard goal are not the same wait.
pub const EVA_COMPUTE_BUDGET: Duration = Duration::from_secs(600);

/// Ceiling on kernel.ast.compute, which reparses the project.
pub const AST_COMPUTE_BUDGET: Duration = Duration::from_secs(120);

/// Ceiling on a plugin EXEC that edits or reads annotations. These return as
/// soon as the plug-in answers; the budget is a backstop against a plug-in that
/// never does.
pub const PLUGIN_EXEC_BUDGET: Duration = Duration::from_secs(30);

/// Ceiling on the wait for the self_check probe's throwaway Frama-C to start
/// listening. Its own name rather than the tool probe budget below, which is
/// the same number for an unrelated reason: waiting for a socket and waiting
/// for a command to print its version are not the same wait. Quoted as well as
/// enforced, since the give-up message names it.
pub const PROBE_CONNECT_BUDGET: Duration = Duration::from_secs(5);

/// Ceiling on an external command run only to ask what it is: frama-c -version,
/// opam var switch, why3 config, a --help probe. A tool that cannot answer this
/// quickly is not going to answer at all.
pub const TOOL_PROBE_BUDGET: Duration = Duration::from_secs(5);

/// Ceiling on an external command that does real work: a WP print run, a why3
/// Ceiling on parsing one C file for the parse-surface report.
///
/// The same number as AST_COMPUTE_BUDGET and for the same reason: a probe runs
/// the front end over one translation unit, which is the work that budget
/// covers for a whole project. It is not EXTERNAL_COMMAND_BUDGET, which is for
/// a tool this server shells out to rather than the analyzer itself.
pub const PARSE_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// dump, an e-acsl compile.
pub const EXTERNAL_COMMAND_BUDGET: Duration = Duration::from_secs(60);
