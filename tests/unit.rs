//! The library's unit tests.
//!
//! One integration target rather than eleven, so CI names one step and the
//! guard tests that pair this directory with the workflow have one row to
//! agree on. The parts live under tests/unit/ because cargo makes a target of
//! every .rs directly under tests/ and none of the ones below it.
//!
//! Every module needs an explicit path: this file is a target root, so its
//! module directory is tests/ rather than tests/unit/.

#[path = "unit/acsl-shapes.rs"]
mod acsl_shapes;
#[path = "unit/check-gaps.rs"]
mod check_gaps;
#[path = "unit/repo-guards.rs"]
mod repo_guards;
#[path = "unit/wp-classify.rs"]
mod wp_classify;
#[path = "unit/annotations.rs"]
mod annotations;
#[path = "unit/error.rs"]
mod error;
#[path = "unit/project.rs"]
mod project;
#[path = "unit/propose.rs"]
mod propose;
#[path = "unit/server.rs"]
mod server;
#[path = "unit/state.rs"]
mod state;
#[path = "unit/status.rs"]
mod status;
#[path = "unit/topo.rs"]
mod topo;
#[path = "unit/types.rs"]
mod types;
#[path = "unit/frama-c-client.rs"]
mod frama_c_client;
#[path = "unit/frama-c-codec.rs"]
mod frama_c_codec;
#[path = "unit/frama-c-transport.rs"]
mod frama_c_transport;
