//! A server with no Frama-C behind it, for tests that only exercise payload
//! logic.
//!
//! One definition, included by every unit module that needs one. There were
//! five, in unit/server.rs, unit/check-gaps.rs and unit/wp-classify.rs, each
//! repeating the same Arc/RwLock/SessionState construction and the same
//! sentinel binary name. The name matters: it has to be a path that cannot
//! exist, and five copies of that promise are five chances to spell one of
//! them as something that does.
#![allow(dead_code)]

use std::sync::Arc;
use tokio::sync::RwLock;

use frama_c_mcp::mcp::server::FramaCMcpServer;
use frama_c_mcp::state::SessionState;

/// The path no binary is installed at, for a server that must not spawn one.
pub const MISSING_FRAMA_C: &str = "__frama_c_mcp_missing_binary__";

/// A lazily-spawning server over an empty session, pointed at `frama_c`.
///
/// Lazy is what makes this cheap: nothing is started until a call needs a
/// client, so a test that only reads payloads never pays for a process.
pub fn lazy_server(frama_c: impl Into<String>) -> FramaCMcpServer {
    FramaCMcpServer::new_lazy(
        Arc::new(RwLock::new(SessionState::default())),
        frama_c.into(),
        4,
    )
}
