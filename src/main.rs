use std::sync::Arc;
use tokio::sync::RwLock;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use frama_c_mcp::check;
use frama_c_mcp::CheckParams;
use frama_c_mcp::mcp::server::FramaCMcpServer;
use frama_c_mcp::state::SessionState;

/// Keeps a session on the initialize lifecycle when the client probes with
/// server/discover first.
///
/// A 2026-07-28 client opens with server/discover and, when the server declines
/// that revision, falls back to initialize on the same stdio session. rmcp
/// commits a session to per-request metadata the moment its first message is
/// not initialize, before the probe is rejected, and never clears it; so the
/// fallback handshake succeeds and then every request without _meta, starting
/// with tools/list, is refused. This server declines 2026-07-28 (see
/// EXCLUDED_PROTOCOL_VERSIONS), so it answers a probe for a declined revision
/// here, with the unsupported-version error rmcp sends for a well-formed one,
/// and rmcp sees initialize first. A probe naming a revision this server does
/// speak is the client choosing that lifecycle, and goes through to rmcp.
struct LegacyLifecycle<T> {
    inner: T,
    initialized: bool,
}

impl<T: rmcp::transport::Transport<rmcp::RoleServer>> rmcp::transport::Transport<rmcp::RoleServer>
    for LegacyLifecycle<T>
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: rmcp::model::ServerJsonRpcMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<rmcp::model::ClientJsonRpcMessage> {
        use rmcp::model::{ClientJsonRpcMessage, ClientRequest, ErrorData, GetMeta};
        loop {
            let msg = self.inner.receive().await?;
            if self.initialized {
                return Some(msg);
            }
            let ClientJsonRpcMessage::Request(req) = &msg else {
                return Some(msg);
            };
            if matches!(req.request, ClientRequest::InitializeRequest(_)) {
                self.initialized = true;
            }
            if !matches!(req.request, ClientRequest::DiscoverRequest(_)) {
                return Some(msg);
            }

            // server/discover exists only in 2026-07-28, so a probe that names
            // no revision is still asking for that one.
            let requested = req
                .request
                .get_meta()
                .protocol_version()
                .unwrap_or(rmcp::model::ProtocolVersion::V_2026_07_28);
            let supported = frama_c_mcp::mcp::server::SUPPORTED_PROTOCOL_VERSIONS;
            if supported.contains(&requested) {
                return Some(msg);
            }
            let error = ErrorData::unsupported_protocol_version(requested, supported);
            let reply = rmcp::model::ServerJsonRpcMessage::error(error, Some(req.id.clone()));

            // A failed write on stdio means the client end is gone. End the
            // session, but say why; forwarding the probe instead would hand
            // rmcp the very message this wrapper exists to keep from it.
            if let Err(error) = self.inner.send(reply).await {
                tracing::warn!("could not answer a declined server/discover probe: {error}");
                return None;
            }
        }
    }

    fn close(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

#[derive(clap::Parser)]
#[command(name = "frama-c-mcp")]
#[command(about = "MCP server for Frama-C formal verification (lazy spawn)")]
struct Cli {
    /// Deprecated and ignored: sockets are now generated per Frama-C spawn as
    /// `/tmp/frama-c-mcp-<pid>-<spawn>.sock`. Still accepted so older
    /// `.mcp.json` files keep working.
    #[arg(long)]
    socket: Option<String>,

    /// Path to the frama-c binary, used for both the main and sandbox
    /// instances.
    #[arg(long, default_value = "frama-c")]
    frama_c: String,

    /// Ceiling on concurrent sandboxes, each of which is a Frama-C process.
    #[arg(long, default_value = "32")]
    max_sandboxes: usize,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run check on a C source file and print JSON.
    Check {
        /// C source file to check.
        file: String,
        /// Keep output machine-readable. Currently the only output mode.
        #[arg(long)]
        json: bool,
        /// Exit non-zero when the JSON payload has non-empty incomplete[].
        #[arg(long = "require-complete")]
        require_complete: bool,
        /// Optional function focus.
        #[arg(long)]
        function: Option<String>,
        /// Also run WP smoke tests and report any smoke goal WP proves.
        #[arg(long)]
        smoke: bool,
        /// Response size: "summary" (default) or "full".
        #[arg(long, value_enum)]
        detail: Option<frama_c_mcp::mcp::types::Detail>,
        /// Include directory passed to Frama-C's preprocessor.
        #[arg(short = 'I', long = "include")]
        include_paths: Vec<String>,
        /// Preprocessor definition as NAME or NAME=VALUE, no leading -D.
        #[arg(short = 'D', long = "define")]
        defines: Vec<String>,
        /// Header force-included ahead of every source, no leading -include.
        #[arg(long = "force-include")]
        force_includes: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    // Manually construct runtime + shutdown_timeout instead of #[tokio::main].
    // tokio stdin uses a blocking-pool thread for sync reads. Runtime Drop can
    // wait forever because that thread is blocked in pipe_read until the parent
    // closes stdin. `shutdown_timeout` lets process shutdown continue after the
    // async Drop chain has dropped MainFramaCState and killed the frama-c
    // child.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async_main());
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    if let Some(sock) = &cli.socket {
        tracing::warn!(
            "--socket {} is deprecated and ignored; sockets are generated per process",
            sock
        );
    }

    if let Some(Command::Check {
        file,
        json: _,
        require_complete,
        function,
        smoke,
        detail,
        include_paths,
        defines,
        force_includes,
    }) = cli.command
    {
        let check = check(
            cli.frama_c,
            cli.max_sandboxes,
            CheckParams {
                files: Some(vec![file]),
                function,
                smoke: smoke.then_some(true),
                detail,
                include_paths: Some(include_paths),
                defines: Some(defines),
                force_includes: Some(force_includes),
                ..Default::default()
            },
        );
        let payload = tokio::select! {
            result = check => result.map_err(|error| anyhow::anyhow!(error.to_string()))?,
            _ = wait_shutdown_signal() => return Err(anyhow::anyhow!("interrupted")),
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        if require_complete
            && payload["incomplete"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        {
            anyhow::bail!("check incomplete");
        }
        return Ok(());
    }

    // Lazy: don't connect frama-c at startup. First reload_project call will
    // ensure_main_spawned() which spawns frama-c + connects client.
    tracing::info!("MCP server starting (lazy spawn mode, frama-c not connected yet)");
    let state = Arc::new(RwLock::new(SessionState::default()));
    let server = FramaCMcpServer::new_lazy(state, cli.frama_c, cli.max_sandboxes);

    // Before `serve`, which takes the server: shutdown needs the registry to
    // kill sandboxes by group, and `kill_on_drop` only ever signals the pid.
    //
    // Nothing to drain if `serve` itself fails: it returns before any tool call
    // can run, so no sandbox exists yet.
    let sandboxes = server.sandbox_registry();
    let main_instance = server.main_frama_c_state();

    let stdio = rmcp::transport::IntoTransport::<rmcp::RoleServer, std::io::Error, _>::into_transport(
        rmcp::transport::io::stdio(),
    );
    let service = server
        .serve(LegacyLifecycle { inner: stdio, initialized: false })
        .await?;
    tracing::info!("MCP server running on stdio");

    // Graceful shutdown: cancel rmcp's service token on SIGTERM/SIGINT/SIGHUP.
    // rmcp's serve_loop observes cancellation, exits, and lets main return so
    // the Drop chain kills MainFramaCState/Sandbox children via kill_on_drop.
    //
    // Do not wrap service.waiting() in an outer tokio::select!: rmcp's inner
    // serve_loop is its own task. Cancelling only the outer await leaves the
    // inner task blocked in transport.receive() (stdin pipe_read), so runtime
    // shutdown deadlocks.
    //
    // Still not covered: SIGKILL/OOM/crash can orphan frama-c because userspace
    // cannot respond to SIGKILL. PR_SET_PDEATHSIG is the kernel-level fix.
    let token = service.cancellation_token();
    tokio::spawn(async move {
        wait_shutdown_signal().await;
        tracing::info!("cancelling MCP service for graceful shutdown");
        token.cancel();
    });

    // Returns QuitReason::Cancelled (we cancel) / Closed (stdin EOF
    // disconnected) / JoinError (internal task panic).
    match service.waiting().await {
        Ok(reason) => tracing::info!("MCP service exited: {:?}", reason),
        Err(e) => tracing::warn!("MCP service exited with error: {}", e),
    }

    // Explicitly, rather than leaving it to the Drop chain. Dropping a sandbox
    // child kills the Frama-C pid and nothing else, so a proof still running
    // leaves its why3server behind; the group kill takes both.
    FramaCMcpServer::kill_live_sandboxes(&sandboxes).await;

    // The main instance needs the same explicit treatment. kill_on_drop reaches
    // Frama-C and not the provers it started, and only when Drop runs at all.
    FramaCMcpServer::kill_main_instance(&main_instance).await;

    Ok(())
}

async fn wait_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!("install SIGTERM handler failed: {}", error);
            return;
        }
    };

    // SIGHUP is sent by the parent shell when a terminal pane closes; handle it
    // to avoid orphans.
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!("install SIGHUP handler failed: {}", error);
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        _ = sighup.recv() => tracing::info!("received SIGHUP"),
    }
}
