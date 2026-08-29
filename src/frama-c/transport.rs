use bytes::{Buf, BufMut, BytesMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::codec;
use crate::error::FramaCError;

/// Bound on a single frame write. A healthy server drains its socket
/// promptly; if a write stalls past this, the server is wedged. Without a
/// timeout the write blocks while the caller holds the client mutex, which
/// freezes every subsequent request, including the poll loop that is meant
/// to enforce request timeouts.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Transport {
    stream: UnixStream,
    read_buf: BytesMut,
    /// Set when a frame write failed or timed out part-way through, or the
    /// read side saw the peer die (EOF or a read error).
    ///
    /// write_all is not cancellation-safe: the socket may already hold a
    /// prefix of that frame, so the next write would append a fresh frame
    /// onto it and corrupt the length-prefixed protocol for every later
    /// command. Poisoning turns that silent corruption into a fast error
    /// on every later use; recovery is a new Transport, which the session
    /// gets through the respawn path in ensure_main_spawned. Read-side
    /// death poisons too: after EOF the peer is gone for good, and a read
    /// error leaves the stream state unknowable. A read that merely times
    /// out does NOT poison; the poll loop times out routinely on healthy
    /// servers.
    ///
    /// Shared with the FramaCClient that owns this transport, so
    /// ensure_main_spawned can read it without taking the request lock.
    /// It is the last disjunct of the respawn decision there, so the first
    /// reload with files respawns instead of failing in place and marking
    /// the session poisoned for the next caller to find. Sandbox clients
    /// still have no respawn path at all.
    poisoned: Arc<AtomicBool>,
}

impl Transport {
    pub async fn connect(path: &str) -> Result<Self, FramaCError> {
        let stream = UnixStream::connect(path).await?;
        Ok(Transport {
            stream,
            read_buf: BytesMut::with_capacity(8192),
            poisoned: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn send_frame(&mut self, payload: &str) -> Result<(), FramaCError> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(poisoned_transport());
        }
        let frame = codec::encode_frame(payload);
        match tokio::time::timeout(WRITE_TIMEOUT, self.stream.write_all(&frame)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(self.poison(FramaCError::Io(e)).await),
            Err(_) => Err(self.poison(FramaCError::Timeout(WRITE_TIMEOUT)).await),
        }
    }

    pub async fn recv_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<String>, FramaCError> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(poisoned_transport());
        }
        loop {
            if let Some((payload, consumed)) = codec::decode_frame(&self.read_buf)? {
                self.read_buf.advance(consumed);
                return Ok(Some(payload));
            }
            let mut tmp = [0u8; 4096];
            match tokio::time::timeout(timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) => {
                    return Err(self
                        .poison(FramaCError::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "connection closed",
                        )))
                        .await);
                }
                Ok(Ok(n)) => {
                    self.read_buf.put_slice(&tmp[..n]);
                }
                Ok(Err(e)) => return Err(self.poison(FramaCError::Io(e)).await),
                Err(_) => return Ok(None),
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), FramaCError> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Mark the stream unusable and close our end of it, returning the
    /// error the caller should see. Any write that did not run to
    /// completion can have left a partial frame in the socket, and no
    /// later frame may follow it on this stream; a read that ended in EOF
    /// or an error means the peer is gone, which is just as final.
    async fn poison(&mut self, error: FramaCError) -> FramaCError {
        self.poisoned.store(true, Ordering::Relaxed);
        let _ = self.stream.shutdown().await;
        error
    }

    /// A shared handle on the poison flag. The FramaCClient takes one at
    /// connect so it can answer is_poisoned without taking the request
    /// lock that guards this transport.
    pub fn poison_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.poisoned)
    }
}

/// The error every later call gets on a poisoned transport.
fn poisoned_transport() -> FramaCError {
    FramaCError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "transport poisoned by an incomplete frame write",
    ))
}
