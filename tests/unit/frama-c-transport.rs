use std::io::ErrorKind;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use frama_c_mcp::error::FramaCError;
use frama_c_mcp::frama_c::transport::Transport;

/// A write that dies part-way poisons the transport, and every later frame
/// in either direction fails fast with the reason rather than waiting on
/// the dead peer.
///
/// The peer is closed rather than wedged, because the close is
/// deterministic: on Linux the next write on an AF_UNIX stream whose peer
/// is gone answers EPIPE at once, where a stalled write would need the
/// write timeout and a wall-clock budget. This is the transport half of
/// poison recovery; the session half is in
/// tests/test-transport-poison-recovery.rs.
#[tokio::test]
async fn a_failed_write_poisons_every_later_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("peer-gone.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind");

    let mut transport = Transport::connect(socket.to_str().expect("utf8 path"))
        .await
        .expect("connect to the listener");
    let (peer, _) = listener.accept().await.expect("accept");

    // close(2) is synchronous: once the peer drops, this stream has no
    // other end and the kernel refuses the next write rather than
    // buffering it.
    drop(peer);

    // The failing write reports the kernel's error, not the poison
    // message: poison() returns the error the caller should see, and the
    // fixed text below is for the calls after it.
    let error = transport
        .send_frame("{}")
        .await
        .expect_err("a write whose peer is gone");
    match error {
        FramaCError::Io(error) => {
            assert_eq!(error.kind(), ErrorKind::BrokenPipe, "{error}");
        }
        other => panic!("expected an io error, got {other:?}"),
    }

    assert!(
        transport.poison_flag().load(Ordering::Relaxed),
        "the failed write did not set the flag every later call checks"
    );

    // Both directions answer at once with the reason, and neither waits:
    // recv_frame is handed a budget it must not spend.
    let started = Instant::now();
    let send = transport
        .send_frame("{}")
        .await
        .expect_err("a poisoned transport accepted a frame");
    let recv = transport
        .recv_frame(Duration::from_secs(60))
        .await
        .expect_err("a poisoned transport waited for a frame");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "poisoned calls waited on the socket: {:?}",
        started.elapsed()
    );
    for error in [send, recv] {
        match error {
            FramaCError::Io(error) => assert_eq!(
                error.to_string(),
                "transport poisoned by an incomplete frame write"
            ),
            other => panic!("expected an io error, got {other:?}"),
        }
    }
}

/// A peer that dies while a frame is being waited for poisons the
/// transport exactly like a failed write does: after EOF the stream has
/// no live end, so the flag both session recovery paths gate on must be
/// set on this path too. This is the common crash shape: a server that
/// aborts or is OOM-killed mid-computation is observed by the in-flight
/// read, not by a later write.
#[tokio::test]
async fn a_peer_death_mid_read_poisons_every_later_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("peer-dies-mid-read.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind");

    let mut transport = Transport::connect(socket.to_str().expect("utf8 path"))
        .await
        .expect("connect to the listener");
    let (peer, _) = listener.accept().await.expect("accept");

    // Die while the transport is blocked in read: close(2) makes the
    // pending read answer EOF at once, deterministically.
    drop(peer);

    let error = transport
        .recv_frame(Duration::from_secs(60))
        .await
        .expect_err("a read whose peer is gone");
    match error {
        FramaCError::Io(error) => {
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof, "{error}");
        }
        other => panic!("expected an io error, got {other:?}"),
    }

    assert!(
        transport.poison_flag().load(Ordering::Relaxed),
        "the read-side death did not set the flag recovery gates on"
    );

    // Later frames in both directions fail fast with the reason.
    let started = Instant::now();
    let send = transport
        .send_frame("{}")
        .await
        .expect_err("a poisoned transport accepted a frame");
    let recv = transport
        .recv_frame(Duration::from_secs(60))
        .await
        .expect_err("a poisoned transport waited for a frame");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "poisoned calls waited on the socket: {:?}",
        started.elapsed()
    );
    for error in [send, recv] {
        match error {
            FramaCError::Io(error) => assert_eq!(
                error.to_string(),
                "transport poisoned by an incomplete frame write"
            ),
            other => panic!("expected an io error, got {other:?}"),
        }
    }
}

/// A read that merely times out is routine (the poll loop does this
/// constantly on healthy servers) and must not poison the transport.
#[tokio::test]
async fn a_read_timeout_does_not_poison() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("slow-peer.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind");

    let mut transport = Transport::connect(socket.to_str().expect("utf8 path"))
        .await
        .expect("connect to the listener");
    let (_peer, _) = listener.accept().await.expect("accept");

    // The peer stays open but silent: the read spends its budget and
    // reports no frame, which is not an error and not a death.
    let frame = transport
        .recv_frame(Duration::from_millis(50))
        .await
        .expect("a timeout is not an error");
    assert!(frame.is_none(), "a silent peer sent a frame");
    assert!(
        !transport.poison_flag().load(Ordering::Relaxed),
        "a routine read timeout poisoned the transport"
    );
}
