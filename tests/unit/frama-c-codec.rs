
use frama_c_mcp::frama_c::codec::*;

// encode_frame / decode_frame round-trip

#[test]
fn frame_roundtrip_small() {
    let payload = r#"{"cmd":"GET","id":"RQ.0","request":"kernel.ast.getFiles","data":null}"#;
    let frame = encode_frame(payload);
    // S prefix for small payloads
    assert_eq!(frame[0], b'S');
    let decoded = decode_frame(&frame).unwrap().unwrap();
    assert_eq!(decoded.0, payload);
    assert_eq!(decoded.1, frame.len());
}

#[test]
fn frame_roundtrip_large() {
    // Create payload > 0xFFF bytes
    let payload = "x".repeat(0x1000);
    let frame = encode_frame(&payload);
    assert_eq!(frame[0], b'L');
    let decoded = decode_frame(&frame).unwrap().unwrap();
    assert_eq!(decoded.0, payload);
}

#[test]
fn decode_frame_incomplete() {
    // Empty buffer
    assert!(decode_frame(b"").unwrap().is_none());
    // Just prefix, no hex
    assert!(decode_frame(b"S").unwrap().is_none());
    // Header complete but payload incomplete
    assert!(decode_frame(b"S00ahel").unwrap().is_none());
}

#[test]
fn decode_frame_invalid_prefix() {
    let result = decode_frame(b"X000hello");
    assert!(result.is_err());
}

/// An oversized declared length is refused before anything is buffered.
///
/// A W frame carries 15 hex digits, so the wire format allows almost 2^60
/// bytes, and recv_frame reads until the declared payload arrives. Without this
/// the loop had no exit: a wedged or corrupt server grew the read buffer with
/// no diagnostic, which a caller sees as a hang rather than a protocol error.
/// The check has to be on the header, since by the time the payload is short
/// the process has already allocated for it.
#[test]
fn decode_frame_refuses_a_length_it_will_never_honour() {
    // One byte over the cap, declared in a well-formed W header, with no
    // payload behind it at all: the refusal must come off the header.
    let header = format!("W{:015x}", MAX_FRAME_PAYLOAD_BYTES + 1);
    let error = decode_frame(header.as_bytes())
        .expect_err("a length over the cap is a protocol error, not a short read");
    let text = error.to_string();
    assert!(
        text.contains("over the") && text.contains(&MAX_FRAME_PAYLOAD_BYTES.to_string()),
        "the error has to name the limit it enforced: {text}"
    );

    // And the cap is not so tight that a large legitimate frame trips it. A
    // whole-AST printDeclaration runs to tens of megabytes.
    let ok = format!("W{:015x}", 64 * 1024 * 1024);
    assert!(
        decode_frame(ok.as_bytes()).unwrap().is_none(),
        "a 64 MB frame is a short read waiting for its payload, not an error"
    );
}

// encode_command

#[test]
fn encode_get_command() {
    let cmd = FramaCCommand::Get {
        id: "RQ.0".into(),
        request: "kernel.ast.getFiles".into(),
        data: serde_json::Value::Null,
    };
    let json: serde_json::Value = serde_json::from_str(&encode_command(&cmd)).unwrap();
    assert_eq!(json["cmd"], "GET");
    assert_eq!(json["id"], "RQ.0");
    assert_eq!(json["request"], "kernel.ast.getFiles");
    assert!(json["data"].is_null());
}

#[test]
fn encode_poll_command() {
    assert_eq!(encode_command(&FramaCCommand::Poll), "\"POLL\"");
}

#[test]
fn encode_shutdown_command() {
    assert_eq!(encode_command(&FramaCCommand::Shutdown), "\"SHUTDOWN\"");
}

#[test]
fn encode_kill_command() {
    let cmd = FramaCCommand::Kill { id: "RQ.1".into() };
    let json: serde_json::Value = serde_json::from_str(&encode_command(&cmd)).unwrap();
    assert_eq!(json["cmd"], "KILL");
    assert_eq!(json["id"], "RQ.1");
}

// decode_response

#[test]
fn decode_cmdlineoff() {
    let resp = decode_response("\"CMDLINEOFF\"").unwrap();
    assert!(matches!(resp, FramaCResponse::CmdLineOff));
}

#[test]
fn decode_cmdlineon() {
    let resp = decode_response("\"CMDLINEON\"").unwrap();
    assert!(matches!(resp, FramaCResponse::CmdLineOn));
}

#[test]
fn decode_data_response() {
    let json = r#"{"res":"DATA","id":"RQ.0","data":["/tmp/test.c"]}"#;
    let resp = decode_response(json).unwrap();
    match resp {
        FramaCResponse::Data { id, data } => {
            assert_eq!(id, "RQ.0");
            assert_eq!(data, serde_json::json!(["/tmp/test.c"]));
        }
        other => panic!("expected Data, got {other:?}"),
    }
}

#[test]
fn decode_error_response() {
    let json = r#"{"res":"ERROR","id":"RQ.1","msg":"Expected object, got null: null"}"#;
    let resp = decode_response(json).unwrap();
    match resp {
        FramaCResponse::Error { id, msg } => {
            assert_eq!(id, "RQ.1");
            assert_eq!(msg, "Expected object, got null: null");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn decode_signal_response() {
    let json = r#"{"res":"SIGNAL","id":"RQ.2"}"#;
    let resp = decode_response(json).unwrap();
    assert!(matches!(resp, FramaCResponse::Signal { id } if id == "RQ.2"));
}

#[test]
fn decode_rejected_response() {
    let json = r#"{"res":"REJECTED","id":"RQ.3"}"#;
    let resp = decode_response(json).unwrap();
    assert!(matches!(resp, FramaCResponse::Rejected { id } if id == "RQ.3"));
}

#[test]
fn decode_killed_response() {
    let json = r#"{"res":"KILLED","id":"RQ.4"}"#;
    let resp = decode_response(json).unwrap();
    assert!(matches!(resp, FramaCResponse::Killed { id } if id == "RQ.4"));
}

#[test]
fn decode_data_null() {
    let json = r#"{"res":"DATA","id":"RQ.5","data":null}"#;
    let resp = decode_response(json).unwrap();
    match resp {
        FramaCResponse::Data { data, .. } => assert!(data.is_null()),
        other => panic!("expected Data, got {other:?}"),
    }
}

// encode_frame + decode_frame with encode_command

#[test]
fn full_roundtrip_get() {
    let cmd = FramaCCommand::Get {
        id: "RQ.0".into(),
        request: "kernel.ast.getFiles".into(),
        data: serde_json::Value::Null,
    };
    let json = encode_command(&cmd);
    let frame = encode_frame(&json);
    let (decoded_payload, consumed) = decode_frame(&frame).unwrap().unwrap();
    assert_eq!(consumed, frame.len());
    let decoded_resp_value: serde_json::Value =
        serde_json::from_str(&decoded_payload).unwrap();
    assert_eq!(decoded_resp_value["cmd"], "GET");
}

#[test]
fn full_roundtrip_poll() {
    let json = encode_command(&FramaCCommand::Poll);
    let frame = encode_frame(&json);
    let (decoded, _) = decode_frame(&frame).unwrap().unwrap();
    assert_eq!(decoded, "\"POLL\"");
}
