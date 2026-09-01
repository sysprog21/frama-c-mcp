use crate::error::FramaCError;

/// Client command sent to Frama-C Server.
#[derive(Debug, Clone)]
pub enum FramaCCommand {
    Get { id: String, request: String, data: serde_json::Value },
    Set { id: String, request: String, data: serde_json::Value },
    Exec { id: String, request: String, data: serde_json::Value },
    Poll,
    Shutdown,
    Kill { id: String },
    SigOn { id: String },
    SigOff { id: String },
}

/// Server response from Frama-C Server.
#[derive(Debug, Clone)]
pub enum FramaCResponse {
    Data { id: String, data: serde_json::Value },
    Error { id: String, msg: String },
    Signal { id: String },
    Rejected { id: String },
    Killed { id: String },
    CmdLineOn,
    CmdLineOff,
}

/// Encode a payload string into a Frama-C Server protocol frame.
///
/// Frame format: `S` + 3 hex digits (≤ 0xFFF bytes),
/// `L` + 7 hex digits (≤ 0xFFFFFFF bytes), or `W` + 15 hex digits.
/// Hex digits are lowercase to match OCaml `Printf.sprintf "%03x"`.
pub fn encode_frame(payload: &str) -> Vec<u8> {
    let len = payload.len();
    let header = if len <= 0xFFF {
        format!("S{:03x}", len)
    } else if len <= 0xFFF_FFFF {
        format!("L{:07x}", len)
    } else {
        format!("W{:015x}", len)
    };
    let mut buf = Vec::with_capacity(header.len() + len);
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(payload.as_bytes());
    buf
}

/// The largest frame this client will accept from the server.
///
/// A W frame declares its length in 15 hex digits, so the wire format allows
/// almost 2^60 bytes, and recv_frame keeps reading until the declared payload
/// arrives. Nothing bounded that: a Frama-C that wedged mid-frame, or wrote a
/// corrupt header, grew this process's read buffer without limit and with no
/// diagnostic, which reads as a hang rather than as the protocol error it is.
///
/// 256 MB rather than something tighter, because a legitimate frame here can
/// be large: fetchFunctions over a whole kernel tree and printDeclaration on a
/// big AST both run to tens of megabytes, and a cap that clips a real payload
/// would be a worse bug than the one it prevents. Every other output path in
/// this tree is capped too, at 256 KB for the e-acsl and why3 readers, which
/// are reading tool output rather than the AST.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Try to decode one complete frame from a byte buffer.
///
/// Returns `Ok(Some((payload, consumed)))` on success,
/// `Ok(None)` if the buffer is incomplete, or `Err` on format error.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(String, usize)>, FramaCError> {
    if buf.is_empty() {
        return Ok(None);
    }

    let hex_len = match buf[0] {
        b'S' => 3,
        b'L' => 7,
        b'W' => 15,
        other => {
            return Err(FramaCError::InvalidFrame(format!(
                "unexpected frame prefix byte: 0x{:02x}",
                other
            )));
        }
    };

    let header_len = 1 + hex_len;
    if buf.len() < header_len {
        return Ok(None);
    }

    let hex_str = std::str::from_utf8(&buf[1..header_len]).map_err(|e| {
        FramaCError::InvalidFrame(format!("invalid UTF-8 in frame header: {e}"))
    })?;

    let payload_len = usize::from_str_radix(hex_str, 16).map_err(|e| {
        FramaCError::InvalidFrame(format!("invalid hex in frame header '{hex_str}': {e}"))
    })?;

    // Refused here rather than after buffering, which is the whole point: the
    // caller reads until the declared length arrives, so a length it will never
    // honour has to be an error before the first read and not after the last.
    if payload_len > MAX_FRAME_PAYLOAD_BYTES {
        return Err(FramaCError::InvalidFrame(format!(
            "frame declares {payload_len} bytes, over the {MAX_FRAME_PAYLOAD_BYTES} \
             byte limit; the server is out of sync or the header is corrupt"
        )));
    }

    let total = header_len + payload_len;
    if buf.len() < total {
        return Ok(None);
    }

    let payload = std::str::from_utf8(&buf[header_len..total]).map_err(|e| {
        FramaCError::InvalidFrame(format!("invalid UTF-8 in frame payload: {e}"))
    })?;

    Ok(Some((payload.to_string(), total)))
}

/// Serialize a `FramaCCommand` to a JSON string.
///
/// GET/SET/EXEC produce JSON objects with `cmd`, `id`, `request`, `data`
/// fields.
/// POLL and SHUTDOWN produce JSON string literals `"POLL"` and `"SHUTDOWN"`.
pub fn encode_command(cmd: &FramaCCommand) -> String {
    match cmd {
        FramaCCommand::Get { id, request, data } => {
            serde_json::json!({
                "cmd": "GET", "id": id, "request": request, "data": data
            })
            .to_string()
        }
        FramaCCommand::Set { id, request, data } => {
            serde_json::json!({
                "cmd": "SET", "id": id, "request": request, "data": data
            })
            .to_string()
        }
        FramaCCommand::Exec { id, request, data } => {
            serde_json::json!({
                "cmd": "EXEC", "id": id, "request": request, "data": data
            })
            .to_string()
        }
        FramaCCommand::Poll => "\"POLL\"".to_string(),
        FramaCCommand::Shutdown => "\"SHUTDOWN\"".to_string(),
        FramaCCommand::Kill { id } => {
            serde_json::json!({"cmd": "KILL", "id": id}).to_string()
        }
        FramaCCommand::SigOn { id } => {
            serde_json::json!({"cmd": "SIGON", "id": id}).to_string()
        }
        FramaCCommand::SigOff { id } => {
            serde_json::json!({"cmd": "SIGOFF", "id": id}).to_string()
        }
    }
}

/// Deserialize a JSON string into a `FramaCResponse`.
///
/// Handles both string responses (CMDLINEON/CMDLINEOFF) and
/// object responses (DATA/ERROR/SIGNAL/REJECTED/KILLED).
pub fn decode_response(json_str: &str) -> Result<FramaCResponse, FramaCError> {
    let value: serde_json::Value = serde_json::from_str(json_str)?;

    if let Some(s) = value.as_str() {
        return match s {
            "CMDLINEON" => Ok(FramaCResponse::CmdLineOn),
            "CMDLINEOFF" => Ok(FramaCResponse::CmdLineOff),
            other => Err(FramaCError::UnexpectedResponse(format!(
                "unknown string response: {other}"
            ))),
        };
    }

    if let Some(obj) = value.as_object() {
        let res = obj
            .get("res")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        return match res {
            "DATA" => Ok(FramaCResponse::Data {
                id,
                data: obj.get("data").cloned().unwrap_or(serde_json::Value::Null),
            }),
            "ERROR" => Ok(FramaCResponse::Error {
                id,
                msg: obj
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }),
            "SIGNAL" => Ok(FramaCResponse::Signal { id }),
            "REJECTED" => Ok(FramaCResponse::Rejected { id }),
            "KILLED" => Ok(FramaCResponse::Killed { id }),
            other => Err(FramaCError::UnexpectedResponse(format!(
                "unknown res type: {other}"
            ))),
        };
    }

    Err(FramaCError::UnexpectedResponse(format!(
        "expected string or object, got: {value}"
    )))
}
