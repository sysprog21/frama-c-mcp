use serde::Deserialize;

use frama_c_mcp::mcp::types::*;

#[derive(Debug, Deserialize)]
struct VecHolder {
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    items: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ValueHolder {
    #[serde(default, deserialize_with = "deserialize_value_or_string")]
    v: Option<serde_json::Value>,
}

fn parse_vec(json: &str) -> Result<Option<Vec<String>>, String> {
    let h: VecHolder = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(h.items)
}

fn parse_value(json: &str) -> Result<Option<serde_json::Value>, String> {
    let h: ValueHolder = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(h.v)
}

#[test]
fn vec_accepts_real_array() {
    assert_eq!(
        parse_vec(r#"{"items": ["a", "b"]}"#).unwrap(),
        Some(vec!["a".to_string(), "b".to_string()])
    );
}

#[test]
fn vec_accepts_stringified_array() {
    assert_eq!(
        parse_vec(r#"{"items": "[\"a\", \"b\"]"}"#).unwrap(),
        Some(vec!["a".to_string(), "b".to_string()])
    );
}

#[test]
fn vec_accepts_empty_string_as_none() {
    assert_eq!(parse_vec(r#"{"items": ""}"#).unwrap(), None);
}

#[test]
fn vec_accepts_null() {
    assert_eq!(parse_vec(r#"{"items": null}"#).unwrap(), None);
}

#[test]
fn vec_accepts_missing() {
    assert_eq!(parse_vec(r#"{}"#).unwrap(), None);
}

#[test]
fn vec_rejects_non_array_string() {
    let err = parse_vec(r#"{"items": "not json"}"#).unwrap_err();
    assert!(err.contains("not valid JSON"), "got: {}", err);
}

#[test]
fn vec_rejects_object_string() {
    let err = parse_vec(r#"{"items": "{}"}"#).unwrap_err();
    assert!(err.contains("not an array"), "got: {}", err);
}

#[test]
fn value_accepts_object() {
    let v = parse_value(r#"{"v": {"k": 1}}"#).unwrap();
    assert_eq!(v, Some(serde_json::json!({"k": 1})));
}

#[test]
fn value_accepts_stringified_object() {
    let v = parse_value(r#"{"v": "{\"k\": 1}"}"#).unwrap();
    assert_eq!(v, Some(serde_json::json!({"k": 1})));
}

#[test]
fn value_accepts_empty_string_as_none() {
    assert_eq!(parse_value(r#"{"v": ""}"#).unwrap(), None);
}

/// pinned takes the stringified array some MCP clients send, like variants.
#[test]
fn pinned_accepts_a_stringified_array() {
    let params: frama_c_mcp::mcp::types::CheckParams = serde_json::from_value(serde_json::json!({
        "pinned": "[{\"predicate\": \"\\\\result >= 0\", \"function\": \"f\"}]",
    }))
    .expect("parses");
    let pins = params.pinned.expect("pins");
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].function.as_deref(), Some("f"));
}

/// A misspelled setting is an error, not a run under defaults. timeout_seconds
/// and parallel are the names a caller reaches for, and run_wp's are timeout
/// and par.
#[test]
fn run_wp_refuses_unknown_fields() {
    use frama_c_mcp::mcp::types::RunWpParams;
    let err = serde_json::from_value::<RunWpParams>(serde_json::json!({
        "timeout_seconds": 30,
    }))
    .expect_err("unknown field must be refused");
    let msg = err.to_string();
    assert!(msg.contains("timeout_seconds"), "{msg}");
    assert!(msg.contains("timeout"), "accepted fields are listed: {msg}");
    serde_json::from_value::<RunWpParams>(serde_json::json!({"timeout": 30, "par": 8}))
        .expect("the real names parse");
}

#[test]
fn check_refuses_unknown_fields() {
    use frama_c_mcp::mcp::types::CheckParams;
    let err = serde_json::from_value::<CheckParams>(serde_json::json!({
        "file": "a.c",
    }))
    .expect_err("`file` is not `files`");
    assert!(err.to_string().contains("file"), "{err}");
}

/// Summary lists three stale markers and full lists twenty; the count beside
/// them covers the rest.
#[test]
fn the_stale_marker_sample_depends_on_detail() {
    use frama_c_mcp::mcp::server::project::stale_marker_sample_size;
    use frama_c_mcp::mcp::types::Detail;
    assert_eq!(stale_marker_sample_size(None), 3);
    assert_eq!(stale_marker_sample_size(Some(Detail::Summary)), 3);
    assert_eq!(stale_marker_sample_size(Some(Detail::Full)), 20);
}

/// The structs nested in a check call refuse unknown fields too: a pin spelled
/// pred would otherwise drop out and weaken what the verdict must contain.
#[test]
fn nested_check_params_refuse_unknown_fields() {
    use frama_c_mcp::mcp::types::CheckParams;
    let pin = serde_json::from_value::<CheckParams>(serde_json::json!({
        "pinned": [{"pred": "x > 0"}]
    }))
    .unwrap_err()
    .to_string();
    assert!(pin.contains("unknown field `pred`"), "{pin}");
    let variant = serde_json::from_value::<CheckParams>(serde_json::json!({
        "variants": [{"define": ["A"]}]
    }))
    .unwrap_err()
    .to_string();
    assert!(variant.contains("define"), "{variant}");
}

/// The server refuses unknown parameters, but the hidden tuning knobs are
/// still accepted, so the published schema must not forbid additional
/// properties: a client that validates against it would reject calls the
/// server takes.
#[test]
fn published_schemas_do_not_forbid_the_hidden_knobs() {
    use frama_c_mcp::mcp::types::{CheckParams, RunWpParams};
    for schema in [schemars::schema_for!(CheckParams), schemars::schema_for!(RunWpParams)] {
        let value = serde_json::to_value(&schema).unwrap();
        assert_ne!(value.get("additionalProperties"), Some(&serde_json::json!(false)), "{value}");
    }
}
