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
