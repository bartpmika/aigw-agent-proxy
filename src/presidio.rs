//! Microsoft Presidio (self-hosted PII detection) as a guardrail.
//!
//! - `presidio.analyze`: fails when the analyzer finds the configured entity
//!   types above `score_threshold` (block with a deny guardrail).
//! - `presidio.redact`: replaces what the analyzer finds before content goes
//!   on, using Presidio's anonymizer operators (`replace`, `mask`, `redact`,
//!   `hash`), applied by the proxy.
//!
//! Parameters (all optional except the analyzer URL):
//! `analyzer_url` (or env `PRESIDIO_ANALYZER_URL`), `language` (`en`),
//! `entities` (list; default all), `score_threshold` (0.5), `timeout` (ms,
//! 3000), `operators` (`{ "US_SSN": {"type": "mask", ...}, "DEFAULT": {...} }`,
//! Presidio anonymizer format; default `replace` with `<ENTITY_TYPE>`).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Entity {
    pub kind: String,
    pub value: String,
    pub score: f64,
}

fn analyzer_url(params: &Value) -> Option<String> {
    params["analyzer_url"]
        .as_str()
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("PRESIDIO_ANALYZER_URL").ok().filter(|u| !u.is_empty()))
        .map(|u| u.trim_end_matches('/').to_string())
}

/// Results per (analyzer settings, text): conversation history is resent on
/// every turn, so most texts were analyzed before.
static CACHE: LazyLock<Mutex<HashMap<String, Vec<Entity>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn cache_key(params: &Value, text: &str) -> String {
    let settings = json!([params["analyzer_url"], params["language"], params["entities"], params["score_threshold"]]);
    hex::encode(Sha256::digest(format!("{settings}\u{0}{text}").as_bytes()))
}

/// Calls the analyzer (`POST /analyze`) and returns entities above the threshold.
pub async fn analyze(http: &reqwest::Client, params: &Value, text: &str) -> Result<Vec<Entity>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let key = cache_key(params, text);
    if let Some(hit) = CACHE.lock().unwrap().get(&key) {
        return Ok(hit.clone());
    }
    let url = analyzer_url(params).ok_or("Presidio analyzer URL not configured (analyzer_url or PRESIDIO_ANALYZER_URL)")?;
    let threshold = params["score_threshold"].as_f64().unwrap_or(0.5);
    let mut body = json!({ "text": text, "language": params["language"].as_str().unwrap_or("en"), "score_threshold": threshold });
    if let Some(e) = params["entities"].as_array().filter(|e| !e.is_empty()) {
        body["entities"] = json!(e);
    }
    let timeout = Duration::from_millis(params["timeout"].as_u64().unwrap_or(3000));
    let resp = http.post(format!("{url}/analyze")).json(&body).timeout(timeout).send().await.map_err(|e| format!("Presidio analyzer: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Presidio analyzer: HTTP {}", resp.status()));
    }
    let found: Value = resp.json().await.map_err(|e| format!("Presidio analyzer: {e}"))?;
    // Offsets are in characters (Python string indices).
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    for r in found.as_array().into_iter().flatten() {
        let (Some(start), Some(end)) = (r["start"].as_u64(), r["end"].as_u64()) else { continue };
        let (start, end) = (start as usize, (end as usize).min(chars.len()));
        let score = r["score"].as_f64().unwrap_or(0.0);
        if start >= end || score < threshold {
            continue;
        }
        out.push(Entity { kind: r["entity_type"].as_str().unwrap_or("PII").to_string(), value: chars[start..end].iter().collect(), score });
    }
    let mut cache = CACHE.lock().unwrap();
    if cache.len() > 20_000 {
        cache.clear();
    }
    cache.insert(key, out.clone());
    Ok(out)
}

/// The replacement for one value, per Presidio's anonymizer operators.
pub fn replacement(params: &Value, kind: &str, value: &str) -> String {
    let ops = &params["operators"];
    let op = if ops[kind].is_object() { &ops[kind] } else { &ops["DEFAULT"] };
    match op["type"].as_str().unwrap_or("replace") {
        "redact" => String::new(),
        "mask" => {
            let ch = op["masking_char"].as_str().and_then(|c| c.chars().next()).unwrap_or('*');
            let chars: Vec<char> = value.chars().collect();
            let n = op["chars_to_mask"].as_u64().map(|n| n as usize).unwrap_or(chars.len()).min(chars.len());
            let from_end = op["from_end"].as_bool().unwrap_or(false);
            chars
                .iter()
                .enumerate()
                .map(|(i, c)| if (from_end && i >= chars.len() - n) || (!from_end && i < n) { ch } else { *c })
                .collect()
        }
        "hash" => hex::encode(Sha256::digest(value.as_bytes())),
        _ => op["new_value"].as_str().map(str::to_string).unwrap_or_else(|| format!("<{kind}>")),
    }
}

/// Value -> replacement pairs, longest values first (so a value that contains
/// another is replaced whole).
pub fn redaction_map(params: &Value, entities: &[Entity]) -> Vec<(String, String)> {
    let mut map: Vec<(String, String)> = Vec::new();
    for e in entities {
        if !map.iter().any(|(v, _)| v == &e.value) {
            map.push((e.value.clone(), replacement(params, &e.kind, &e.value)));
        }
    }
    map.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    map
}

/// Replaces values in a plain string.
pub fn replace_all(text: &str, map: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (value, with) in map {
        if out.contains(value.as_str()) {
            out = out.replace(value.as_str(), with);
        }
    }
    out
}

/// Applies replacements to raw bytes of any text format (form data, JSON,
/// HTML). Values are matched as written and JSON-escaped, since JSON bodies
/// carry them inside strings. None if nothing matched.
pub fn apply(bytes: &[u8], map: &[(String, String)]) -> Option<Vec<u8>> {
    if map.is_empty() {
        return None;
    }
    let original = String::from_utf8_lossy(bytes);
    let mut text = replace_all(&original, map);
    for (value, with) in map {
        let escaped = serde_json::to_string(value).unwrap_or_default();
        let escaped = &escaped[1..escaped.len().saturating_sub(1)];
        if escaped != value && text.contains(escaped) {
            let with = serde_json::to_string(with).unwrap_or_default();
            text = text.replace(escaped, &with[1..with.len().saturating_sub(1)]);
        }
    }
    (text != original).then(|| text.into_bytes())
}

/// Redacts a complete SSE body (Anthropic Messages, OpenAI Chat Completions
/// or Responses). A value split across deltas is caught by joining each
/// block's deltas, replacing in the joined text, and putting the result in
/// the block's first delta (the rest become empty).
pub fn redact_sse(body: &[u8], map: &[(String, String)]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut events: Vec<(Vec<String>, Option<Value>)> = text
        .split("\n\n")
        .map(|e| {
            let lines: Vec<String> = e.split('\n').map(str::to_string).collect();
            let data = lines.iter().find_map(|l| l.strip_prefix("data:")).and_then(|d| serde_json::from_str(d.trim_start()).ok());
            (lines, data)
        })
        .collect();
    // Delta pointers per content block, in stream order.
    let mut blocks: Vec<(String, Vec<(usize, String)>)> = Vec::new();
    let mut add = |key: String, at: usize, pointer: String| match blocks.iter_mut().find(|(k, _)| *k == key) {
        Some((_, v)) => v.push((at, pointer)),
        None => blocks.push((key, vec![(at, pointer)])),
    };
    for (i, (_, data)) in events.iter().enumerate() {
        let Some(d) = data else { continue };
        match d["type"].as_str() {
            Some("content_block_delta") => {
                for field in ["text", "partial_json"] {
                    if d["delta"][field].is_string() {
                        add(format!("a{}", d["index"]), i, format!("/delta/{field}"));
                    }
                }
            }
            Some("response.output_text.delta" | "response.function_call_arguments.delta") => {
                add(format!("r{}{}", d["item_id"], d["content_index"]), i, "/delta".into());
            }
            _ => {
                for (c, choice) in d["choices"].as_array().into_iter().flatten().enumerate() {
                    let n = choice["index"].as_u64().unwrap_or(c as u64);
                    if choice["delta"]["content"].is_string() {
                        add(format!("c{n}"), i, format!("/choices/{c}/delta/content"));
                    }
                    for (t, call) in choice["delta"]["tool_calls"].as_array().into_iter().flatten().enumerate() {
                        if call["function"]["arguments"].is_string() {
                            add(format!("t{n}.{}", call["index"]), i, format!("/choices/{c}/delta/tool_calls/{t}/function/arguments"));
                        }
                    }
                }
            }
        }
    }
    let mut changed = vec![false; events.len()];
    for (_, parts) in &blocks {
        let joined: String = parts
            .iter()
            .filter_map(|(i, p)| events[*i].1.as_ref().and_then(|d| d.pointer(p)).and_then(Value::as_str))
            .collect();
        let Some(redacted) = apply(joined.as_bytes(), map) else { continue };
        let redacted = String::from_utf8_lossy(&redacted).into_owned();
        for (n, (i, p)) in parts.iter().enumerate() {
            if let Some(slot) = events[*i].1.as_mut().and_then(|d| d.pointer_mut(p)) {
                *slot = json!(if n == 0 { redacted.as_str() } else { "" });
                changed[*i] = true;
            }
        }
    }
    // Whole values elsewhere (message_start, *.done, response.completed).
    for (i, (_, data)) in events.iter_mut().enumerate() {
        if let Some(d) = data {
            changed[i] |= crate::guardrails::redact_json(d, map);
        }
    }
    events
        .into_iter()
        .zip(changed)
        .map(|((lines, data), changed)| match (changed, data) {
            (true, Some(d)) => lines
                .into_iter()
                .map(|l| if l.starts_with("data:") { format!("data: {d}") } else { l })
                .collect::<Vec<_>>()
                .join("\n"),
            _ => lines.join("\n"),
        })
        .collect::<Vec<_>>()
        .join("\n\n")
        .into_bytes()
}

/// Summary for hook results: count and top score per entity type, never
/// the values.
pub fn summary(entities: &[Entity]) -> Value {
    let mut out = serde_json::Map::new();
    for e in entities {
        let slot = out.entry(e.kind.clone()).or_insert_with(|| json!({ "count": 0, "score": 0.0 }));
        slot["count"] = json!(slot["count"].as_u64().unwrap_or(0) + 1);
        slot["score"] = json!(slot["score"].as_f64().unwrap_or(0.0).max(e.score));
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operators_match_presidio() {
        let p = json!({ "operators": { "US_SSN": { "type": "mask", "masking_char": "#", "chars_to_mask": 7, "from_end": false },
                                        "EMAIL_ADDRESS": { "type": "redact" }, "DEFAULT": { "type": "replace" } } });
        assert_eq!(replacement(&p, "US_SSN", "538-21-4076"), "#######4076");
        assert_eq!(replacement(&p, "EMAIL_ADDRESS", "a@b.co"), "");
        assert_eq!(replacement(&p, "PHONE_NUMBER", "555-0100"), "<PHONE_NUMBER>");
        assert_eq!(replacement(&json!({}), "US_SSN", "x"), "<US_SSN>");
    }

    #[test]
    fn applies_to_json_and_sse() {
        let ents = vec![Entity { kind: "US_SSN".into(), value: "538-21-4076".into(), score: 0.9 },
                        Entity { kind: "PERSON".into(), value: "Jordan \"JJ\" Miller".into(), score: 0.8 }];
        let map = redaction_map(&json!({}), &ents);
        let body = br#"{"messages":[{"role":"user","content":"Jordan \"JJ\" Miller SSN 538-21-4076"}]}"#;
        let out = String::from_utf8(apply(body, &map).unwrap()).unwrap();
        assert_eq!(out, r#"{"messages":[{"role":"user","content":"<PERSON> SSN <US_SSN>"}]}"#);
        assert!(apply(b"nothing here", &map).is_none());
    }

    #[test]
    fn redacts_values_split_across_deltas() {
        let map = vec![("538-21-4076".to_string(), "<US_SSN>".to_string())];
        let delta = |i: u32, t: &str| format!("event: content_block_delta\ndata: {}", json!({"type":"content_block_delta","index":i,"delta":{"type":"text_delta","text":t}}));
        let sse = [delta(0, "SSN is 538-"), delta(0, "21-40"), delta(0, "76."), "event: message_stop\ndata: {\"type\":\"message_stop\"}".into()].join("\n\n") + "\n\n";
        let out = String::from_utf8(redact_sse(sse.as_bytes(), &map)).unwrap();
        assert!(!out.contains("538-") && out.contains("SSN is <US_SSN>."), "{out}");
        assert!(out.ends_with("\n\n") && out.matches("content_block_delta").count() == 6);
        let chat = format!("data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
            json!({"choices":[{"index":0,"delta":{"content":"538-21"}}]}), json!({"choices":[{"index":0,"delta":{"content":"-4076"}}]}));
        let out = String::from_utf8(redact_sse(chat.as_bytes(), &map)).unwrap();
        assert!(out.contains("<US_SSN>") && !out.contains("4076") && out.contains("[DONE]"), "{out}");
    }
}
