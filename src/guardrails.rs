//! Guardrails: checks run on the request (input) or the complete response
//! (output). Supported checks: default.regexMatch, default.contains,
//! panw-prisma-airs.intercept, presidio.analyze, and the transform
//! presidio.redact (see `redact`). Unknown checks pass with an error recorded.

use crate::control_plane::{ControlPlane, KeyDetails};
use crate::presidio;
use crate::providers::Endpoint;
use regex::Regex;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const AIRS_URL: &str = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Stage {
    Input,
    Output,
}

#[derive(Debug, Default)]
pub struct Outcome {
    /// A failing guardrail with `deny: true`: block the request/response.
    pub denied: bool,
    /// Any guardrail failed (with or without deny).
    pub any_failed: bool,
    /// Hook results, for logs.
    pub results: Vec<Value>,
}

/// A guardrail resolved from the control plane (slug + record).
#[derive(Debug, Clone)]
pub struct Guardrail {
    pub slug: String,
    pub record: Value,
}

fn join_texts(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i["text"].as_str())
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Removes `<system-reminder>…</system-reminder>` blocks: context Claude Code
/// adds around every prompt (instructions, CLAUDE.md, environment). They are
/// the agent's own text, and their bulk hides the user's content from
/// detectors such as AIRS DLP.
pub fn strip_agent_context(text: &str) -> String {
    const OPEN: &str = "<system-reminder>";
    const CLOSE: &str = "</system-reminder>";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        match rest[start..].find(CLOSE) {
            Some(end) => rest = &rest[start + end + CLOSE.len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out.split('\n').map(str::trim_end).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

/// Text a guardrail sees in a request (last message for chat-style APIs).
pub fn request_text(endpoint: Endpoint, body: &Value) -> String {
    match endpoint {
        // The last *user* message: agents can put a system message after it
        // (Claude Code appends its environment as a trailing system message).
        Endpoint::Messages | Endpoint::ChatCompletions => body["messages"]
            .as_array()
            .and_then(|m| m.iter().rev().find(|m| m["role"] == "user").or(m.last()))
            .map(|m| strip_agent_context(&join_texts(&m["content"])))
            .unwrap_or_default(),
        Endpoint::Completions | Endpoint::Complete => join_texts(&body["prompt"]),
        Endpoint::Embeddings => match &body["input"] {
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"),
            v => v.as_str().unwrap_or("").to_string(),
        },
        Endpoint::Responses => match &body["input"] {
            Value::String(s) => s.clone(),
            Value::Array(items) => items
                .iter()
                .map(|i| match &i["content"] {
                    Value::String(s) => s.clone(),
                    Value::Array(parts) => parts
                        .iter()
                        .filter(|p| matches!(p["type"].as_str(), Some("input_text" | "text")))
                        .filter_map(|p| p["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                    _ => i["output"].as_str().unwrap_or("").to_string(),
                })
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        },
        Endpoint::CountTokens => String::new(),
    }
}

/// Text a guardrail sees in a complete response, including tool-call inputs
/// and thinking, so content written into files is scanned too.
pub fn response_text(endpoint: Endpoint, body: &Value) -> String {
    match endpoint {
        Endpoint::Messages | Endpoint::Complete => {
            if let Some(blocks) = body["content"].as_array() {
                blocks
                    .iter()
                    .map(|b| match b["type"].as_str() {
                        Some("tool_use") => b["input"].to_string(),
                        Some("thinking") => b["thinking"].as_str().unwrap_or("").to_string(),
                        _ => b["text"].as_str().unwrap_or("").to_string(),
                    })
                    .filter(|t| !t.is_empty() && t != "{}")
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                body["completion"].as_str().unwrap_or("").to_string()
            }
        }
        Endpoint::ChatCompletions | Endpoint::Completions => {
            let choice = &body["choices"][0];
            let mut parts = vec![choice["message"]["content"]
                .as_str()
                .or(choice["text"].as_str())
                .unwrap_or("")
                .to_string()];
            if let Some(calls) = choice["message"]["tool_calls"].as_array() {
                parts.extend(calls.iter().filter_map(|c| c["function"]["arguments"].as_str().map(str::to_string)));
            }
            parts.retain(|p| !p.is_empty());
            parts.join("\n")
        }
        Endpoint::Responses => body["output"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .flat_map(|i| {
                        let mut t: Vec<String> = i["content"]
                            .as_array()
                            .map(|c| c.iter().filter_map(|p| p["text"].as_str().map(str::to_string)).collect())
                            .unwrap_or_default();
                        if let Some(args) = i["arguments"].as_str() {
                            t.push(args.to_string());
                        }
                        t
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        Endpoint::Embeddings | Endpoint::CountTokens => String::new(),
    }
}

pub struct CheckEnv<'a> {
    pub http: &'a reqwest::Client,
    pub control_plane: &'a ControlPlane,
    pub key: &'a KeyDetails,
    pub api_key: &'a str,
    pub trace_id: &'a str,
    pub airs_api_key: Option<&'a str>,
}

/// Runs guardrails for one stage. Skips work when there is no text.
pub async fn run(guardrails: &[Guardrail], stage: Stage, text: &str, env: &CheckEnv<'_>) -> Outcome {
    let mut outcome = Outcome::default();
    if guardrails.is_empty() || text.is_empty() {
        return outcome;
    }
    // Guardrails with only transforms have nothing to verify here.
    let detects = |g: &&Guardrail| {
        g.record["checks"].as_array().into_iter().flatten().any(|c| c["id"] != REDACT_CHECK && c["is_enabled"] != json!(false))
    };
    let futures = guardrails.iter().filter(detects).map(|g| run_guardrail(g, stage, text, env));
    for (verdict, deny, result) in futures_util::future::join_all(futures).await {
        if !verdict {
            outcome.any_failed = true;
            outcome.denied |= deny;
        }
        outcome.results.push(result);
    }
    outcome
}

async fn run_guardrail(g: &Guardrail, stage: Stage, text: &str, env: &CheckEnv<'_>) -> (bool, bool, Value) {
    let started = Instant::now();
    let deny = g.record["actions"]["deny"].as_bool().unwrap_or(false);
    let mut checks = Vec::new();
    let mut verdict = true;
    for check in g.record["checks"].as_array().cloned().unwrap_or_default() {
        let id = check["id"].as_str().unwrap_or("").to_string();
        // Transforms run separately (`redact`) and never fail a guardrail.
        if check["is_enabled"] == json!(false) || id == REDACT_CHECK {
            continue;
        }
        let params = &check["parameters"];
        let fail_on_error = params["failOnError"].as_bool().unwrap_or(false);
        let check_started = Instant::now();
        let (check_verdict, data, error) = run_check(&id, params, stage, text, env).await;
        // A check that errors counts as passing unless failOnError is set.
        verdict &= check_verdict || (error.is_some() && !fail_on_error);
        checks.push(json!({
            "id": id,
            "verdict": check_verdict,
            "data": data,
            "error": error.map(|e| json!({ "message": e })),
            "execution_time": check_started.elapsed().as_millis() as u64,
            "fail_on_error": fail_on_error,
        }));
    }
    let result = json!({
        "id": g.slug,
        "verdict": verdict,
        "deny": deny,
        "async": false,
        "type": "guardrail",
        "checks": checks,
        "execution_time": started.elapsed().as_millis() as u64,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    (verdict, deny, result)
}

async fn run_check(id: &str, params: &Value, stage: Stage, text: &str, env: &CheckEnv<'_>) -> (bool, Value, Option<String>) {
    match id {
        "default.regexMatch" => {
            let Some(rule) = params["rule"].as_str() else {
                return (false, Value::Null, Some("Missing regex pattern".into()));
            };
            let not = params["not"].as_bool().unwrap_or(false);
            match Regex::new(rule) {
                Ok(re) => {
                    let matched = re.is_match(text);
                    let verdict = if not { !matched } else { matched };
                    (verdict, json!({ "regexPattern": rule, "not": not, "verdict": verdict }), None)
                }
                Err(e) => (false, Value::Null, Some(format!("invalid regex: {e}"))),
            }
        }
        "default.contains" => {
            let words: Vec<String> = params["words"]
                .as_array()
                .map(|w| w.iter().filter_map(|x| x.as_str().map(str::to_lowercase)).collect())
                .unwrap_or_default();
            let lower = text.to_lowercase();
            let found = words.iter().filter(|w| lower.contains(w.as_str())).count();
            let verdict = match params["operator"].as_str().unwrap_or("any") {
                "all" => found == words.len(),
                "none" => found == 0,
                _ => found > 0,
            };
            (verdict, json!({ "found": found, "verdict": verdict }), None)
        }
        "panw-prisma-airs.intercept" => airs_scan(params, stage, text, env).await,
        "presidio.analyze" => match presidio::analyze(env.http, params, text).await {
            Ok(found) => (found.is_empty(), json!({ "entities": presidio::summary(&found), "verdict": found.is_empty() }), None),
            Err(e) => (false, Value::Null, Some(e)),
        },
        other => (true, Value::Null, Some(format!("unsupported check: {other}"))),
    }
}

const REDACT_CHECK: &str = "presidio.redact";

/// Keys whose string values are content: prompts, tool results, model
/// output, stream deltas. Tool arguments (`input`/`arguments` objects, MCP
/// `structuredContent`) are content throughout.
const TEXT_KEYS: &[&str] = &["text", "content", "input", "output", "arguments", "prompt", "partial_json", "delta", "query"];
const ARG_KEYS: &[&str] = &["input", "arguments", "structuredContent"];
/// Never content: system prompts, tool definitions, and fields that clients
/// or providers verify (thinking signatures).
const SKIP_KEYS: &[&str] = &["system", "instructions", "tools", "tool_choice", "metadata", "thinking", "signature", "redacted_thinking"];

/// Visits every content string in a JSON body, skipping system/developer
/// messages.
fn visit_content(v: &mut Value, key: Option<&str>, in_args: bool, f: &mut dyn FnMut(&mut String)) {
    match v {
        Value::String(s) if in_args || key.is_some_and(|k| TEXT_KEYS.contains(&k)) => f(s),
        Value::Array(items) => items.iter_mut().for_each(|i| visit_content(i, key, in_args, f)),
        Value::Object(map) => {
            if !in_args && matches!(map.get("role").and_then(Value::as_str), Some("system" | "developer")) {
                return;
            }
            for (k, child) in map.iter_mut() {
                if !in_args && SKIP_KEYS.contains(&k.as_str()) {
                    continue;
                }
                let args = in_args || (ARG_KEYS.contains(&k.as_str()) && child.is_object());
                visit_content(child, Some(k), args, f);
            }
        }
        _ => {}
    }
}

/// Content strings of a JSON body, for analysis.
pub fn content_strings(body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    visit_content(&mut body.clone(), None, false, &mut |s| out.push(s.clone()));
    out
}

/// Replaces values in the content strings of a JSON body. True if changed.
pub fn redact_json(body: &mut Value, map: &[(String, String)]) -> bool {
    let mut changed = false;
    visit_content(body, None, false, &mut |s| {
        let r = presidio::replace_all(s, map);
        if r != *s {
            *s = r;
            changed = true;
        }
    });
    changed
}

/// What `redact` found: value -> replacement pairs, and hook results for logs.
#[derive(Debug, Default)]
pub struct Redaction {
    pub map: Vec<(String, String)>,
    pub results: Vec<Value>,
}

impl Redaction {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Guardrails that have a redact transform for this check set.
pub fn has_redact(guardrails: &[Guardrail]) -> bool {
    guardrails.iter().any(|g| redact_checks(g).next().is_some())
}

fn redact_checks(g: &Guardrail) -> impl Iterator<Item = &Value> {
    g.record["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["id"] == REDACT_CHECK && c["is_enabled"] != json!(false))
        .map(|c| &c["parameters"])
}

/// Runs the guardrails' `presidio.redact` checks over texts and returns what
/// to replace. An analyzer error leaves content unredacted unless the check
/// sets `failOnError`, which then blocks (`Err`).
pub async fn redact(guardrails: &[Guardrail], texts: &[String], env: &CheckEnv<'_>) -> Result<Redaction, Redaction> {
    let mut out = Redaction::default();
    let mut failed = false;
    let texts: Vec<String> = texts.iter().map(|t| strip_agent_context(t)).filter(|t| !t.trim().is_empty()).collect();
    for g in guardrails {
        for params in redact_checks(g) {
            let started = Instant::now();
            let mut found = Vec::new();
            for chunk in texts.chunks(8) {
                found.extend(futures_util::future::join_all(chunk.iter().map(|t| presidio::analyze(env.http, params, t))).await);
            }
            let mut entities = Vec::new();
            let mut error = None;
            for r in found {
                match r {
                    Ok(e) => entities.extend(e),
                    Err(e) => error = Some(e),
                }
            }
            let fail_on_error = params["failOnError"].as_bool().unwrap_or(false);
            failed |= error.is_some() && fail_on_error;
            for pair in presidio::redaction_map(params, &entities) {
                if !out.map.iter().any(|(v, _)| v == &pair.0) {
                    out.map.push(pair);
                }
            }
            out.results.push(json!({
                "id": g.slug,
                "verdict": !(error.is_some() && fail_on_error),
                "deny": fail_on_error,
                "async": false,
                "type": "mutator",
                "transformed": !entities.is_empty(),
                "checks": [{
                    "id": REDACT_CHECK,
                    "verdict": true,
                    "data": { "entities": presidio::summary(&entities) },
                    "error": error.map(|e| json!({ "message": e })),
                    "execution_time": started.elapsed().as_millis() as u64,
                    "transformed": !entities.is_empty(),
                }],
                "execution_time": started.elapsed().as_millis() as u64,
                "created_at": chrono::Utc::now().to_rfc3339(),
            }));
        }
    }
    out.map.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    if failed { Err(out) } else { Ok(out) }
}

async fn airs_scan(params: &Value, stage: Stage, text: &str, env: &CheckEnv<'_>) -> (bool, Value, Option<String>) {
    let credentials = if params["credentials"].is_object() {
        params["credentials"].clone()
    } else {
        env.control_plane
            .integration_credentials("panw-prisma-airs", env.key, env.api_key)
            .await
    };
    let api_key = credentials["AIRS_API_KEY"]
        .as_str()
        .map(str::to_string)
        .or(env.airs_api_key.map(str::to_string))
        .unwrap_or_default();
    if api_key.trim().is_empty() {
        return (
            true,
            Value::Null,
            Some("AIRS_API_KEY is required but not configured. Please add your API key in the Portkey dashboard.".into()),
        );
    }
    let content_key = if stage == Stage::Input { "prompt" } else { "response" };
    let mut payload = json!({
        "tr_id": env.trace_id,
        "metadata": {
            "ai_model": params["ai_model"].as_str().unwrap_or("unknown-model"),
            "app_user": params["app_user"].as_str().unwrap_or("portkey-gateway"),
            "app_name": params["app_name"].as_str().filter(|s| !s.is_empty())
                .map(|s| format!("Portkey-{s}")).unwrap_or_else(|| "Portkey".into()),
        },
        "contents": [{ content_key: text }],
    });
    let mut profile = serde_json::Map::new();
    for field in ["profile_name", "profile_id"] {
        if let Some(v) = params[field].as_str().filter(|v| !v.is_empty()) {
            profile.insert(field.into(), json!(v));
        }
    }
    if !profile.is_empty() {
        payload["ai_profile"] = Value::Object(profile);
    }
    let timeout = Duration::from_millis(params["timeout"].as_u64().unwrap_or(5000));
    let response = env
        .http
        .post(AIRS_URL)
        .header("x-pan-token", api_key)
        .timeout(timeout)
        .json(&payload)
        .send()
        .await;
    match response {
        Ok(r) => match r.json::<Value>().await {
            Ok(body) if body["action"].is_string() => (body["action"] != "block", body, None),
            Ok(_) => (false, Value::Null, Some("Malformed AIRS response".into())),
            Err(e) => (false, Value::Null, Some(e.to_string())),
        },
        Err(e) => (false, Value::Null, Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_claude_code_context() {
        let req = json!({"messages":[{"role":"user","content":[
            {"type":"text","text":"<system-reminder>\nlots of agent context\n</system-reminder>"},
            {"type":"text","text":"Jordan's SSN is 538-21-4076."},
            {"type":"text","text":"<system-reminder>Today's date is 2026-11-09.</system-reminder>"}]},
            {"role":"system","content":[{"type":"text","text":"# Environment ... long agent instructions"}]}]});
        assert_eq!(request_text(Endpoint::Messages, &req), "Jordan's SSN is 538-21-4076.");
    }

    #[test]
    fn extracts_request_and_response_text() {
        let req = json!({"messages":[{"role":"user","content":"old"},{"role":"user","content":[{"type":"text","text":"a"},{"type":"tool_result"},{"type":"text","text":"b"}]}]});
        assert_eq!(request_text(Endpoint::Messages, &req), "a\nb");
        let resp = json!({"content":[{"type":"text","text":"hi"},{"type":"tool_use","input":{"content":"SECRET-1"}},{"type":"thinking","thinking":"hmm"}]});
        let text = response_text(Endpoint::Messages, &resp);
        assert!(text.contains("hi") && text.contains("SECRET-1") && text.contains("hmm"));
        let chat = json!({"choices":[{"message":{"content":"x","tool_calls":[{"function":{"arguments":"{\"a\":1}"}}]}}]});
        assert_eq!(response_text(Endpoint::ChatCompletions, &chat), "x\n{\"a\":1}");
    }

    #[test]
    fn redacts_content_fields_only() {
        let map = vec![("538-21-4076".to_string(), "<US_SSN>".to_string()), ("user".to_string(), "<X>".to_string())];
        let mut body = json!({
            "system": [{"type":"text","text":"user 538-21-4076"}],
            "tools": [{"name":"Write","description":"538-21-4076"}],
            "messages": [
                {"role":"user","content":[{"type":"text","text":"SSN 538-21-4076"},{"type":"tool_result","tool_use_id":"user","content":"file: 538-21-4076"}]},
                {"role":"assistant","content":[{"type":"thinking","thinking":"538-21-4076","signature":"sig"},
                    {"type":"tool_use","id":"toolu_1","name":"Write","input":{"file_path":"/tmp/a","content":"538-21-4076"}}]},
                {"role":"system","content":"538-21-4076"}]});
        let texts = content_strings(&body);
        assert!(texts.iter().all(|t| !t.contains("Write") && t != "user"), "{texts:?}");
        assert!(redact_json(&mut body, &map[..1]));
        let out = body.to_string();
        assert_eq!(out.matches("538-21-4076").count(), 4, "system, tools, thinking, system message stay: {out}");
        assert!(out.contains("SSN <US_SSN>") && out.contains("file: <US_SSN>") && out.contains(r#""content":"<US_SSN>""#));
        assert!(out.contains(r#""role":"user""#) && out.contains(r#""tool_use_id":"user""#));
    }
}
