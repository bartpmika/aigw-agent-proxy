//! MCP inspection: calls to remote MCP servers (HTTP / streamable HTTP)
//! pass through the proxy like other web traffic. JSON-RPC requests that
//! carry content — `tools/call`, `resources/read`, `prompts/get` — are
//! checked with the workspace MCP guardrails (falling back to the input and
//! output guardrails), logged to the control plane with server and tool, and
//! forwarded to their destination unchanged. A block is returned as a
//! JSON-RPC error, which agents show as a failed tool call.

use crate::analytics::{self, Record};
use crate::body::{self, Body};
use crate::control_plane::KeyDetails;
use crate::gateway::{client_headers, json_response, response_headers, with_headers, Gateway, Tunnel};
use crate::guardrails::{self, CheckEnv, Guardrail, Stage};
use crate::identity;
use crate::providers::Usage;
use futures_util::{FutureExt, StreamExt};
use hyper::Response;
use serde_json::{json, Map, Value};
use std::io;
use std::sync::Arc;
use std::time::Instant;

/// Methods whose content is inspected.
const INSPECTED: [&str; 3] = ["tools/call", "resources/read", "prompts/get"];

/// One inspected MCP request.
#[derive(Debug, Clone)]
pub struct McpCall {
    pub id: Value,
    pub method: String,
    /// Tool, prompt or resource the call is about.
    pub target: String,
    /// What the request guardrails see.
    pub text: String,
    pub request: Value,
}

/// Flattens JSON into text: string values and keys, one per line.
fn json_text(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| json_text(x, out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            if let Value::String(s) = x {
                out.push(format!("{k}: {s}"));
            } else {
                json_text(x, out);
            }
        }),
        Value::Number(n) => out.push(n.to_string()),
        _ => {}
    }
}

/// Parses an MCP JSON-RPC request worth inspecting (single message).
pub fn parse_request(body: &[u8]) -> Option<McpCall> {
    let v: Value = serde_json::from_slice(body).ok()?;
    if v["jsonrpc"] != "2.0" {
        return None;
    }
    let method = v["method"].as_str()?.to_string();
    if !INSPECTED.contains(&method.as_str()) {
        return None;
    }
    let p = &v["params"];
    let target = p["name"].as_str().or(p["uri"].as_str()).unwrap_or("").to_string();
    let mut lines = vec![format!("MCP {method} {target}")];
    json_text(&p["arguments"], &mut lines);
    Some(McpCall { id: v["id"].clone(), method, target, text: lines.join("\n"), request: v })
}

/// The JSON-RPC response for `id` from a JSON or SSE body.
fn find_response(body: &str, id: &Value) -> Option<Value> {
    let candidates: Vec<Value> = if body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
        match serde_json::from_str::<Value>(body).ok()? {
            Value::Array(a) => a,
            v => vec![v],
        }
    } else {
        body.lines().filter_map(|l| l.strip_prefix("data:")).filter_map(|d| serde_json::from_str(d.trim()).ok()).collect()
    };
    candidates.into_iter().find(|m| &m["id"] == id && (m.get("result").is_some() || m.get("error").is_some()))
}

/// What the response guardrails see in an MCP result.
pub fn result_text(msg: &Value) -> String {
    let mut lines = Vec::new();
    let r = &msg["result"];
    for c in r["content"].as_array().into_iter().flatten() {
        if let Some(t) = c["text"].as_str() {
            lines.push(t.to_string());
        }
        if let Some(t) = c["resource"]["text"].as_str() {
            lines.push(t.to_string());
        }
    }
    for c in r["contents"].as_array().into_iter().flatten() {
        if let Some(t) = c["text"].as_str() {
            lines.push(t.to_string());
        }
    }
    for m in r["messages"].as_array().into_iter().flatten() {
        if let Some(t) = m["content"]["text"].as_str() {
            lines.push(t.to_string());
        }
    }
    if !r["structuredContent"].is_null() {
        json_text(&r["structuredContent"], &mut lines);
    }
    if let Some(e) = msg["error"]["message"].as_str() {
        lines.push(e.to_string());
    }
    lines.join("\n")
}

fn rpc_error(id: &Value, message: &str, detections: &[String]) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": message, "data": { "type": "guardrail_blocked", "detections": detections } } })
}

impl Gateway {
    /// MCP guardrails: the workspace/org MCP defaults, else the regular ones.
    async fn mcp_guardrails(&self, key: &KeyDetails, api_key: &str, stage: Stage) -> Vec<Guardrail> {
        let (mcp, regular) = match stage {
            Stage::Input => ("mcp_input_guardrails", "input_guardrails"),
            Stage::Output => ("mcp_output_guardrails", "output_guardrails"),
        };
        let mut slugs = key.default_guardrails(mcp);
        if slugs.is_empty() {
            slugs = key.default_guardrails(regular);
        }
        slugs.dedup();
        let mut out = Vec::new();
        for slug in slugs {
            if let Some(record) = self.control_plane.guardrail(&slug, key, api_key).await {
                out.push(Guardrail { slug, record });
            }
        }
        out
    }

    /// Inspects, forwards and logs one MCP call.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn mcp(
        self: Arc<Self>,
        parts: hyper::http::request::Parts,
        raw: bytes::Bytes,
        tunnel: &Tunnel,
        url: &str,
        key: KeyDetails,
        api_key: String,
        call: McpCall,
        started: Instant,
    ) -> Response<Body> {
        let trace_id = uuid::Uuid::new_v4().to_string();
        let env = CheckEnv {
            http: &self.http,
            control_plane: &self.control_plane,
            key: &key,
            api_key: &api_key,
            trace_id: &trace_id,
            airs_api_key: self.settings.airs_api_key.as_deref(),
        };
        let what = format!("MCP {} {} on {}", call.method, call.target, tunnel.host);

        // Request: the call's arguments.
        let input = self.mcp_guardrails(&key, &api_key, Stage::Input).await;
        let checked = guardrails::run(&input, Stage::Input, &call.text, &env).await;
        let mut hooks = json!({ "before_request_hooks": checked.results, "after_request_hooks": [] });
        if checked.denied {
            let found = crate::web::detections(&hooks["before_request_hooks"].as_array().cloned().unwrap_or_default());
            let msg = format!("Blocked by AI Gateway guardrail: {what} violates policy ({}).", found.join(", "));
            tracing::info!("mcp inspection: {msg}");
            let body = rpc_error(&call.id, &msg, &found);
            self.mcp_log(tunnel, &key, &api_key, &call, url, 446, body.clone(), hooks, &trace_id, &parts.headers, started).await;
            return json_response(200, &body, &[("x-portkey-guardrail-blocked", "true".into())]);
        }

        // Forward unchanged.
        let resp = match self.http.request(parts.method.clone(), url).headers(client_headers(&parts.headers)).body(raw).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("mcp request to {url} failed: {e}");
                return json_response(502, &json!({ "error": "Bad Gateway" }), &[]);
            }
        };
        let status = resp.status().as_u16();
        let headers = response_headers(resp.headers());

        // Response: hold it (the server ends the stream after the result),
        // up to the scan limit; larger bodies are scanned on their start.
        let cap = self.settings.web.max_scan_bytes.max(1024 * 1024);
        let mut upstream = resp.bytes_stream();
        let (mut held, mut ended) = (Vec::new(), false);
        while held.len() < cap {
            match upstream.next().await {
                Some(Ok(b)) => held.extend_from_slice(&b),
                Some(Err(_)) => return json_response(502, &json!({ "error": "Bad Gateway" }), &[]),
                None => {
                    ended = true;
                    break;
                }
            }
        }
        let held = bytes::Bytes::from(held);
        let reply = find_response(&String::from_utf8_lossy(&held), &call.id);
        if let Some(msg) = &reply {
            let text = result_text(msg);
            let output = self.mcp_guardrails(&key, &api_key, Stage::Output).await;
            let checked = guardrails::run(&output, Stage::Output, &text, &env).await;
            hooks["after_request_hooks"] = json!(checked.results);
            if checked.denied {
                let found = crate::web::detections(&checked.results);
                let msg = format!("Blocked by AI Gateway guardrail: result of {what} violates policy ({}).", found.join(", "));
                tracing::info!("mcp inspection: {msg}");
                let body = rpc_error(&call.id, &msg, &found);
                self.mcp_log(tunnel, &key, &api_key, &call, url, 446, body.clone(), hooks, &trace_id, &parts.headers, started).await;
                return json_response(200, &body, &[("x-portkey-guardrail-blocked", "true".into())]);
            }
        }
        let logged = reply.unwrap_or(Value::Null);
        self.mcp_log(tunnel, &key, &api_key, &call, url, status, logged, hooks, &trace_id, &parts.headers, started).await;
        if ended {
            return with_headers(status, headers, body::full(held));
        }
        let rest = upstream.map(|r| r.map_err(io::Error::other));
        let stream = futures_util::stream::once(async move { Ok::<_, io::Error>(held) }).chain(rest);
        with_headers(status, headers, body::from_stream(stream))
    }

    /// Logs an MCP call (provider `mcp`, model = tool) with caller identity.
    #[allow(clippy::too_many_arguments)]
    async fn mcp_log(
        self: &Arc<Self>,
        tunnel: &Tunnel,
        key: &KeyDetails,
        api_key: &str,
        call: &McpCall,
        url: &str,
        status: u16,
        response: Value,
        hooks: Value,
        trace_id: &str,
        request_headers: &hyper::HeaderMap,
        started: Instant,
    ) {
        let gateway = self.clone();
        let user_agent = request_headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_string);
        let (lookup, host, key_c, method, target) =
            (tunnel.client.clone(), tunnel.host.clone(), key.clone(), call.method.clone(), call.target.clone());
        let metadata_source = async move {
            let (client, host_id) = tokio::join!(lookup, identity::host_identity());
            let mut md = gateway.metadata(None, &host, client, host_id, user_agent, &key_c);
            md.insert("_source".into(), json!("forward-proxy-mcp"));
            md.insert("_mcp_server".into(), json!(host));
            md.insert("_mcp_method".into(), json!(method));
            if !target.is_empty() {
                md.insert("_mcp_tool".into(), json!(target));
            }
            md
        }
        .boxed();
        let request = Arc::new(call.request.clone());
        let elapsed = started.elapsed().as_millis() as u64;
        let record = Record {
            id: uuid::Uuid::new_v4().to_string(),
            trace_id: trace_id.to_string(),
            provider: "mcp".into(),
            model: if call.target.is_empty() { call.method.clone() } else { call.target.clone() },
            request_url: url.to_string(),
            method: "POST".into(),
            status,
            is_streaming: false,
            usage: Usage::default(),
            response_time_ms: elapsed,
            ttlt_ms: elapsed,
            metadata: Map::new(),
            metadata_source: Some(metadata_source),
            request_body: request.clone(),
            transformed_request_body: request,
            response_headers: Map::new(),
            response_body: response,
            portkey_headers: analytics::masked_portkey_headers(api_key, "{}", "{}", trace_id),
            hook_results: hooks,
            mode: "single".into(),
            last_used_option_index: -1,
            config_slug: String::new(),
            api_key: String::new(),
        };
        self.sink.record(record, key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tool_calls_and_results() {
        let req = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.c","body":"SSN 538-21-4076"}}}"#;
        let c = parse_request(req).unwrap();
        assert_eq!((c.method.as_str(), c.target.as_str()), ("tools/call", "send_email"));
        assert!(c.text.contains("body: SSN 538-21-4076"));
        assert!(parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).is_none());

        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}}\n\n";
        let msg = find_response(sse, &json!(7)).unwrap();
        assert_eq!(result_text(&msg), "done");
        let j = r#"{"jsonrpc":"2.0","id":"x","result":{"contents":[{"uri":"f","text":"file body"}]}}"#;
        assert_eq!(result_text(&find_response(j, &json!("x")).unwrap()), "file body");
    }
}
