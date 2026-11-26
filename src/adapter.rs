//! The Messages API adapter: Anthropic Messages requests served by a
//! provider's chat completions. Port of the TS `src/adapters/messages`
//! (request, response and stream transforms), kept field-for-field.

use serde_json::{json, Map, Value};

fn text_block(b: &Value) -> Value {
    json!({ "type": "text", "text": b["text"].as_str().unwrap_or("") })
}

/// TS transformMessage: one Messages message -> chat message(s).
fn transform_message(msg: &Value) -> Vec<Value> {
    if let Some(s) = msg["content"].as_str() {
        return vec![json!({ "role": msg["role"], "content": s })];
    }
    let Some(blocks) = msg["content"].as_array() else { return vec![] };
    let mut parts = Vec::new();
    let mut tool_calls = Vec::new();
    let mut tool_results = Vec::new();
    for block in blocks {
        match block["type"].as_str() {
            Some("text") => parts.push(text_block(block)),
            Some("image") if block.get("source").is_some_and(|s| !s.is_null()) => parts.push(json!({
                "type": "image_url",
                "image_url": { "url": format!("data:{};base64,{}",
                    block["source"]["media_type"].as_str().unwrap_or("undefined"),
                    block["source"]["data"].as_str().unwrap_or("undefined")) },
            })),
            Some("tool_use") if block["id"].as_str().is_some_and(|s| !s.is_empty()) && block["name"].as_str().is_some_and(|s| !s.is_empty()) => {
                let input = if block["input"].is_null() { json!({}) } else { block["input"].clone() };
                tool_calls.push(json!({
                    "id": block["id"], "type": "function",
                    "function": { "name": block["name"], "arguments": input.to_string() },
                }));
            }
            Some("tool_result") => tool_results.push(json!({
                "role": "tool",
                "tool_call_id": block["tool_use_id"].as_str().unwrap_or(""),
                "content": match &block["content"] {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                },
            })),
            _ => {}
        }
    }
    if !tool_results.is_empty() {
        return tool_results;
    }
    if !tool_calls.is_empty() {
        let content = match parts.first() {
            Some(p) if p["type"] == "text" => p["text"].clone(),
            _ => Value::Null,
        };
        return vec![json!({ "role": "assistant", "content": content, "tool_calls": tool_calls })];
    }
    if parts.len() == 1 && parts[0]["type"] == "text" {
        return vec![json!({ "role": msg["role"], "content": parts[0]["text"] })];
    }
    vec![json!({ "role": msg["role"], "content": parts })]
}

fn present(v: &Value) -> bool {
    !v.is_null()
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        _ => true,
    }
}

/// TS transformMessagesToChatCompletions.
pub fn messages_to_chat(req: &Value) -> Value {
    let mut messages = Vec::new();
    if truthy(&req["system"]) {
        let system = match &req["system"] {
            Value::String(s) => s.clone(),
            Value::Array(blocks) => blocks.iter().map(|b| b["text"].as_str().unwrap_or("")).collect::<Vec<_>>().join("\n"),
            other => other.to_string(),
        };
        messages.push(json!({ "role": "system", "content": system }));
    }
    for m in req["messages"].as_array().into_iter().flatten() {
        messages.extend(transform_message(m));
    }
    let mut out = Map::new();
    out.insert("model".into(), req["model"].clone());
    out.insert("messages".into(), Value::Array(messages));
    if present(&req["max_tokens"]) {
        out.insert("max_completion_tokens".into(), req["max_tokens"].clone());
    }
    for k in ["temperature", "top_p", "stream"] {
        if present(&req[k]) {
            out.insert(k.into(), req[k].clone());
        }
    }
    if truthy(&req["stop_sequences"]) {
        out.insert("stop".into(), req["stop_sequences"].clone());
    }
    if out.get("stream").is_some_and(truthy) {
        out.insert("stream_options".into(), json!({ "include_usage": true }));
    }
    if let Some(tools) = req["tools"].as_array().filter(|t| !t.is_empty()) {
        out.insert(
            "tools".into(),
            Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        let mut f = Map::new();
                        f.insert("name".into(), t["name"].clone());
                        f.insert("description".into(), json!(t["description"].as_str().filter(|d| !d.is_empty()).unwrap_or("")));
                        if present(&t["input_schema"]) {
                            f.insert("parameters".into(), t["input_schema"].clone());
                        }
                        json!({ "type": "function", "function": f })
                    })
                    .collect(),
            ),
        );
    }
    let tc = &req["tool_choice"];
    if truthy(tc) {
        match tc["type"].as_str() {
            Some("auto") => {
                out.insert("tool_choice".into(), json!("auto"));
            }
            Some("any") => {
                out.insert("tool_choice".into(), json!("required"));
            }
            Some("tool") if truthy(&tc["name"]) => {
                out.insert("tool_choice".into(), json!({ "type": "function", "function": { "name": tc["name"] } }));
            }
            _ => {}
        }
    }
    if truthy(&req["metadata"]["user_id"]) {
        out.insert("user".into(), req["metadata"]["user_id"].clone());
    }
    let oc = &req["output_config"];
    if truthy(oc) {
        if oc["format"]["type"] == "json_schema" {
            out.insert("response_format".into(), json!({ "type": "json_schema", "json_schema": oc["format"]["schema"] }));
        }
        if truthy(&oc["effort"]) {
            out.insert("reasoning_effort".into(), oc["effort"].clone());
        }
    }
    Value::Object(out)
}

fn stop_reason(finish: &Value) -> &'static str {
    match finish.as_str() {
        Some("length" | "max_tokens") => "max_tokens",
        Some("tool_calls" | "function_call") => "tool_use",
        _ => "end_turn",
    }
}

/// TS transformChatCompletionsToMessages.
pub fn chat_to_messages(resp: &Value, status: u16, provider: &str) -> Value {
    if resp.get("error").is_some() {
        return resp.clone();
    }
    if status != 200 {
        return json!({ "error": { "message": "Request failed", "type": "api_error", "param": null, "code": null }, "provider": provider });
    }
    let mut content = Vec::new();
    let mut stop = Value::Null;
    for choice in resp["choices"].as_array().into_iter().flatten() {
        let msg = &choice["message"];
        stop = json!(stop_reason(&choice["finish_reason"]));
        for block in msg["content_blocks"].as_array().into_iter().flatten() {
            if truthy(&block["thinking"]) || block["type"] == "thinking" {
                let thinking = block["thinking"].as_str().filter(|t| !t.is_empty()).or(block["text"].as_str()).unwrap_or("");
                content.push(json!({ "type": "thinking", "thinking": thinking, "signature": "" }));
            }
        }
        for tc in msg["tool_calls"].as_array().into_iter().flatten() {
            if tc["type"] != "function" {
                continue;
            }
            let args = tc["function"]["arguments"].as_str().filter(|a| !a.is_empty()).unwrap_or("{}");
            let input = serde_json::from_str::<Value>(args).ok().filter(Value::is_object).unwrap_or_else(|| json!({}));
            let id = tc["id"].as_str().filter(|i| !i.is_empty()).map(str::to_string).unwrap_or_else(|| format!("toolu_{}", uuid::Uuid::new_v4()));
            content.push(json!({ "type": "tool_use", "id": id, "name": tc["function"]["name"], "input": input }));
        }
        let text = match &msg["content"] {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            Value::Array(parts) => parts.iter().map(|p| p["text"].as_str().unwrap_or("")).collect(),
            other => other.to_string(),
        };
        if !text.is_empty() {
            content.push(json!({ "type": "text", "text": text }));
        }
    }
    let u = &resp["usage"];
    let id = resp["id"].as_str().filter(|i| !i.is_empty()).map(str::to_string).unwrap_or_else(|| format!("msg_{}", uuid::Uuid::new_v4()));
    let mut out = json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "content": content,
        "stop_reason": stop,
        "stop_sequence": null,
        "usage": { "input_tokens": u["prompt_tokens"].as_u64().unwrap_or(0), "output_tokens": u["completion_tokens"].as_u64().unwrap_or(0) },
    });
    if present(&resp["model"]) {
        out["model"] = resp["model"].clone();
    }
    out
}

/// TS messages transformStreamChunk over a byte stream (chat SSE in,
/// Messages events out).
#[derive(Default)]
pub struct MessagesStream {
    buffer: String,
    started: bool,
    completed: bool,
    input_tokens: u64,
    output_tokens: u64,
    stop_reason: Option<&'static str>,
}

fn event(name: &str, data: Value) -> String {
    format!("event: {name}\ndata: {data}\n\n")
}

impl MessagesStream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> String {
        self.buffer.push_str(&String::from_utf8_lossy(bytes));
        let mut out = String::new();
        while let Some(i) = self.buffer.find("\n\n") {
            let chunk: String = self.buffer.drain(..i + 2).collect();
            let chunk = &chunk[..i];
            if !chunk.trim().is_empty() {
                out.push_str(&self.chunk(chunk));
            }
        }
        out
    }

    /// End of stream: flushes any partial chunk, then completion events
    /// (providers like Gemini end without `data: [DONE]`).
    pub fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.buffer);
        let mut out = if rest.trim().is_empty() { String::new() } else { self.chunk(&rest) };
        out.push_str(&self.chunk("data: [DONE]"));
        out
    }

    fn chunk(&mut self, chunk: &str) -> String {
        let trimmed = chunk.trim();
        if trimmed == "data: [DONE]" {
            if !self.started || self.completed {
                return String::new();
            }
            self.completed = true;
            return event(
                "message_delta",
                json!({ "type": "message_delta",
                    "delta": { "stop_reason": self.stop_reason.unwrap_or("end_turn"), "stop_sequence": null },
                    "usage": { "output_tokens": self.output_tokens, "input_tokens": self.input_tokens } }),
            ) + &event("message_stop", json!({ "type": "message_stop" }));
        }
        let Some(data) = trimmed.strip_prefix("data: ") else { return String::new() };
        let Ok(parsed) = serde_json::from_str::<Value>(data) else { return String::new() };
        let mut out = String::new();
        if !self.started {
            self.started = true;
            out.push_str(&event(
                "message_start",
                json!({ "type": "message_start", "message": {
                    "id": format!("msg_{}", uuid::Uuid::new_v4()), "type": "message", "role": "assistant",
                    "content": [], "model": parsed["model"].as_str().unwrap_or(""), "stop_reason": null,
                    "stop_sequence": null, "usage": { "input_tokens": self.input_tokens, "output_tokens": 0 } } }),
            ));
            out.push_str(&event(
                "content_block_start",
                json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
            ));
        }
        let delta = &parsed["choices"][0]["delta"];
        if truthy(&delta["content"]) {
            out.push_str(&event(
                "content_block_delta",
                json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": delta["content"] } }),
            ));
        }
        for tc in delta["tool_calls"].as_array().into_iter().flatten() {
            let idx = tc["index"].as_u64().unwrap_or(0) + 1;
            if truthy(&tc["function"]["name"]) {
                let id = tc["id"].as_str().filter(|i| !i.is_empty()).map(str::to_string).unwrap_or_else(|| format!("toolu_{}", uuid::Uuid::new_v4()));
                out.push_str(&event(
                    "content_block_start",
                    json!({ "type": "content_block_start", "index": idx,
                        "content_block": { "type": "tool_use", "id": id, "name": tc["function"]["name"], "input": {} } }),
                ));
            }
            if truthy(&tc["function"]["arguments"]) {
                out.push_str(&event(
                    "content_block_delta",
                    json!({ "type": "content_block_delta", "index": idx,
                        "delta": { "type": "input_json_delta", "partial_json": tc["function"]["arguments"] } }),
                ));
            }
        }
        let u = &parsed["usage"];
        if truthy(u) {
            if let Some(p) = u["prompt_tokens"].as_u64().filter(|p| *p > 0) {
                self.input_tokens = p;
            }
            if let Some(c) = u["completion_tokens"].as_u64().filter(|c| *c > 0) {
                self.output_tokens = c;
            }
        }
        let finish = &parsed["choices"][0]["finish_reason"];
        if truthy(finish) {
            self.stop_reason = Some(match finish.as_str() {
                Some("tool_calls") => "tool_use",
                Some("length") => "max_tokens",
                _ => "end_turn",
            });
            out.push_str(&event("content_block_stop", json!({ "type": "content_block_stop", "index": 0 })));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_ts() {
        let req = json!({"model":"m","max_tokens":5,"system":[{"type":"text","text":"a"},{"type":"text","text":"b"}],
            "stream":true,"tool_choice":{"type":"any"},
            "tools":[{"name":"t","input_schema":{"type":"object"}}],
            "messages":[{"role":"user","content":"hi"},
                {"role":"assistant","content":[{"type":"text","text":"x"},{"type":"tool_use","id":"tu1","name":"t","input":{"a":1}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":[{"type":"text","text":"r"}]}]}]});
        let out = messages_to_chat(&req);
        assert_eq!(out["max_completion_tokens"], 5);
        assert_eq!(out["messages"][0], json!({"role":"system","content":"a\nb"}));
        assert_eq!(out["messages"][2]["tool_calls"][0]["function"]["arguments"], "{\"a\":1}");
        assert_eq!(out["messages"][3]["role"], "tool");
        assert_eq!(out["tool_choice"], "required");
        assert_eq!(out["stream_options"], json!({"include_usage":true}));
        assert_eq!(out["tools"][0]["function"]["description"], "");
    }

    #[test]
    fn stream_matches_ts() {
        let mut s = MessagesStream::new();
        let mut out = s.push(b"data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}\n\ndata: [DONE]\n\n");
        out.push_str(&s.finish());
        let events: Vec<&str> = out.lines().filter_map(|l| l.strip_prefix("event: ")).collect();
        assert_eq!(events, ["message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"]);
        assert!(out.contains("\"input_tokens\":3"));
    }
}
