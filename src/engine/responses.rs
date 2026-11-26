//! Provider responses -> unified (OpenAI) format, buffered and streaming.
//! Ports of the TS gateway's response transforms for native-format
//! providers; OpenAI-compatible providers use a generic transform.

use serde_json::{json, Map, Value};

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// TS transformFinishReason (strict OpenAI compliance maps to OpenAI values).
pub fn finish_reason(reason: &Value, strict: bool) -> Value {
    let Some(r) = reason.as_str().filter(|r| !r.is_empty()) else { return json!("stop") };
    if !strict {
        return json!(r);
    }
    json!(match r {
        "tool_use" | "tool_calls" | "TOOL_CALLS" | "TOOL_CALL" | "function_call" => "tool_calls",
        "max_tokens" | "MAX_TOKENS" | "length" | "LENGTH" | "MODEL_LENGTH" | "model_context_window_exceeded" => "length",
        "content_filtered" | "content_filter" | "SAFETY" | "SPII" | "CONTENT_FILTERED" => "content_filter",
        "refusal" => "refusal",
        _ => "stop",
    })
}

/// TS generateErrorResponse.
pub fn error(provider: &str, message: &str, kind: Value, param: Value, code: Value) -> Value {
    json!({
        "error": { "message": format!("{provider} error: {message}"), "type": kind, "param": param, "code": code },
        "provider": provider,
    })
}

pub fn invalid_response(provider: &str, body: &Value) -> Value {
    json!({
        "error": { "message": format!("Invalid response received from {provider}: {body}"), "type": null, "param": null, "code": null },
        "provider": provider,
    })
}

fn str_or_null(v: &Value) -> Value {
    if v.is_null() { Value::Null } else { v.clone() }
}

// --------------------------------------------------------------- buffered

fn anthropic_chat(body: &Value, status: u16, strict: bool, provider: &str) -> Value {
    if status != 200 && body.get("error").is_some() {
        let e = &body["error"];
        return error(provider, e["message"].as_str().unwrap_or(""), str_or_null(&e["type"]), Value::Null, Value::Null);
    }
    let Some(content) = body["content"].as_array() else { return invalid_response(provider, body) };
    let u = &body["usage"];
    let (input, output) = (u["input_tokens"].as_u64().unwrap_or(0), u["output_tokens"].as_u64().unwrap_or(0));
    let (cc, cr) = (u["cache_creation_input_tokens"].as_u64(), u["cache_read_input_tokens"].as_u64());
    let text: String = content.iter().filter(|i| i["type"] == "text").filter_map(|i| i["text"].as_str()).collect();
    let tool_calls: Vec<Value> = content.iter().filter(|i| i["type"] == "tool_use").map(|i| json!({
        "id": i["id"], "type": "function", "function": { "name": i["name"], "arguments": i["input"].to_string() } })).collect();
    let prompt = input + cr.unwrap_or(0) + cc.unwrap_or(0);
    let mut message = json!({ "role": "assistant", "content": text });
    if !strict {
        message["content_blocks"] = Value::Array(content.iter().filter(|i| i["type"] != "tool_use").cloned().collect());
    }
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
    }
    let mut usage = json!({ "prompt_tokens": prompt, "completion_tokens": output, "total_tokens": prompt + output,
        "prompt_tokens_details": { "cached_tokens": cr.unwrap_or(0) } });
    if cc.unwrap_or(0) > 0 || cr.unwrap_or(0) > 0 {
        usage["cache_read_input_tokens"] = json!(cr);
        usage["cache_creation_input_tokens"] = json!(cc);
    }
    json!({ "id": body["id"], "object": "chat.completion", "created": now(), "model": body["model"], "provider": provider,
        "choices": [{ "message": message, "index": 0, "logprobs": null, "finish_reason": finish_reason(&body["stop_reason"], strict) }],
        "usage": usage })
}

fn gemini_usage(u: &Value) -> Value {
    let p = u["promptTokenCount"].as_u64().unwrap_or(0);
    let c = u["candidatesTokenCount"].as_u64().unwrap_or(0) + u["thoughtsTokenCount"].as_u64().unwrap_or(0);
    json!({ "prompt_tokens": p, "completion_tokens": c, "total_tokens": u["totalTokenCount"].as_u64().unwrap_or(0),
        "completion_tokens_details": { "reasoning_tokens": u["thoughtsTokenCount"].as_u64().unwrap_or(0) },
        "prompt_tokens_details": { "cached_tokens": u["cachedContentTokenCount"].as_u64().unwrap_or(0) } })
}

fn gemini_error(body: &Value, provider: &str) -> Option<Value> {
    let e = if body.is_array() { &body[0]["error"] } else { &body["error"] };
    if e.is_null() {
        return None;
    }
    let code = if e["code"].is_null() { Value::Null } else { json!(e["code"].to_string().trim_matches('"')) };
    Some(error(provider, e["message"].as_str().unwrap_or(""), str_or_null(&e["status"]), Value::Null, code))
}

fn gemini_chat(body: &Value, status: u16, strict: bool, provider: &str) -> Value {
    if status != 200 {
        if let Some(e) = gemini_error(body, provider) {
            return e;
        }
    }
    if body.get("candidates").is_none() && body.get("usageMetadata").is_none() {
        return invalid_response(provider, body);
    }
    let vertex = provider == "vertex-ai";
    let choices: Vec<Value> = body["candidates"].as_array().into_iter().flatten().enumerate().map(|(idx, g)| {
        let mut tool_calls = Vec::new();
        let mut content: Option<String> = None;
        let mut blocks = Vec::new();
        for part in g["content"]["parts"].as_array().into_iter().flatten() {
            if part["functionCall"].is_object() {
                let mut f = json!({ "name": part["functionCall"]["name"], "arguments": part["functionCall"]["args"].to_string() });
                if !strict && part["thoughtSignature"].is_string() {
                    f["thought_signature"] = part["thoughtSignature"].clone();
                }
                tool_calls.push(json!({ "id": format!("portkey-{}", uuid::Uuid::new_v4()), "type": "function", "function": f }));
            } else if let Some(t) = part["text"].as_str().filter(|t| !t.is_empty()) {
                if part["thought"] == true {
                    blocks.push(json!({ "type": "thinking", "thinking": t }));
                } else {
                    content = Some(content.unwrap_or_default() + t);
                    blocks.push(json!({ "type": "text", "text": t }));
                }
            } else if part["inlineData"].is_object() {
                blocks.push(json!({ "type": "image_url", "image_url": { "url": format!("data:{};base64,{}",
                    part["inlineData"]["mimeType"].as_str().unwrap_or(""), part["inlineData"]["data"].as_str().unwrap_or("")) } }));
            }
        }
        if content.is_none() && tool_calls.is_empty() {
            content = g["finishMessage"].as_str().map(str::to_string);
        }
        let mut message = json!({ "role": "assistant" });
        if !tool_calls.is_empty() {
            message["tool_calls"] = Value::Array(tool_calls);
        }
        if let Some(c) = content.filter(|c| !c.is_empty()) {
            message["content"] = json!(c);
        }
        if !strict && !blocks.is_empty() {
            message["content_blocks"] = Value::Array(blocks);
        }
        let mut choice = json!({ "message": message, "index": if vertex { json!(idx) } else { g.get("index").cloned().unwrap_or(json!(idx)) },
            "finish_reason": finish_reason(&g["finishReason"], strict) });
        if !strict && vertex {
            choice["safetyRatings"] = g["safetyRatings"].clone();
        }
        if !strict && g["groundingMetadata"].is_object() {
            choice["groundingMetadata"] = g["groundingMetadata"].clone();
        }
        choice
    }).collect();
    json!({ "id": format!("portkey-{}", uuid::Uuid::new_v4()), "object": "chat.completion", "created": now(),
        "model": body["modelVersion"], "provider": provider, "choices": choices, "usage": gemini_usage(&body["usageMetadata"]) })
}

/// TS transformToAnthropicStopReason (Converse stop reasons).
fn anthropic_stop_reason(r: &Value) -> &'static str {
    match r.as_str() {
        Some("tool_use") => "tool_use",
        Some("max_tokens") => "max_tokens",
        Some("stop_sequence") => "stop_sequence",
        _ => "end_turn",
    }
}

/// TS BedrockMessagesResponseTransform: Converse -> Messages.
fn bedrock_messages(body: &Value, status: u16, request: &Value) -> Value {
    if status != 200 {
        return bedrock_error(body).unwrap_or_else(|| invalid_response("bedrock", body));
    }
    if body.get("output").is_none() {
        return invalid_response("bedrock", body);
    }
    let mut content = Vec::new();
    for b in body["output"]["message"]["content"].as_array().into_iter().flatten() {
        if b["text"].as_str().is_some_and(|t| !t.is_empty()) {
            content.push(json!({ "type": "text", "text": b["text"] }));
        } else if b["reasoningContent"]["reasoningText"].is_object() {
            let r = &b["reasoningContent"]["reasoningText"];
            content.push(json!({ "type": "thinking", "thinking": r["text"], "signature": r["signature"] }));
        } else if !b["reasoningContent"]["redactedContent"].is_null() {
            content.push(json!({ "type": "redacted_thinking", "data": b["reasoningContent"]["redactedContent"] }));
        } else if b["toolUse"].is_object() {
            let t = &b["toolUse"];
            content.push(json!({ "type": "tool_use", "id": t["toolUseId"], "name": t["name"], "input": t["input"] }));
        }
    }
    let u = &body["usage"];
    let mut usage = Map::new();
    for (k, from) in [("cache_read_input_tokens", "cacheReadInputTokens"), ("cache_creation_input_tokens", "cacheWriteInputTokens"),
        ("input_tokens", "inputTokens"), ("output_tokens", "outputTokens")] {
        if !u[from].is_null() {
            usage.insert(k.into(), u[from].clone());
        }
    }
    json!({ "id": format!("portkey-{}", uuid::Uuid::new_v4()), "model": request["model"].as_str().unwrap_or(""),
        "type": "message", "role": "assistant", "content": content,
        "stop_reason": anthropic_stop_reason(&body["stopReason"]), "usage": usage })
}

fn bedrock_error(body: &Value) -> Option<Value> {
    body["message"].as_str().map(|m| error("bedrock", m, Value::Null, Value::Null, Value::Null))
}

fn bedrock_chat(body: &Value, status: u16, strict: bool, request: &Value) -> Value {
    if status != 200 {
        if let Some(e) = bedrock_error(body) {
            return e;
        }
    }
    let Some(content) = body["output"]["message"]["content"].as_array() else { return invalid_response("bedrock", body) };
    let text = content.iter().filter_map(|i| i["text"].as_str()).collect::<Vec<_>>().join("\n");
    let u = &body["usage"];
    let (cr, cw) = (u["cacheReadInputTokens"].as_u64().unwrap_or(0), u["cacheWriteInputTokens"].as_u64().unwrap_or(0));
    let mut message = json!({ "role": "assistant", "content": text });
    if !strict {
        message["content_blocks"] = Value::Array(content.iter().filter_map(|i| {
            if let Some(t) = i["text"].as_str() {
                Some(json!({ "type": "text", "text": t }))
            } else if i["reasoningContent"]["reasoningText"].is_object() {
                Some(json!({ "type": "thinking", "thinking": i["reasoningContent"]["reasoningText"]["text"], "signature": i["reasoningContent"]["reasoningText"]["signature"] }))
            } else if !i["reasoningContent"]["redactedContent"].is_null() {
                Some(json!({ "type": "redacted_thinking", "data": i["reasoningContent"]["redactedContent"] }))
            } else {
                None
            }
        }).collect());
    }
    let calls: Vec<Value> = content.iter().filter(|i| i["toolUse"].is_object()).map(|i| json!({ "id": i["toolUse"]["toolUseId"],
        "type": "function", "function": { "name": i["toolUse"]["name"], "arguments": i["toolUse"]["input"].to_string() } })).collect();
    if !calls.is_empty() {
        message["tool_calls"] = Value::Array(calls);
    }
    let mut usage = json!({ "prompt_tokens": u["inputTokens"].as_u64().unwrap_or(0) + cr + cw, "completion_tokens": u["outputTokens"],
        "total_tokens": u["totalTokens"], "prompt_tokens_details": { "cached_tokens": cr } });
    if cr > 0 || cw > 0 {
        usage["cache_read_input_tokens"] = json!(cr);
        usage["cache_creation_input_tokens"] = json!(cw);
    }
    json!({ "id": chrono::Utc::now().timestamp_millis().to_string(), "object": "chat.completion", "created": now(),
        "model": request["model"].as_str().unwrap_or(""), "provider": "bedrock",
        "choices": [{ "index": 0, "message": message, "finish_reason": finish_reason(&body["stopReason"], strict) }], "usage": usage })
}

fn cohere_chat(body: &Value, status: u16, strict: bool, request: &Value) -> Value {
    if status != 200 {
        if let Some(m) = body["message"].as_str() {
            return error("cohere", m, Value::Null, Value::Null, Value::Null);
        }
    }
    if body.get("message").is_none() || body.get("usage").is_none() {
        return invalid_response("cohere", body);
    }
    let tok = |k: &str| body["usage"]["tokens"][k].as_u64().or(body["usage"]["billed_units"][k].as_u64()).unwrap_or(0);
    let (p, c) = (tok("input_tokens"), tok("output_tokens"));
    let text: String = body["message"]["content"].as_array().into_iter().flatten().filter(|i| i["type"] == "text").filter_map(|i| i["text"].as_str()).collect();
    json!({ "id": body["id"], "model": request["model"].as_str().unwrap_or(""), "object": "chat.completion", "created": now(), "provider": "cohere",
        "choices": [{ "index": 0, "finish_reason": finish_reason(&body["finish_reason"], strict),
            "message": { "role": "assistant", "content": text, "tool_calls": body["message"]["tool_calls"] } }],
        "usage": { "completion_tokens": c, "prompt_tokens": p, "total_tokens": p + c } })
}

/// Copies `key` from `from` into `to` if present (JS spreads skip undefined).
fn copy(to: &mut Map<String, Value>, from: &Value, key: &str) {
    if let Some(v) = from.get(key) {
        to.insert(key.into(), v.clone());
    }
}

fn usage_or_zero(u: &Value) -> Value {
    let n = |k: &str| u[k].as_u64().unwrap_or(0);
    json!({ "prompt_tokens": n("prompt_tokens"), "completion_tokens": n("completion_tokens"), "total_tokens": n("total_tokens") })
}

/// TS GroqChatCompleteResponseTransform.
fn groq_chat(body: &Value, status: u16) -> Value {
    if body.get("error").is_some() && status != 200 {
        let e = &body["error"];
        let code = match &e["code"] {
            Value::Null => Value::Null,
            Value::String(s) => json!(s),
            other => json!(other.to_string()),
        };
        return error("groq", e["message"].as_str().unwrap_or(""), str_or_null(&e["type"]), Value::Null, code);
    }
    let Some(choices) = body["choices"].as_array() else { return invalid_response("groq", body) };
    let choices: Vec<Value> = choices
        .iter()
        .map(|c| {
            let mut m = Map::new();
            for k in ["index", "message", "logprobs", "finish_reason"] {
                copy(&mut m, c, k);
            }
            Value::Object(m)
        })
        .collect();
    let mut out = Map::new();
    for k in ["id", "object", "created", "model"] {
        copy(&mut out, body, k);
    }
    out.insert("provider".into(), json!("groq"));
    out.insert("choices".into(), json!(choices));
    out.insert("usage".into(), usage_or_zero(&body["usage"]));
    Value::Object(out)
}

/// TS GetMistralAIChatCompleteResponseTransform.
fn mistral_chat(body: &Value, status: u16, strict: bool, provider: &str) -> Value {
    if body.get("message").is_some() && status != 200 {
        return error(provider, body["message"].as_str().unwrap_or(""), str_or_null(&body["type"]), str_or_null(&body["param"]), str_or_null(&body["code"]));
    }
    let Some(choices) = body["choices"].as_array() else { return invalid_response(provider, body) };
    let choices: Vec<Value> = choices
        .iter()
        .map(|c| {
            let mut msg = Map::new();
            for k in ["role", "content", "tool_calls"] {
                copy(&mut msg, &c["message"], k);
            }
            let mut m = Map::new();
            copy(&mut m, c, "index");
            m.insert("message".into(), Value::Object(msg));
            m.insert("finish_reason".into(), finish_reason(&c["finish_reason"], strict));
            Value::Object(m)
        })
        .collect();
    let mut out = Map::new();
    for k in ["id", "object", "created", "model"] {
        copy(&mut out, body, k);
    }
    out.insert("provider".into(), json!(provider));
    out.insert("choices".into(), json!(choices));
    let mut usage = Map::new();
    for k in ["prompt_tokens", "completion_tokens", "total_tokens"] {
        copy(&mut usage, &body["usage"], k);
    }
    out.insert("usage".into(), Value::Object(usage));
    Value::Object(out)
}

/// OpenAI-compatible providers: errors in the gateway shape, provider added.
fn openai_like(body: &Value, status: u16, provider: &str) -> Value {
    // OpenAI and Azure OpenAI responses (and errors) are returned as-is.
    if matches!(provider, "openai" | "azure-openai") {
        return body.clone();
    }
    if status >= 400 || (body.get("error").is_some() && body.get("choices").is_none() && body.get("data").is_none()) {
        let e = if body["error"].is_object() { body["error"].clone() } else { body.clone() };
        let message = e["message"].as_str().map(str::to_string).or_else(|| body["error"].as_str().map(str::to_string)).unwrap_or_else(|| body.to_string());
        return error(provider, &message, str_or_null(&e["type"]), str_or_null(&e["param"]), str_or_null(&e["code"]));
    }
    let mut out = body.clone();
    if let Value::Object(m) = &mut out {
        m.insert("provider".into(), json!(provider));
    }
    out
}

/// Buffered response -> unified response for `fn_name`.
pub fn transform(provider: &str, fn_name: &str, family: Option<&str>, status: u16, body: &Value, strict: bool, request: &Value) -> Value {
    match (provider, family, fn_name) {
        ("anthropic", _, "chatComplete") => anthropic_chat(body, status, strict, "anthropic"),
        ("vertex-ai", Some("anthropic"), "chatComplete") => anthropic_chat(body, status, strict, "vertex-ai"),
        ("google", _, "chatComplete") => gemini_chat(body, status, strict, "google"),
        ("vertex-ai", Some("google"), "chatComplete") => gemini_chat(body, status, strict, "vertex-ai"),
        ("bedrock", _, "chatComplete") => bedrock_chat(body, status, strict, request),
        ("bedrock", f, "messages") if f != Some("anthropic") => bedrock_messages(body, status, request),
        ("cohere", _, "chatComplete") => cohere_chat(body, status, strict, request),
        ("groq", _, "chatComplete") => groq_chat(body, status),
        ("mistral-ai", _, "chatComplete") => mistral_chat(body, status, strict, "mistral-ai"),
        // Native Messages API (Anthropic format): errors only.
        (_, _, "messages") | (_, _, "messagesCountTokens") => {
            if status >= 400 && body.get("type") != Some(&json!("error")) {
                let msg = body["message"].as_str().or(body["error"]["message"].as_str()).unwrap_or("error");
                json!({ "type": "error", "error": { "type": "api_error", "message": format!("{provider} error: {msg}") } })
            } else {
                body.clone()
            }
        }
        _ => openai_like(body, status, provider),
    }
}

// --------------------------------------------------------------- streaming

/// How a provider's stream is framed.
#[derive(Clone, Copy, PartialEq)]
pub enum Framing {
    Delimited(&'static str),
    AwsEventStream,
}

pub fn framing(provider: &str, url: &str) -> Framing {
    match provider {
        "bedrock" => Framing::AwsEventStream,
        "anthropic" if url.ends_with("/complete") => Framing::Delimited("\r\n\r\n"),
        "cohere" => Framing::Delimited(if url.contains("/chat") { "\n\n" } else { "\n" }),
        "google" => Framing::Delimited("\r\n"),
        "vertex-ai" if url.contains("/publishers/google") => Framing::Delimited("\r\n\r\n"),
        "perplexity-ai" => Framing::Delimited("\r\n\r\n"),
        "deepinfra" | "sambanova" => Framing::Delimited("\n"),
        _ => Framing::Delimited("\n\n"),
    }
}

/// Stateful stream transformer: provider chunks in, OpenAI SSE chunks out.
pub struct StreamTx {
    provider: String,
    family: Option<String>,
    fn_name: String,
    framing: Framing,
    strict: bool,
    request: Value,
    id: String,
    buffer: Vec<u8>,
    state: Map<String, Value>,
}

impl StreamTx {
    pub fn new(provider: &str, family: Option<&str>, fn_name: &str, url: &str, strict: bool, request: Value) -> Self {
        Self {
            provider: provider.into(),
            family: family.map(str::to_string),
            fn_name: fn_name.into(),
            framing: framing(provider, url),
            strict,
            request,
            id: format!("portkey-{}", uuid::Uuid::new_v4()),
            buffer: Vec::new(),
            state: Map::new(),
        }
    }

    /// Whether this provider/fn needs transformation (else pass bytes through).
    pub fn needed(provider: &str, family: Option<&str>, fn_name: &str) -> bool {
        (provider == "bedrock" && fn_name == "messages" && family != Some("anthropic"))
            || (fn_name == "chatComplete"
                && (matches!(provider, "anthropic" | "google" | "bedrock" | "cohere" | "groq" | "mistral-ai")
                    || (provider == "vertex-ai" && matches!(family, Some("google" | "anthropic")))))
    }

    pub fn push(&mut self, bytes: &[u8]) -> String {
        self.buffer.extend_from_slice(bytes);
        let mut out = String::new();
        match self.framing {
            Framing::AwsEventStream => {
                while self.buffer.len() >= 4 {
                    let total = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap()) as usize;
                    if total < 16 || self.buffer.len() < total {
                        break;
                    }
                    let frame: Vec<u8> = self.buffer.drain(..total).collect();
                    let headers_len = u32::from_be_bytes(frame[4..8].try_into().unwrap()) as usize;
                    let payload = &frame[12 + headers_len..total - 4];
                    let text = String::from_utf8_lossy(payload).into_owned();
                    out.push_str(&self.chunk(&text));
                }
            }
            Framing::Delimited(sep) => {
                let sep_b = sep.as_bytes();
                while let Some(pos) = find(&self.buffer, sep_b) {
                    let chunk: Vec<u8> = self.buffer.drain(..pos + sep_b.len()).collect();
                    let text = String::from_utf8_lossy(&chunk[..pos]).into_owned();
                    if !text.trim().is_empty() {
                        out.push_str(&self.chunk(&text));
                    }
                }
            }
        }
        out
    }

    pub fn finish(&mut self) -> String {
        let rest = String::from_utf8_lossy(&std::mem::take(&mut self.buffer)).into_owned();
        let mut out = if rest.trim().is_empty() || self.framing == Framing::AwsEventStream { String::new() } else { self.chunk(&rest) };
        out
    }

    fn sse(v: Value) -> String {
        format!("data: {v}\n\n")
    }

    fn base(&self, model: Value) -> Value {
        json!({ "id": self.id, "object": "chat.completion.chunk", "created": now(), "model": model, "provider": self.provider })
    }

    fn chunk(&mut self, raw: &str) -> String {
        let result = match (self.provider.as_str(), self.family.as_deref()) {
            ("anthropic", _) | ("vertex-ai", Some("anthropic")) => self.anthropic(raw),
            ("google", _) | ("vertex-ai", Some("google")) => self.gemini(raw),
            ("bedrock", _) if self.fn_name == "messages" => self.bedrock_messages(raw),
            ("bedrock", _) => self.bedrock(raw),
            ("cohere", _) => self.cohere(raw),
            ("groq", _) => self.groq(raw),
            ("mistral-ai", _) => self.mistral(raw),
            _ => Some(format!("{raw}\n\n")),
        };
        result.unwrap_or_default()
    }

    /// TS GroqChatCompleteStreamChunkTransform.
    fn groq(&mut self, raw: &str) -> Option<String> {
        let chunk = raw.trim().strip_prefix("data: ").unwrap_or(raw.trim()).trim();
        if chunk == "[DONE]" {
            return Some("data: [DONE]\n\n".into());
        }
        let p: Value = serde_json::from_str(chunk).ok()?;
        let mut out = Map::new();
        for k in ["id", "object", "created", "model"] {
            copy(&mut out, &p, k);
        }
        out.insert("provider".into(), json!("groq"));
        let c0 = &p["choices"][0];
        let index = if c0["index"].as_u64().unwrap_or(0) == 0 { json!(0) } else { c0["index"].clone() };
        if p["x_groq"]["usage"].is_object() {
            let mut choice = json!({ "index": index, "delta": {}, "logprobs": null });
            if let Some(f) = c0.get("finish_reason") {
                choice["finish_reason"] = f.clone();
            }
            out.insert("choices".into(), json!([choice]));
            out.insert("usage".into(), usage_or_zero(&p["x_groq"]["usage"]));
            return Some(Self::sse(Value::Object(out)));
        }
        let choices = if p["choices"].as_array().is_some_and(|c| !c.is_empty()) {
            let d = &c0["delta"];
            let content = d["content"].as_str().filter(|s| !s.is_empty()).map(|s| json!(s)).unwrap_or(json!(""));
            let tools = if d["tool_calls"].is_null() { json!([]) } else { d["tool_calls"].clone() };
            let finish = if c0["finish_reason"].is_null() || c0["finish_reason"] == "" { Value::Null } else { c0["finish_reason"].clone() };
            json!([{ "index": index, "delta": { "role": "assistant", "content": content, "tool_calls": tools }, "logprobs": null, "finish_reason": finish }])
        } else {
            json!([])
        };
        out.insert("choices".into(), choices);
        if p["usage"].is_object() {
            out.insert("usage".into(), usage_or_zero(&p["usage"]));
        }
        Some(Self::sse(Value::Object(out)))
    }

    /// TS GetMistralAIChatCompleteStreamChunkTransform.
    fn mistral(&mut self, raw: &str) -> Option<String> {
        let chunk = raw.trim().strip_prefix("data: ").unwrap_or(raw.trim()).trim();
        if chunk == "[DONE]" {
            return Some("data: [DONE]\n\n".into());
        }
        let p: Value = serde_json::from_str(chunk).ok()?;
        let c0 = &p["choices"][0];
        let finish = if c0["finish_reason"].is_null() || c0["finish_reason"] == "" { Value::Null } else { finish_reason(&c0["finish_reason"], self.strict) };
        let mut choice = Map::new();
        copy(&mut choice, c0, "index");
        copy(&mut choice, c0, "delta");
        choice.insert("finish_reason".into(), finish);
        let mut out = Map::new();
        for k in ["id", "object", "created", "model"] {
            copy(&mut out, &p, k);
        }
        out.insert("provider".into(), json!(self.provider));
        out.insert("choices".into(), json!([choice]));
        if !p["usage"].is_null() {
            out.insert("usage".into(), p["usage"].clone());
        }
        Some(Self::sse(Value::Object(out)))
    }

    fn anthropic(&mut self, raw: &str) -> Option<String> {
        let chunk = raw.trim();
        if chunk.starts_with("event: ping") || chunk.starts_with("event: content_block_stop") {
            return None;
        }
        if chunk.starts_with("event: message_stop") {
            return Some("data: [DONE]\n\n".into());
        }
        let data = chunk.lines().find_map(|l| l.strip_prefix("data:")).unwrap_or(chunk).trim();
        let p: Value = serde_json::from_str(data).ok()?;
        let model = self.state.get("model").cloned().unwrap_or(json!(""));
        match p["type"].as_str() {
            Some("error") => {
                let mut c = self.base(json!(""));
                c["choices"] = json!([{ "finish_reason": p["error"]["type"], "delta": { "content": "" } }]);
                Some(format!("{}data: [DONE]\n\n", Self::sse(c)))
            }
            Some("message_start") => {
                let m = &p["message"];
                self.state.insert("model".into(), m["model"].clone());
                self.state.insert("usage".into(), m["usage"].clone());
                let mut c = self.base(m["model"].clone());
                c["choices"] = json!([{ "delta": { "content": "", "role": "assistant" }, "index": 0, "logprobs": null, "finish_reason": null }]);
                Some(Self::sse(c))
            }
            Some("message_delta") => {
                let start = self.state.get("usage").cloned().unwrap_or(json!({}));
                let u = &p["usage"];
                let pick = |k: &str| u[k].as_u64().or(start[k].as_u64()).unwrap_or(0);
                let (input, cr, cc) = (pick("input_tokens"), pick("cache_read_input_tokens"), pick("cache_creation_input_tokens"));
                let out = u["output_tokens"].as_u64().unwrap_or(0);
                let mut usage = json!({ "prompt_tokens": input + cr + cc, "completion_tokens": out, "total_tokens": input + cr + cc + out,
                    "prompt_tokens_details": { "cached_tokens": cr } });
                if cr > 0 || cc > 0 {
                    usage["cache_read_input_tokens"] = json!(cr);
                    usage["cache_creation_input_tokens"] = json!(cc);
                }
                let mut c = self.base(model);
                c["choices"] = json!([{ "index": 0, "delta": {}, "finish_reason": finish_reason(&p["delta"]["stop_reason"], self.strict) }]);
                c["usage"] = usage;
                Some(Self::sse(c))
            }
            // Any other event (text/tool/thinking block start or delta).
            _ => {
                let mut tool_index = self.state.get("toolIndex").and_then(Value::as_i64).unwrap_or(-1);
                let mut tool_calls = Vec::new();
                if p["type"] == "content_block_start" && p["content_block"]["type"] == "tool_use" {
                    tool_index += 1;
                    self.state.insert("toolIndex".into(), json!(tool_index));
                    tool_calls.push(json!({ "index": tool_index, "id": p["content_block"]["id"], "type": "function",
                        "function": { "name": p["content_block"]["name"], "arguments": "" } }));
                } else if p["type"] == "content_block_delta" && !p["delta"]["partial_json"].is_null() {
                    tool_calls.push(json!({ "index": tool_index, "function": { "arguments": p["delta"]["partial_json"] } }));
                }
                let mut delta = Map::new();
                if !p["delta"]["text"].is_null() {
                    delta.insert("content".into(), p["delta"]["text"].clone());
                }
                delta.insert("role".into(), json!("assistant"));
                if !tool_calls.is_empty() {
                    delta.insert("tool_calls".into(), json!(tool_calls));
                } else if !self.strict {
                    let mut block = p.get("delta").filter(|d| !d.is_null()).or(p.get("content_block").filter(|d| !d.is_null())).cloned().unwrap_or(json!({}));
                    if let Value::Object(m) = &mut block {
                        m.remove("type");
                    }
                    delta.insert("content_blocks".into(), json!([{ "index": p["index"], "delta": block }]));
                }
                let mut c = self.base(model);
                c["choices"] = json!([{ "delta": delta, "index": 0, "logprobs": null, "finish_reason": null }]);
                Some(Self::sse(c))
            }
        }
    }

    fn gemini(&mut self, raw: &str) -> Option<String> {
        let mut chunk = raw.trim();
        chunk = chunk.strip_prefix('[').unwrap_or(chunk);
        chunk = chunk.strip_suffix(',').unwrap_or(chunk);
        let mut owned = chunk.to_string();
        if owned.ends_with(']') {
            owned.truncate(owned.len().saturating_sub(2).max(0));
        }
        let data = owned.trim().strip_prefix("data: ").unwrap_or(owned.trim()).trim().to_string();
        if data == "[DONE]" {
            self.state.insert("done".into(), json!(true));
            return Some("data: [DONE]\n\n".into());
        }
        let p: Value = serde_json::from_str(&data).ok()?;
        let vertex = self.provider == "vertex-ai";
        let cot = self.state.get("cot").and_then(Value::as_bool).unwrap_or(false);
        let mut cot_now = cot;
        let choices: Vec<Value> = p["candidates"].as_array().into_iter().flatten().enumerate().map(|(i, g)| {
            let finish = if g["finishReason"].is_null() { Value::Null } else { finish_reason(&g["finishReason"], self.strict) };
            let parts = g["content"]["parts"].as_array().cloned().unwrap_or_default();
            let mut message = json!({ "role": "assistant", "content": "" });
            if parts.first().and_then(|x| x["text"].as_str()).is_some() {
                let mut content = String::new();
                let mut blocks = Vec::new();
                for part in &parts {
                    if part["thought"] == true {
                        blocks.push(json!({ "index": 0, "delta": { "thinking": part["text"] } }));
                        cot_now = true;
                    } else {
                        content.push_str(part["text"].as_str().unwrap_or(""));
                        blocks.push(json!({ "index": if cot_now { 1 } else { 0 }, "delta": { "text": part["text"] } }));
                    }
                }
                message = json!({ "role": "assistant", "content": content });
                if !self.strict && !blocks.is_empty() {
                    message["content_blocks"] = Value::Array(blocks);
                }
            } else if parts.first().is_some_and(|x| x["functionCall"].is_object()) {
                message = json!({ "role": "assistant", "tool_calls": parts.iter().enumerate().filter(|(_, x)| x["functionCall"].is_object()).map(|(idx, x)| {
                    let mut f = json!({ "name": x["functionCall"]["name"], "arguments": x["functionCall"]["args"].to_string() });
                    if !self.strict && x["thoughtSignature"].is_string() {
                        f["thought_signature"] = x["thoughtSignature"].clone();
                    }
                    json!({ "index": idx, "id": format!("portkey-{}", uuid::Uuid::new_v4()), "type": "function", "function": f })
                }).collect::<Vec<_>>() });
            } else if let Some(m) = g["finishMessage"].as_str() {
                message = json!({ "role": "assistant", "content": m });
            }
            let mut choice = json!({ "delta": message, "index": if vertex { json!(i) } else { g.get("index").cloned().unwrap_or(json!(i)) }, "finish_reason": finish });
            if !self.strict && vertex {
                choice["safetyRatings"] = g["safetyRatings"].clone();
            }
            choice
        }).collect();
        self.state.insert("cot".into(), json!(cot_now));
        let mut c = self.base(p["modelVersion"].clone());
        c["choices"] = Value::Array(choices);
        if p["usageMetadata"]["candidatesTokenCount"].as_u64().unwrap_or(0) > 0 {
            c["usage"] = gemini_usage(&p["usageMetadata"]);
        }
        Some(Self::sse(c))
    }

    /// TS BedrockConverseMessagesStreamChunkTransform: Converse events ->
    /// Anthropic Messages events.
    fn bedrock_messages(&mut self, raw: &str) -> Option<String> {
        let p: Value = serde_json::from_str(raw).ok()?;
        let ev = |name: &str, data: Value| format!("event: {name}\ndata: {data}\n\n");
        let current = self.state.get("blockIndex").and_then(Value::as_i64).unwrap_or(-1);
        if !p["stopReason"].is_null() {
            self.state.insert("stopReason".into(), p["stopReason"].clone());
        }
        if !p["role"].is_null() {
            return Some(ev("message_start", json!({ "type": "message_start", "message": {
                "id": self.id, "type": "message", "role": "assistant", "model": self.request["model"], "content": [],
                "stop_reason": null, "stop_sequence": null,
                "usage": { "input_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 0 } } })));
        }
        let delta_event = |p: &Value| -> Option<String> {
            let d = &p["delta"];
            let idx = p["contentBlockIndex"].as_i64()?;
            let delta = if d["text"].as_str().is_some_and(|t| !t.is_empty()) {
                json!({ "type": "text_delta", "text": d["text"] })
            } else if d["reasoningContent"]["text"].as_str().is_some_and(|t| !t.is_empty()) {
                json!({ "type": "thinking_delta", "thinking": d["reasoningContent"]["text"] })
            } else if d["reasoningContent"]["signature"].as_str().is_some_and(|t| !t.is_empty()) {
                json!({ "type": "signature_delta", "signature": d["reasoningContent"]["signature"] })
            } else if d["toolUse"].is_object() {
                json!({ "type": "input_json_delta", "partial_json": d["toolUse"]["input"] })
            } else {
                return None;
            };
            Some(ev("content_block_delta", json!({ "type": "content_block_delta", "index": idx, "delta": delta })))
        };
        if let Some(idx) = p["contentBlockIndex"].as_i64().filter(|i| *i != current) {
            let mut out = String::new();
            if current != -1 {
                out.push_str(&ev("content_block_stop", json!({ "type": "content_block_stop", "index": idx - 1 })));
            }
            self.state.insert("blockIndex".into(), json!(idx));
            let block = if p["start"]["toolUse"]["toolUseId"].as_str().is_some_and(|t| !t.is_empty()) {
                json!({ "type": "tool_use", "id": p["start"]["toolUse"]["toolUseId"], "name": p["start"]["toolUse"]["name"], "input": {} })
            } else if p["delta"]["reasoningContent"].get("text").is_some() {
                json!({ "type": "thinking", "thinking": "", "signature": "" })
            } else if !p["delta"]["reasoningContent"]["redactedContent"].is_null() {
                json!({ "type": "redacted_thinking", "data": p["delta"]["reasoningContent"]["redactedContent"] })
            } else {
                json!({ "type": "text", "text": "" })
            };
            out.push_str(&ev("content_block_start", json!({ "type": "content_block_start", "index": idx, "content_block": block })));
            if p.get("delta").is_some() {
                out.push_str(&delta_event(&p).unwrap_or_default());
            }
            return Some(out);
        }
        if p.get("delta").is_some() {
            if let Some(e) = delta_event(&p) {
                return Some(e);
            }
        }
        if p["usage"].is_object() {
            let u = &p["usage"];
            let stop = anthropic_stop_reason(self.state.get("stopReason").unwrap_or(&Value::Null));
            let mut usage = json!({ "input_tokens": u["inputTokens"], "output_tokens": u["outputTokens"],
                "cache_read_input_tokens": u["cacheReadInputTokens"], "cache_creation_input_tokens": u["cacheWriteInputTokens"] });
            if let Value::Object(m) = &mut usage {
                m.retain(|_, v| !v.is_null());
            }
            let mut out = ev("content_block_stop", json!({ "type": "content_block_stop", "index": current }));
            out.push_str(&ev("message_delta", json!({ "type": "message_delta", "delta": { "stop_reason": stop, "stop_sequence": null }, "usage": usage })));
            out.push_str(&ev("message_stop", json!({ "type": "message_stop" })));
            return Some(out);
        }
        None
    }

    fn bedrock(&mut self, raw: &str) -> Option<String> {
        let p: Value = serde_json::from_str(raw).ok()?;
        let model = json!(self.request["model"].as_str().unwrap_or(""));
        if p["message"].is_string() {
            let mut c = self.base(model);
            c["choices"] = json!([{ "index": 0, "delta": { "role": "assistant", "content": "" }, "finish_reason": "stop" }]);
            return Some(format!("{}data: [DONE]\n\n", Self::sse(c)));
        }
        if !p["stopReason"].is_null() {
            self.state.insert("stopReason".into(), p["stopReason"].clone());
        }
        let mut idx = self.state.get("toolIndex").and_then(Value::as_i64).unwrap_or(-1);
        if p["usage"].is_object() {
            let u = &p["usage"];
            let (cr, cw) = (u["cacheReadInputTokens"].as_u64().unwrap_or(0), u["cacheWriteInputTokens"].as_u64().unwrap_or(0));
            let mut usage = json!({ "prompt_tokens": u["inputTokens"].as_u64().unwrap_or(0) + cr + cw, "completion_tokens": u["outputTokens"],
                "total_tokens": u["totalTokens"], "prompt_tokens_details": { "cached_tokens": cr } });
            if cr > 0 || cw > 0 {
                usage["cache_read_input_tokens"] = json!(cr);
                usage["cache_creation_input_tokens"] = json!(cw);
            }
            let stop = self.state.get("stopReason").cloned().unwrap_or(Value::Null);
            let mut c = self.base(model);
            c["choices"] = json!([{ "index": 0, "delta": {}, "finish_reason": finish_reason(&stop, self.strict) }]);
            c["usage"] = usage;
            return Some(format!("{}data: [DONE]\n\n", Self::sse(c)));
        }
        let mut tool_calls = Vec::new();
        if p["start"]["toolUse"].is_object() {
            idx += 1;
            self.state.insert("toolIndex".into(), json!(idx));
            let t = &p["start"]["toolUse"];
            tool_calls.push(json!({ "index": idx, "id": t["toolUseId"], "type": "function", "function": { "name": t["name"], "arguments": t["input"] } }));
        } else if p["delta"]["toolUse"].is_object() {
            let t = &p["delta"]["toolUse"];
            tool_calls.push(json!({ "index": idx, "id": t["toolUseId"], "type": "function", "function": { "name": t["name"], "arguments": t["input"] } }));
        }
        let mut block = Map::new();
        let rc = &p["delta"]["reasoningContent"];
        if rc["text"].is_string() { block.insert("thinking".into(), rc["text"].clone()); }
        if rc["signature"].is_string() { block.insert("signature".into(), rc["signature"].clone()); }
        if p["delta"]["text"].is_string() { block.insert("text".into(), p["delta"]["text"].clone()); }
        if !rc["redactedContent"].is_null() { block.insert("data".into(), rc["redactedContent"].clone()); }
        let mut delta = json!({ "role": "assistant" });
        if !p["delta"]["text"].is_null() {
            delta["content"] = p["delta"]["text"].clone();
        }
        if !self.strict && tool_calls.is_empty() && !block.is_empty() {
            delta["content_blocks"] = json!([{ "index": p.get("contentBlockIndex").cloned().unwrap_or(json!(0)), "delta": block }]);
        }
        if !tool_calls.is_empty() {
            delta["tool_calls"] = Value::Array(tool_calls);
        }
        let mut c = self.base(model);
        c["choices"] = json!([{ "index": 0, "delta": delta, "finish_reason": null }]);
        Some(Self::sse(c))
    }

    fn cohere(&mut self, raw: &str) -> Option<String> {
        let data = raw.trim().lines().find_map(|l| l.strip_prefix("data:")).unwrap_or(raw.trim()).trim();
        let p: Value = serde_json::from_str(data).ok()?;
        let model = json!(self.request["model"].as_str().unwrap_or(""));
        if p["type"] == "message-start" {
            self.state.insert("id".into(), p["id"].clone());
        }
        let id = self.state.get("id").cloned().unwrap_or(json!(""));
        let last = self.state.get("lastIndex").cloned().unwrap_or(json!(0));
        if p["type"] == "message-end" {
            let u = &p["delta"]["usage"];
            let tok = |k: &str| u["tokens"][k].as_u64().or(u["billed_units"][k].as_u64()).unwrap_or(0);
            let (pt, ct) = (tok("input_tokens"), tok("output_tokens"));
            let c = json!({ "id": id, "object": "chat.completion.chunk", "created": now(), "model": model,
                "choices": [{ "index": last, "delta": {}, "logprobs": null, "finish_reason": finish_reason(&p["delta"]["finish_reason"], self.strict) }],
                "usage": { "completion_tokens": ct, "prompt_tokens": pt, "total_tokens": pt + ct } });
            return Some(format!("{}data: [DONE]\n\n", Self::sse(c)));
        }
        if let Some(i) = p.get("index").filter(|i| **i != last) {
            self.state.insert("lastIndex".into(), i.clone());
        }
        let last = self.state.get("lastIndex").cloned().unwrap_or(json!(0));
        let c = json!({ "id": id, "object": "chat.completion.chunk", "created": now(), "model": model, "system_fingerprint": null,
            "choices": [{ "index": last, "delta": { "role": "assistant", "content": p["delta"]["message"]["content"]["text"].as_str().unwrap_or(""),
                "tool_calls": p["delta"]["message"]["tool_calls"] }, "logprobs": null, "finish_reason": null }] });
        Some(Self::sse(c))
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_to_openai() {
        let r = transform("anthropic", "chatComplete", None, 200, &json!({"id":"m1","model":"claude","content":[{"type":"text","text":"hi"},{"type":"tool_use","id":"t","name":"f","input":{"a":1}}],"stop_reason":"tool_use","usage":{"input_tokens":3,"output_tokens":2}}), true, &json!({}));
        assert_eq!(r["choices"][0]["message"]["content"], "hi");
        assert_eq!(r["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(r["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"], "{\"a\":1}");
        assert_eq!(r["usage"]["total_tokens"], 5);
    }

    #[test]
    fn errors_use_gateway_shape() {
        let r = transform("groq", "chatComplete", None, 401, &json!({"error":{"message":"bad key","type":"invalid_request_error"}}), true, &json!({}));
        assert_eq!(r["error"]["message"], "groq error: bad key");
        assert_eq!(r["provider"], "groq");
    }

    #[test]
    fn aws_event_stream_frames() {
        let payload = br#"{"contentBlockIndex":0,"delta":{"text":"Hi"}}"#;
        let total = 12 + payload.len() + 4;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(total as u32).to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&0u32.to_be_bytes());
        let mut tx = StreamTx::new("bedrock", Some("anthropic"), "chatComplete", "https://x/converse-stream", true, json!({"model":"m"}));
        let (a, b) = frame.split_at(10);
        assert_eq!(tx.push(a), "");
        let out = tx.push(b);
        assert!(out.contains("\"content\":\"Hi\""), "{out}");
    }
}
