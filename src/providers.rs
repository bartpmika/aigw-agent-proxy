//! Provider specifics: endpoints, upstream URLs/auth for configured targets,
//! token usage, and Anthropic Messages <-> OpenAI Chat translation (including
//! streaming) for cross-provider routing.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Messages,
    CountTokens,
    Complete,
    ChatCompletions,
    Completions,
    Responses,
    Embeddings,
}

impl Endpoint {
    pub fn from_path(path: &str) -> Option<Self> {
        Some(match path {
            "/v1/messages" => Self::Messages,
            "/v1/messages/count_tokens" => Self::CountTokens,
            "/v1/complete" => Self::Complete,
            "/v1/chat/completions" => Self::ChatCompletions,
            "/v1/completions" => Self::Completions,
            "/v1/responses" | "/backend-api/codex/responses" => Self::Responses,
            "/v1/embeddings" => Self::Embeddings,
            _ => return None,
        })
    }
}

/// Token usage for analytics and cost.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    /// All prompt tokens, including cache reads and writes.
    pub req_units: u64,
    pub res_units: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.req_units + self.res_units
    }

    pub fn from_json(body: &Value) -> Self {
        let u = &body["usage"];
        if u.is_null() {
            return Self::default();
        }
        if u.get("prompt_tokens").is_some() || u.get("completion_tokens").is_some() {
            return Self {
                req_units: u["prompt_tokens"].as_u64().unwrap_or(0),
                res_units: u["completion_tokens"].as_u64().unwrap_or(0),
                cache_read: u["prompt_tokens_details"]["cached_tokens"].as_u64().unwrap_or(0),
                cache_write: 0,
            };
        }
        let cache_read = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
        let cache_write = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
        // Responses API reports cached tokens inside input_tokens already.
        let responses_cached = u["input_tokens_details"]["cached_tokens"].as_u64();
        Self {
            req_units: u["input_tokens"].as_u64().unwrap_or(0)
                + if responses_cached.is_some() { 0 } else { cache_read + cache_write },
            res_units: u["output_tokens"].as_u64().unwrap_or(0),
            cache_read: responses_cached.unwrap_or(cache_read),
            cache_write,
        }
    }

    /// Usage from an SSE body (Anthropic, OpenAI Chat or Responses).
    pub fn from_sse(body: &str) -> Self {
        let mut usage = Self::default();
        for event in sse_data(body) {
            match event["type"].as_str() {
                Some("message_start") => {
                    let u = Self::from_json(&event["message"]);
                    usage.req_units = u.req_units;
                    usage.cache_read = u.cache_read;
                    usage.cache_write = u.cache_write;
                    usage.res_units = u.res_units;
                }
                Some("message_delta") => {
                    if let Some(out) = event["usage"]["output_tokens"].as_u64() {
                        usage.res_units = out;
                    }
                }
                Some("response.completed") => usage = Self::from_json(&event["response"]),
                _ if !event["usage"].is_null() => usage = Self::from_json(&event),
                _ => {}
            }
        }
        usage
    }
}

/// The parsed JSON payloads of an SSE body's `data:` lines.
pub fn sse_data(body: &str) -> impl Iterator<Item = Value> + '_ {
    body.lines().filter_map(|l| {
        let d = l.strip_prefix("data:")?.trim();
        if d.is_empty() || d == "[DONE]" {
            return None;
        }
        serde_json::from_str(d).ok()
    })
}

/// Rebuilds the complete response from a stream, for output guardrails/logs.
pub fn assemble_stream(endpoint: Endpoint, body: &str) -> Option<Value> {
    match endpoint {
        Endpoint::Messages => {
            let mut message = json!({ "type": "message", "content": [] });
            // Per block: the block, plus text/thinking/tool-JSON accumulators.
            let mut blocks: Vec<(Value, String, String, String)> = Vec::new();
            let slot = |blocks: &mut Vec<(Value, String, String, String)>, i: usize| {
                while blocks.len() <= i {
                    blocks.push((json!({"type":"text"}), String::new(), String::new(), String::new()));
                }
            };
            for e in sse_data(body) {
                match e["type"].as_str() {
                    Some("message_start") => {
                        message = e["message"].clone();
                        message["content"] = json!([]);
                    }
                    Some("content_block_start") => {
                        let i = e["index"].as_u64().unwrap_or(0) as usize;
                        slot(&mut blocks, i);
                        blocks[i].0 = e["content_block"].clone();
                    }
                    Some("content_block_delta") => {
                        let i = e["index"].as_u64().unwrap_or(0) as usize;
                        slot(&mut blocks, i);
                        let d = &e["delta"];
                        let (_, text, thinking, partial) = &mut blocks[i];
                        match d["type"].as_str() {
                            Some("text_delta") => text.push_str(d["text"].as_str().unwrap_or("")),
                            Some("thinking_delta") => thinking.push_str(d["thinking"].as_str().unwrap_or("")),
                            Some("input_json_delta") => partial.push_str(d["partial_json"].as_str().unwrap_or("")),
                            _ => {}
                        }
                    }
                    Some("message_delta") => {
                        if let Some(d) = e["delta"].as_object() {
                            for (k, v) in d {
                                message[k] = v.clone();
                            }
                        }
                        if let Some(out) = e["usage"]["output_tokens"].as_u64() {
                            message["usage"]["output_tokens"] = json!(out);
                        }
                    }
                    _ => {}
                }
            }
            let content: Vec<Value> = blocks
                .into_iter()
                .map(|(mut b, text, thinking, partial)| {
                    match b["type"].as_str() {
                        Some("tool_use") if !partial.is_empty() => {
                            // Unparseable partial JSON is still scanned as text.
                            b["input"] = serde_json::from_str(&partial).unwrap_or(json!({ "_raw": partial }));
                        }
                        Some("thinking") => b["thinking"] = json!(format!("{}{thinking}", b["thinking"].as_str().unwrap_or(""))),
                        _ => b["text"] = json!(format!("{}{text}", b["text"].as_str().unwrap_or(""))),
                    }
                    b
                })
                .collect();
            message["content"] = Value::Array(content);
            Some(message)
        }
        Endpoint::ChatCompletions => {
            let (mut content, mut tool_args, mut model, mut id) =
                (String::new(), Vec::<String>::new(), Value::Null, Value::Null);
            let mut usage = Value::Null;
            for e in sse_data(body) {
                id = e["id"].clone();
                model = e["model"].clone();
                let d = &e["choices"][0]["delta"];
                if let Some(t) = d["content"].as_str() {
                    content.push_str(t);
                }
                for c in d["tool_calls"].as_array().cloned().unwrap_or_default() {
                    let i = c["index"].as_u64().unwrap_or(0) as usize;
                    while tool_args.len() <= i {
                        tool_args.push(String::new());
                    }
                    tool_args[i].push_str(c["function"]["arguments"].as_str().unwrap_or(""));
                }
                if !e["usage"].is_null() {
                    usage = e["usage"].clone();
                }
            }
            let calls: Vec<Value> = tool_args
                .into_iter()
                .map(|a| json!({ "type": "function", "function": { "arguments": a } }))
                .collect();
            Some(json!({
                "id": id, "object": "chat.completion", "model": model, "usage": usage,
                "choices": [{ "index": 0, "message": { "role": "assistant", "content": content, "tool_calls": calls } }],
            }))
        }
        Endpoint::Responses => sse_data(body)
            .filter(|e| e["type"] == "response.completed")
            .last()
            .map(|e| e["response"].clone()),
        _ => None,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_from_anthropic_and_openai() {
        let a = Usage::from_json(&json!({"usage":{"input_tokens":10,"output_tokens":3,"cache_read_input_tokens":5}}));
        assert_eq!((a.req_units, a.res_units, a.cache_read), (15, 3, 5));
        let o = Usage::from_json(&json!({"usage":{"prompt_tokens":8,"completion_tokens":2}}));
        assert_eq!((o.req_units, o.res_units), (8, 2));
        let s = Usage::from_sse("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n");
        assert_eq!((s.req_units, s.res_units), (11, 5));
    }

}
