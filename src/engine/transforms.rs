//! Hand-ported param transforms, keyed by the fingerprint of the TypeScript
//! function they replace (see `data/providers.inventory.json` for sources).
//! A transform returning `Value::Null` omits the field (TS `undefined`).

use serde_json::{json, Map, Value};

type Transform = fn(&Value, &Map<String, Value>) -> Value;

const SYSTEM_ROLES: [&str; 2] = ["system", "developer"];

fn is_system(m: &Value) -> bool {
    m["role"].as_str().is_some_and(|r| SYSTEM_ROLES.contains(&r))
}

fn opt<'a>(o: &'a Map<String, Value>, k: &str) -> Option<&'a Value> {
    o.get(k).filter(|v| !v.is_null() && v.as_str() != Some(""))
}

fn ephemeral_if(item: &Value) -> Option<Value> {
    (!item["cache_control"].is_null()).then(|| json!({ "type": "ephemeral" }))
}

fn insert_opt(m: &mut Map<String, Value>, k: &str, v: Option<Value>) {
    if let Some(v) = v {
        m.insert(k.into(), v);
    }
}

fn parse_args(args: &Value) -> Value {
    match args.as_str() {
        Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or(json!({})),
        _ => json!({}),
    }
}

// ---------------------------------------------------------------- Anthropic

fn anthropic_image(item: &Value, content: &mut Vec<Value>) {
    let Some(url) = item["image_url"]["url"].as_str() else { return };
    if !url.starts_with("data:") {
        content.push(json!({ "type": "image", "source": { "type": "url", "url": url } }));
        return;
    }
    let parts: Vec<&str> = url.split(';').collect();
    if parts.len() != 2 {
        return;
    }
    let data = parts[1].split(',').nth(1);
    let media: Vec<&str> = parts[0].split(':').collect();
    if let (2, Some(data)) = (media.len(), data) {
        let media_type = media[1];
        let mut block = json!({
            "type": if media_type == "application/pdf" { "document" } else { "image" },
            "source": { "type": "base64", "media_type": media_type, "data": data },
        });
        if let Some(e) = ephemeral_if(item) {
            block["cache_control"] = e;
        }
        content.push(block);
    }
}

fn anthropic_file(item: &Value, content: &mut Vec<Value>) {
    let mime = item["file"]["mime_type"].as_str().unwrap_or("application/pdf");
    if let Some(url) = item["file"]["file_url"].as_str() {
        content.push(json!({ "type": "document", "source": { "type": "url", "url": url } }));
    } else if !item["file"]["file_data"].is_null() {
        let kind = if mime == "text/plain" { "text" } else { "base64" };
        content.push(json!({ "type": "document", "source": { "type": kind, "data": item["file"]["file_data"], "media_type": mime } }));
    }
}

fn anthropic_assistant(msg: &Value) -> Value {
    let mut content = Vec::new();
    let input = if msg["content_blocks"].is_null() { &msg["content"] } else { &msg["content_blocks"] };
    match input {
        Value::String(s) if !s.is_empty() => content.push(json!({ "type": "text", "text": s })),
        Value::Array(items) => content.extend(items.iter().filter(|i| i["type"] != "tool_use").cloned()),
        _ => {}
    }
    for call in msg["tool_calls"].as_array().into_iter().flatten() {
        let mut block = json!({
            "type": "tool_use",
            "name": call["function"]["name"],
            "id": call["id"],
            "input": parse_args(&call["function"]["arguments"]),
        });
        if !call["cache_control"].is_null() {
            block["cache_control"] = call["cache_control"].clone();
        }
        content.push(block);
    }
    json!({ "role": msg["role"], "content": content })
}

/// aaa605f69d: OpenAI messages -> Anthropic messages.
fn anthropic_messages(p: &Value, _: &Map<String, Value>) -> Value {
    let mut out = Vec::new();
    for msg in p["messages"].as_array().into_iter().flatten() {
        if is_system(msg) {
            continue;
        }
        match msg["role"].as_str() {
            Some("assistant") => out.push(anthropic_assistant(msg)),
            Some("tool") => out.push(json!({ "role": "user", "content": [{
                "type": "tool_result", "tool_use_id": msg["tool_call_id"].as_str().unwrap_or(""), "content": msg["content"] }] })),
            _ => match &msg["content"] {
                Value::Array(items) if !items.is_empty() => {
                    let mut content = Vec::new();
                    for item in items {
                        match item["type"].as_str() {
                            Some("text") => {
                                let mut b = json!({ "type": "text", "text": item["text"] });
                                if let Some(e) = ephemeral_if(item) {
                                    b["cache_control"] = e;
                                }
                                content.push(b);
                            }
                            Some("image_url") => anthropic_image(item, &mut content),
                            Some("file") => anthropic_file(item, &mut content),
                            _ => {}
                        }
                    }
                    out.push(json!({ "role": msg["role"], "content": content }));
                }
                c => out.push(json!({ "role": msg["role"], "content": c })),
            },
        }
    }
    Value::Array(out)
}

/// 98a5cd2629: system messages -> Anthropic `system` blocks.
fn anthropic_system(p: &Value, _: &Map<String, Value>) -> Value {
    let mut out = Vec::new();
    for msg in p["messages"].as_array().into_iter().flatten().filter(|m| is_system(m)) {
        match &msg["content"] {
            Value::Array(items) if !items.is_empty() && !items[0]["text"].is_null() => {
                for item in items {
                    let mut b = json!({ "text": item["text"], "type": "text" });
                    if let Some(e) = ephemeral_if(item) {
                        b["cache_control"] = e;
                    }
                    out.push(b);
                }
            }
            Value::String(s) => {
                let mut b = Map::new();
                insert_opt(&mut b, "cache_control", ephemeral_if(msg));
                b.insert("text".into(), json!(s));
                b.insert("type".into(), json!("text"));
                out.push(Value::Object(b));
            }
            _ => {}
        }
    }
    Value::Array(out)
}

/// a0c27b6d65: OpenAI tools -> Anthropic tools.
fn anthropic_tools(p: &Value, _: &Map<String, Value>) -> Value {
    let mut out = Vec::new();
    for tool in p["tools"].as_array().into_iter().flatten() {
        let f = &tool["function"];
        if f.is_object() {
            let params = &f["parameters"];
            let mut t = json!({
                "name": f["name"],
                "description": f["description"].as_str().unwrap_or(""),
                "input_schema": {
                    "type": params["type"].as_str().unwrap_or("object"),
                    "properties": if params["properties"].is_null() { json!({}) } else { params["properties"].clone() },
                    "required": if params["required"].is_null() { json!([]) } else { params["required"].clone() },
                    "$defs": if params["$defs"].is_null() { json!({}) } else { params["$defs"].clone() },
                },
            });
            if let Some(e) = ephemeral_if(tool) {
                t["cache_control"] = e;
            }
            for k in ["defer_loading", "allowed_callers", "input_examples", "strict"] {
                if !f[k].is_null() {
                    t[k] = f[k].clone();
                }
            }
            out.push(t);
        } else if let Some(kind) = tool["type"].as_str() {
            let mut t = tool[kind].as_object().cloned().unwrap_or_default();
            let inner_name = t.get("name").cloned();
            t.insert("name".into(), json!(kind));
            t.insert("type".into(), inner_name.unwrap_or(Value::Null));
            if let Some(e) = ephemeral_if(tool) {
                t.insert("cache_control".into(), e);
            }
            out.push(Value::Object(t));
        }
    }
    Value::Array(out)
}

/// 535a2054fc: tool_choice -> Anthropic tool_choice.
fn anthropic_tool_choice(p: &Value, _: &Map<String, Value>) -> Value {
    match &p["tool_choice"] {
        Value::String(s) => match s.as_str() {
            "required" => json!({ "type": "any" }),
            "auto" => json!({ "type": "auto" }),
            "none" => json!({ "type": "none" }),
            _ => Value::Null,
        },
        Value::Object(_) => json!({ "type": "tool", "name": p["tool_choice"]["function"]["name"] }),
        _ => Value::Null,
    }
}

/// 31f44a2e24: response_format / reasoning_effort -> output_config.
fn anthropic_output_config(p: &Value, _: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    if p["response_format"]["type"] == "json_schema" {
        let js = &p["response_format"]["json_schema"];
        out.insert("format".into(), json!({ "type": "json_schema", "schema": if js["schema"].is_null() { js.clone() } else { js["schema"].clone() } }));
    }
    if !p["reasoning_effort"].is_null() {
        out.insert("effort".into(), p["reasoning_effort"].clone());
    }
    if out.is_empty() { Value::Null } else { Value::Object(out) }
}

fn anthropic_adaptive_thinking(_: &Value, _: &Map<String, Value>) -> Value {
    json!({ "type": "adaptive" })
}

fn anthropic_complete_prompt(p: &Value, _: &Map<String, Value>) -> Value {
    json!(format!("\n\nHuman: {}\n\nAssistant:", p["prompt"].as_str().unwrap_or("")))
}

fn stop_null_to_empty(p: &Value, _: &Map<String, Value>) -> Value {
    if p["stop"].is_null() { json!([]) } else { p["stop"].clone() }
}

// ---------------------------------------------------------- Gemini / Vertex

const SYSTEM_INSTRUCTION_DISABLED: [&str; 6] = [
    "gemini-1.0-pro", "gemini-1.0-pro-001", "gemini-1.0-pro-latest",
    "gemini-1.0-pro-vision-latest", "gemini-pro", "gemini-pro-vision",
];

fn google_role(role: &str) -> &str {
    match role {
        "assistant" => "model",
        "tool" => "function",
        "developer" => "system",
        r => r,
    }
}

fn thought_signature(model: &str, given: &Value) -> Option<Value> {
    if let Some(s) = given.as_str().filter(|s| !s.is_empty()) {
        return Some(json!(s));
    }
    if ["gemini-1.5", "gemini-2.0", "gemini-2.5"].iter().any(|m| model.contains(m)) {
        return None;
    }
    Some(json!("skip_thought_signature_validator"))
}

fn mime_from_url(url: &str) -> Option<&'static str> {
    let ext = url.rsplit('.').next()?.to_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "mp3" => "audio/mp3",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "txt" => "text/plain",
        _ => return None,
    })
}

fn audio_mime(format: &str) -> String {
    match format {
        "mp3" => "audio/mp3".into(),
        "wav" => "audio/wav".into(),
        "flac" => "audio/flac".into(),
        "ogg" => "audio/ogg".into(),
        "webm" => "audio/webm".into(),
        f => f.into(),
    }
}

/// 201b796e3c / a0d9bd1628: OpenAI messages -> Gemini contents.
fn gemini_contents(p: &Value, _: &Map<String, Value>) -> Value {
    let model = p["model"].as_str().unwrap_or("");
    let system_disabled = SYSTEM_INSTRUCTION_DISABLED.contains(&model);
    let mut out: Vec<Value> = Vec::new();
    let mut last_role: Option<String> = None;
    for msg in p["messages"].as_array().into_iter().flatten() {
        if is_system(msg) && !system_disabled {
            continue;
        }
        let role = google_role(msg["role"].as_str().unwrap_or("user")).to_string();
        let mut parts = Vec::new();
        if msg["role"] == "assistant" && msg["tool_calls"].is_array() {
            for call in msg["tool_calls"].as_array().into_iter().flatten() {
                let mut part = json!({ "functionCall": { "name": call["function"]["name"], "args": parse_args(&call["function"]["arguments"]) } });
                if let Some(sig) = thought_signature(model, &call["function"]["thought_signature"]) {
                    part["thoughtSignature"] = sig;
                }
                parts.push(part);
            }
        } else if msg["role"] == "tool" {
            let name = msg["name"].as_str().unwrap_or("gateway-tool-filler-name");
            match &msg["content"] {
                Value::String(s) => parts.push(json!({ "functionResponse": { "name": name, "response": { "content": s } } })),
                Value::Array(items) => parts.extend(items.iter().map(|i| json!({ "functionResponse": { "name": name, "response": { "content": i["text"] } } }))),
                _ => {}
            }
        } else if let Value::Array(items) = &msg["content"] {
            for c in items {
                match c["type"].as_str() {
                    Some("text") => parts.push(json!({ "text": c["text"] })),
                    Some("input_audio") => parts.push(json!({ "inlineData": {
                        "data": c["input_audio"]["data"], "mimeType": audio_mime(c["input_audio"]["format"].as_str().unwrap_or("")) } })),
                    Some("image_url") => {
                        let Some(url) = c["image_url"]["url"].as_str() else { continue };
                        let res = &c["image_url"]["media_resolution"];
                        let mut part = if let Some(rest) = url.strip_prefix("data:") {
                            let (mime, data) = rest.split_once(";base64,").unwrap_or((rest, ""));
                            json!({ "inlineData": { "mimeType": mime, "data": data } })
                        } else if url.starts_with("gs://") || url.starts_with("https://") || url.starts_with("http://") {
                            let mime = c["image_url"]["mime_type"].as_str().map(str::to_string).or(mime_from_url(url).map(str::to_string));
                            json!({ "fileData": { "mimeType": mime, "fileUri": url } })
                        } else {
                            json!({ "inlineData": { "mimeType": "image/jpeg", "data": url } })
                        };
                        if !res.is_null() {
                            part["mediaResolution"] = res.clone();
                        }
                        parts.push(part);
                    }
                    _ => {}
                }
            }
        } else if let Some(s) = msg["content"].as_str() {
            parts.push(json!({ "text": s }));
        }
        let combine = last_role.as_deref() == Some(role.as_str()) && !model.contains("vision");
        if combine {
            if let Some(Value::Array(prev)) = out.last_mut().map(|m| &mut m["parts"]) {
                prev.extend(parts);
            }
        } else {
            out.push(json!({ "role": role, "parts": parts }));
        }
        last_role = Some(role);
    }
    Value::Array(out)
}

/// 68ae0e005c: first system message -> systemInstruction.
fn gemini_system(p: &Value, _: &Map<String, Value>) -> Value {
    if SYSTEM_INSTRUCTION_DISABLED.contains(&p["model"].as_str().unwrap_or("")) {
        return Value::Null;
    }
    let first = &p["messages"][0];
    if !is_system(first) {
        return Value::Null;
    }
    match &first["content"] {
        Value::String(s) => json!({ "parts": [{ "text": s }], "role": "system" }),
        Value::Array(a) if !a.is_empty() && !a[0]["text"].is_null() => json!({ "parts": [{ "text": a[0]["text"] }], "role": "system" }),
        _ => Value::Null,
    }
}

fn present(v: &Value) -> bool {
    !v.is_null()
}

/// f42c3f4d69: OpenAI params -> Gemini generationConfig.
fn gemini_generation_config(p: &Value, _: &Map<String, Value>) -> Value {
    let mut g = Map::new();
    for (from, to) in [("temperature", "temperature"), ("top_p", "topP"), ("top_k", "topK"), ("max_tokens", "maxOutputTokens"), ("max_completion_tokens", "maxOutputTokens")] {
        if present(&p[from]) {
            g.insert(to.into(), p[from].clone());
        }
    }
    if !p["stop"].is_null() && p["stop"] != json!("") {
        g.insert("stopSequences".into(), p["stop"].clone());
    }
    if p["response_format"]["type"] == "json_object" {
        g.insert("responseMimeType".into(), json!("application/json"));
    }
    if p["logprobs"].as_bool() == Some(true) {
        g.insert("responseLogprobs".into(), p["logprobs"].clone());
    }
    if present(&p["top_logprobs"]) {
        g.insert("logprobs".into(), p["top_logprobs"].clone());
    }
    if present(&p["seed"]) {
        g.insert("seed".into(), p["seed"].clone());
    }
    if p["response_format"]["type"] == "json_schema" {
        let js = &p["response_format"]["json_schema"];
        g.insert("responseMimeType".into(), json!("application/json"));
        g.insert("responseJsonSchema".into(), if js["schema"].is_null() { js.clone() } else { js["schema"].clone() });
    }
    if p["thinking"].is_object() {
        let t = &p["thinking"];
        let include = t["type"] == "enabled" && t["budget_tokens"].as_f64().is_some_and(|b| b != 0.0);
        g.insert("thinking_config".into(), json!({ "include_thoughts": include, "thinking_budget": t["budget_tokens"] }));
    }
    if let Some(m) = p["modalities"].as_array() {
        g.insert("responseModalities".into(), Value::Array(m.iter().map(|x| json!(x.as_str().unwrap_or("").to_uppercase())).collect()));
    }
    if let Some(effort) = p["reasoning_effort"].as_str().filter(|e| *e != "none") {
        if p["model"].as_str().unwrap_or("").contains("gemini-2.5") {
            let budget = match effort {
                "minimal" | "low" => 1024,
                "high" => 24576,
                _ => 8192,
            };
            g.insert("thinking_config".into(), json!({ "include_thoughts": true, "thinking_budget": budget }));
        } else {
            g.insert("thinkingConfig".into(), json!({ "thinkingLevel": effort }));
        }
    }
    if p["image_config"].is_object() {
        let mut ic = Map::new();
        insert_opt(&mut ic, "aspectRatio", p["image_config"].get("aspect_ratio").filter(|v| present(v)).cloned());
        insert_opt(&mut ic, "imageSize", p["image_config"].get("image_size").filter(|v| present(v)).cloned());
        g.insert("imageConfig".into(), Value::Object(ic));
    }
    if present(&p["media_resolution"]) {
        g.insert("mediaResolution".into(), p["media_resolution"].clone());
    }
    Value::Object(g)
}

const VERTEX_SCHEMA_FIELDS: [&str; 22] = [
    "type", "format", "title", "description", "nullable", "default", "example", "items", "minItems",
    "maxItems", "enum", "properties", "propertyOrdering", "required", "minProperties", "maxProperties",
    "minimum", "maximum", "minLength", "maxLength", "pattern", "anyOf",
];

fn deref_schema(node: &Value, defs: &Map<String, Value>, depth: usize) -> Value {
    if depth > 32 {
        return node.clone();
    }
    match node {
        Value::Object(m) => {
            if let Some(r) = m.get("$ref").and_then(Value::as_str) {
                if let Some(name) = r.strip_prefix("#/$defs/") {
                    if let Some(def) = defs.get(name) {
                        return deref_schema(def, defs, depth + 1);
                    }
                }
            }
            Value::Object(m.iter().map(|(k, v)| (k.clone(), deref_schema(v, defs, depth + 1))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| deref_schema(v, defs, depth + 1)).collect()),
        v => v.clone(),
    }
}

/// transformGeminiToolParameters: deref $defs, collapse nullable anyOf.
fn gemini_tool_parameters(params: &Value) -> Value {
    let Value::Object(map) = params else { return params.clone() };
    let mut schema = params.clone();
    if let Some(defs) = map.get("$defs").and_then(Value::as_object) {
        schema = deref_schema(params, defs, 0);
        schema.as_object_mut().unwrap().remove("$defs");
    }
    fn is_null_type(n: &Value) -> bool {
        n["type"] == "null"
    }
    fn transform(node: &Value) -> Value {
        match node {
            Value::Array(a) => Value::Array(a.iter().map(transform).collect()),
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, v) in m {
                    if (k == "anyOf" || k == "oneOf") && v.is_array() {
                        let items = v.as_array().unwrap();
                        let non_null: Vec<&Value> = items.iter().filter(|i| !is_null_type(i)).collect();
                        let had_null = non_null.len() < items.len();
                        if non_null.len() == 1 && had_null {
                            if let Value::Object(single) = transform(non_null[0]) {
                                out.extend(single);
                                out.insert("nullable".into(), json!(true));
                            }
                            continue;
                        }
                        let kept = if had_null { Value::Array(non_null.into_iter().cloned().collect()) } else { v.clone() };
                        out.insert(k.clone(), transform(&kept));
                        if had_null {
                            out.insert("nullable".into(), json!(true));
                        }
                        continue;
                    }
                    out.insert(k.clone(), transform(v));
                }
                Value::Object(out)
            }
            v => v.clone(),
        }
    }
    transform(&schema)
}

fn filter_schema_fields(obj: &mut Value, is_schema: bool) {
    let Value::Object(m) = obj else { return };
    if is_schema {
        if let Some(Value::Array(types)) = m.get("type").cloned() {
            m.remove("type");
            if !m.contains_key("anyOf") {
                m.insert("anyOf".into(), Value::Array(types.iter().map(|t| json!({ "type": t })).collect()));
            }
        }
        m.retain(|k, _| VERTEX_SCHEMA_FIELDS.contains(&k.as_str()));
    }
    for (k, v) in m.iter_mut() {
        match (k.as_str(), v) {
            ("properties", Value::Object(props)) => props.values_mut().for_each(|p| filter_schema_fields(p, true)),
            ("items", v) => filter_schema_fields(v, true),
            (_, Value::Array(a)) => a.iter_mut().filter(|i| i.is_object()).for_each(|i| filter_schema_fields(i, true)),
            (_, v @ Value::Object(_)) => filter_schema_fields(v, true),
            _ => {}
        }
    }
}

const GOOGLE_TOOLS: [&str; 8] = ["googleSearch", "google_search", "googleSearchRetrieval", "google_search_retrieval", "computerUse", "computer_use", "googleMaps", "google_maps"];

/// fd0ed5f6e2: OpenAI tools -> Gemini tools.
fn gemini_tools(p: &Value, _: &Map<String, Value>) -> Value {
    let mut declarations = Vec::new();
    let mut tools = Vec::new();
    for tool in p["tools"].as_array().into_iter().flatten() {
        if tool["type"] != "function" {
            continue;
        }
        let f = &tool["function"];
        let name = f["name"].as_str().unwrap_or("");
        if GOOGLE_TOOLS.contains(&name) {
            let params = &f["parameters"];
            match name {
                "googleSearch" | "google_search" => {
                    let mut gs = Map::new();
                    insert_opt(&mut gs, "timeRangeFilter", params.get("timeRangeFilter").cloned());
                    tools.push(json!({ "googleSearch": gs }));
                }
                "googleSearchRetrieval" | "google_search_retrieval" => {
                    let mut r = Map::new();
                    insert_opt(&mut r, "dynamicRetrievalConfig", params.get("dynamicRetrievalConfig").cloned());
                    tools.push(json!({ "googleSearchRetrieval": r }));
                }
                "computerUse" | "computer_use" => tools.push(json!({ "computerUse": {
                    "environment": params["environment"], "excludedPredefinedFunctions": params["excluded_predefined_functions"] } })),
                _ => tools.push(json!({ "googleMaps": { "enableWidget": params["enableWidget"] } })),
            }
        } else if f.is_object() {
            let mut func = f.as_object().cloned().unwrap_or_default();
            let mut params = gemini_tool_parameters(f.get("parameters").unwrap_or(&json!({})));
            if let Value::Object(pm) = &mut params {
                pm.remove("strict");
                pm.remove("additionalProperties");
                pm.remove("$schema");
            }
            filter_schema_fields(&mut params, true);
            func.insert("parameters".into(), params);
            func.remove("strict");
            declarations.push(Value::Object(func));
        }
    }
    if !declarations.is_empty() {
        tools.push(json!({ "functionDeclarations": declarations }));
    }
    Value::Array(tools)
}

fn gemini_mode(choice: &Value) -> Value {
    match choice {
        Value::Object(_) if choice["type"] == "function" => json!("ANY"),
        Value::String(s) => match s.as_str() {
            "auto" => json!("AUTO"),
            "none" => json!("NONE"),
            "required" => json!("ANY"),
            _ => Value::Null,
        },
        _ => Value::Null,
    }
}

fn maps_retrieval(p: &Value) -> Option<Value> {
    p["tools"].as_array()?.iter().find(|t| matches!(t["function"]["name"].as_str(), Some("googleMaps" | "google_maps")))
        .map(|t| t["function"]["parameters"]["retrievalConfig"].clone())
}

fn gemini_function_calling(p: &Value) -> Value {
    let mut cfg = json!({ "mode": gemini_mode(&p["tool_choice"]) });
    if p["tool_choice"]["type"] == "function" {
        cfg["allowed_function_names"] = json!([p["tool_choice"]["function"]["name"]]);
    }
    cfg
}

/// 94d1bbf5cd (Gemini): toolConfig only when tool_choice is set.
fn google_tool_config(p: &Value, _: &Map<String, Value>) -> Value {
    if p["tool_choice"].is_null() || p["tool_choice"] == json!("") {
        return Value::Null;
    }
    let mut tc = json!({ "function_calling_config": gemini_function_calling(p) });
    if let Some(r) = maps_retrieval(p) {
        tc["retrievalConfig"] = r;
    }
    tc
}

/// 1f3a2b3e55 (Vertex): toolConfig, always an object.
fn vertex_tool_config(p: &Value, _: &Map<String, Value>) -> Value {
    let mut tc = Map::new();
    if !p["tool_choice"].is_null() && p["tool_choice"] != json!("") {
        tc.insert("function_calling_config".into(), gemini_function_calling(p));
    }
    insert_opt(&mut tc, "retrievalConfig", maps_retrieval(p));
    Value::Object(tc)
}

fn undefined(_: &Value, _: &Map<String, Value>) -> Value {
    Value::Null
}

fn vertex_anthropic_version(p: &Value, o: &Map<String, Value>) -> Value {
    opt(o, "anthropicVersion").cloned().or_else(|| p.get("anthropic_version").filter(|v| present(v)).cloned()).unwrap_or(json!("vertex-2023-10-16"))
}

fn strip_model_prefix(p: &Value, prefix: &str) -> Value {
    p["model"].as_str().map(|m| json!(m.replacen(prefix, "", 1))).unwrap_or(Value::Null)
}

fn vertex_meta_model(p: &Value, _: &Map<String, Value>) -> Value {
    json!(p["model"].as_str().filter(|m| !m.is_empty()).map(|m| m.replacen("meta.", "meta/", 1)).unwrap_or_else(|| "meta/llama-3.1-405b-instruct-maas".into()))
}

fn developer_to_system(p: &Value, _: &Map<String, Value>) -> Value {
    Value::Array(
        p["messages"].as_array().into_iter().flatten()
            .map(|m| if m["role"] == "developer" { let mut m = m.clone(); m["role"] = json!("system"); m } else { m.clone() })
            .collect(),
    )
}

fn required_to_any(p: &Value, _: &Map<String, Value>) -> Value {
    if p["tool_choice"] == "required" { json!("any") } else { p["tool_choice"].clone() }
}

// ------------------------------------------------------------ Bedrock Converse

const IMAGE_MIMES: [&str; 4] = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const VIDEO_MIMES: [&str; 8] = ["video/mp4", "video/mov", "video/quicktime", "video/mkv", "video/webm", "video/flv", "video/mpeg", "video/3gpp"];

fn bedrock_text_array(msg: &Value) -> Vec<Value> {
    match &msg["content"] {
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items.iter().filter(|i| i["type"] == "text") {
                out.push(json!({ "text": item["text"].as_str().unwrap_or("") }));
                if !item["cache_control"].is_null() {
                    out.push(json!({ "cachePoint": { "type": "default" } }));
                }
            }
            out
        }
        c => vec![json!({ "text": c.as_str().unwrap_or("") })],
    }
}

fn bedrock_media(mime: &str, source: Value, name: Option<&str>) -> Value {
    let format = mime.split('/').nth(1).unwrap_or("");
    if IMAGE_MIMES.contains(&mime) {
        json!({ "image": { "source": source, "format": format } })
    } else if VIDEO_MIMES.contains(&mime) {
        json!({ "video": { "format": format, "source": source } })
    } else {
        json!({ "document": { "format": format, "name": name.map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string()), "source": source } })
    }
}

fn bedrock_content(msg: &Value) -> Vec<Value> {
    if msg["content"].is_null() && msg["tool_calls"].is_null() && msg["tool_call_id"].is_null() {
        return Vec::new();
    }
    if msg["role"] == "tool" {
        let text = bedrock_text_array(msg);
        let has_text = text.first().and_then(|t| t["text"].as_str()).is_some_and(|t| !t.is_empty());
        return vec![json!({ "toolResult": { "content": if has_text { Value::Array(text) } else { json!([]) }, "toolUseId": msg["tool_call_id"] } })];
    }
    let mut out = Vec::new();
    let input = if msg["content_blocks"].is_null() { &msg["content"] } else { &msg["content_blocks"] };
    match input {
        Value::String(s) if !s.trim().is_empty() => out.push(json!({ "text": s })),
        Value::Array(items) => {
            for item in items {
                match item["type"].as_str() {
                    Some("text") => out.push(json!({ "text": item["text"].as_str().unwrap_or("") })),
                    Some("thinking") => out.push(json!({ "reasoningContent": { "reasoningText": { "signature": item["signature"], "text": item["thinking"] } } })),
                    Some("redacted_thinking") => out.push(json!({ "reasoningContent": { "redactedContent": item["data"] } })),
                    Some("image_url") => {
                        let url = item["image_url"]["url"].as_str().unwrap_or("");
                        let mut parts = url.split(';');
                        let mime = parts.next().and_then(|m| m.split(':').nth(1)).unwrap_or("");
                        let bytes = parts.next().and_then(|b| b.split(',').nth(1)).unwrap_or("");
                        out.push(bedrock_media(mime, json!({ "bytes": bytes }), None));
                    }
                    Some("file") => {
                        let f = &item["file"];
                        let mime = f["mime_type"].as_str().unwrap_or("application/pdf");
                        let mut source = Map::new();
                        insert_opt(&mut source, "bytes", f.get("file_data").filter(|v| present(v)).cloned());
                        if let Some(u) = f["file_url"].as_str() {
                            source.insert("s3Location".into(), json!({ "uri": u }));
                        }
                        out.push(bedrock_media(mime, Value::Object(source), f["file_name"].as_str()));
                    }
                    _ => {}
                }
                if !item["cache_control"].is_null() {
                    out.push(json!({ "cachePoint": { "type": "default" } }));
                }
            }
        }
        _ => {}
    }
    for call in msg["tool_calls"].as_array().into_iter().flatten() {
        out.push(json!({ "toolUse": { "name": call["function"]["name"], "input": parse_args(&call["function"]["arguments"]), "toolUseId": call["id"] } }));
    }
    out
}

/// 16dc233977: OpenAI messages -> Converse messages (user turns merged).
fn bedrock_messages(p: &Value, _: &Map<String, Value>) -> Value {
    let mut out: Vec<Value> = Vec::new();
    let mut prev = String::new();
    for msg in p["messages"].as_array().into_iter().flatten().filter(|m| !is_system(m)) {
        let role = if msg["role"] == "assistant" { "assistant" } else { "user" };
        let content = bedrock_content(msg);
        if role == "user" && prev == "user" {
            if let Some(Value::Array(last)) = out.last_mut().map(|m| &mut m["content"]) {
                last.extend(content);
            }
        } else {
            out.push(json!({ "role": role, "content": content }));
        }
        prev = role.into();
    }
    Value::Array(out)
}

/// 95fd922646: system messages -> Converse system blocks.
fn bedrock_system(p: &Value, _: &Map<String, Value>) -> Value {
    let Some(msgs) = p["messages"].as_array() else { return Value::Null };
    let out: Vec<Value> = msgs.iter().filter(|m| is_system(m)).flat_map(bedrock_text_array).collect();
    if out.is_empty() { Value::Null } else { Value::Array(out) }
}

/// e1ca28204b: tools + tool_choice -> Converse toolConfig.
fn bedrock_tool_config(p: &Value, _: &Map<String, Value>) -> Value {
    let amazon = p["model"].as_str().unwrap_or("").contains("amazon");
    let mut tools = Vec::new();
    for tool in p["tools"].as_array().into_iter().flatten() {
        if tool["function"].is_object() {
            let f = &tool["function"];
            tools.push(json!({ "toolSpec": { "name": f["name"], "description": f["description"], "inputSchema": { "json": f["parameters"] } } }));
        }
        if !tool["cache_control"].is_null() && !amazon {
            tools.push(json!({ "cachePoint": { "type": "default" } }));
        }
    }
    if tools.is_empty() {
        return Value::Null;
    }
    let choice = match &p["tool_choice"] {
        Value::Object(_) => json!({ "tool": { "name": p["tool_choice"]["function"]["name"] } }),
        Value::String(s) if s == "required" => json!({ "any": {} }),
        Value::String(s) if s == "auto" => json!({ "auto": {} }),
        _ => Value::Null,
    };
    let mut cfg = json!({ "tools": tools });
    if !choice.is_null() {
        cfg["toolChoice"] = choice;
    }
    cfg
}

/// ada0cbe4a9: OpenAI params -> Converse inferenceConfig.
fn bedrock_inference_config(p: &Value, _: &Map<String, Value>) -> Value {
    let mut c = Map::new();
    let max = if p["max_tokens"].as_f64().is_some_and(|v| v != 0.0) { &p["max_tokens"] } else { &p["max_completion_tokens"] };
    if max.as_f64().is_some_and(|v| v != 0.0) {
        c.insert("maxTokens".into(), max.clone());
    }
    if !p["stop"].is_null() && p["stop"] != json!("") {
        c.insert("stopSequences".into(), p["stop"].clone());
    }
    if present(&p["temperature"]) {
        c.insert("temperature".into(), p["temperature"].clone());
    }
    if present(&p["top_p"]) {
        c.insert("topP".into(), p["top_p"].clone());
    }
    Value::Object(c)
}

fn base_additional_fields(p: &Value) -> Map<String, Value> {
    p["additionalModelRequestFields"].as_object()
        .or(p["additional_model_request_fields"].as_object())
        .cloned()
        .unwrap_or_default()
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// 7d7bf63c1e: Anthropic-on-Bedrock additionalModelRequestFields.
fn bedrock_anthropic_fields(p: &Value, o: &Map<String, Value>) -> Value {
    let mut f = base_additional_fields(p);
    if present(&p["top_k"]) {
        f.insert("top_k".into(), p["top_k"].clone());
    }
    if truthy(&p["anthropic_version"]) {
        f.insert("anthropic_version".into(), p["anthropic_version"].clone());
    }
    if truthy(&p["user"]) {
        f.insert("metadata".into(), json!({ "user_id": p["user"] }));
    }
    if truthy(&p["thinking"]) {
        f.insert("thinking".into(), p["thinking"].clone());
    }
    let oc = anthropic_output_config(p, o);
    if !oc.is_null() {
        f.insert("output_config".into(), oc);
    }
    let beta = opt(o, "anthropicBeta").cloned().or_else(|| p.get("anthropic_beta").filter(|v| truthy(v)).cloned());
    if let Some(beta) = beta {
        f.insert("anthropic_beta".into(), match beta {
            Value::String(s) => Value::Array(s.split(',').map(|b| json!(b.trim())).collect()),
            v => v,
        });
    }
    let non_function: Vec<Value> = p["tools"].as_array().into_iter().flatten()
        .filter(|t| t["type"] != "function" && t["type"].is_string())
        .map(|t| {
            let kind = t["type"].as_str().unwrap();
            let mut m = t[kind].as_object().cloned().unwrap_or_default();
            let inner = m.get("name").cloned();
            m.insert("name".into(), json!(kind));
            m.insert("type".into(), inner.unwrap_or(Value::Null));
            Value::Object(m)
        })
        .collect();
    if !non_function.is_empty() {
        f.insert("tools".into(), Value::Array(non_function));
    }
    Value::Object(f)
}

/// 0b9b3498db: generic Converse additionalModelRequestFields.
fn bedrock_generic_fields(p: &Value, _: &Map<String, Value>) -> Value {
    let mut f = base_additional_fields(p);
    if present(&p["top_k"]) {
        f.insert("top_k".into(), p["top_k"].clone());
    }
    if truthy(&p["response_format"]) {
        f.insert("response_format".into(), p["response_format"].clone());
    }
    Value::Object(f)
}

/// 32508a6cec: Cohere-on-Bedrock additionalModelRequestFields.
fn bedrock_cohere_fields(p: &Value, _: &Map<String, Value>) -> Value {
    let mut f = base_additional_fields(p);
    for (from, to) in [("top_k", "top_k"), ("n", "n"), ("frequency_penalty", "frequency_penalty"), ("presence_penalty", "presence_penalty"), ("logit_bias", "logitBias")] {
        if truthy(&p[from]) {
            f.insert(to.into(), p[from].clone());
        }
    }
    Value::Object(f)
}

/// 05fb29e8aa: AI21-on-Bedrock additionalModelRequestFields.
fn bedrock_ai21_fields(p: &Value, _: &Map<String, Value>) -> Value {
    let mut f = base_additional_fields(p);
    if truthy(&p["top_k"]) {
        f.insert("top_k".into(), p["top_k"].clone());
    }
    if truthy(&p["frequency_penalty"]) {
        f.insert("frequencyPenalty".into(), json!({ "scale": p["frequency_penalty"] }));
    }
    if truthy(&p["presence_penalty"]) {
        f.insert("presencePenalty".into(), json!({ "scale": p["presence_penalty"] }));
    }
    for k in ["frequencyPenalty", "presencePenalty", "countPenalty"] {
        if truthy(&p[k]) {
            f.insert(k.into(), p[k].clone());
        }
    }
    Value::Object(f)
}

// ----------------------------------------------------------------- Cohere etc.

fn cohere_messages(p: &Value, _: &Map<String, Value>) -> Value {
    Value::Array(p["messages"].as_array().into_iter().flatten().map(|m| {
        let role = if m["role"] == "developer" { json!("system") } else { m["role"].clone() };
        json!({ "role": role, "content": m["content"] })
    }).collect())
}

fn stop_to_array(p: &Value, _: &Map<String, Value>) -> Value {
    match &p["stop"] {
        Value::String(s) => json!([s]),
        v => v.clone(),
    }
}

fn cohere_strict(p: &Value, _: &Map<String, Value>) -> Value {
    if p["response_format"]["type"] == "json_schema" { p["response_format"]["json_schema"]["strict"].clone() } else { Value::Null }
}

fn cohere_tool_choice(p: &Value, _: &Map<String, Value>) -> Value {
    match p["tool_choice"].as_str() {
        Some("required") => json!("REQUIRED"),
        Some("auto") => Value::Null,
        Some("none") => json!("NONE"),
        _ => json!("REQUIRED"),
    }
}

fn cohere_embed_texts(p: &Value, _: &Map<String, Value>) -> Value {
    match &p["input"] {
        Value::String(s) => json!([s]),
        Value::Array(items) if !items.is_empty() => {
            let texts: Vec<Value> = items.iter().filter_map(|i| i.as_str().map(|s| json!(s)).or_else(|| i.get("text").cloned())).collect();
            if texts.is_empty() { Value::Null } else { Value::Array(texts) }
        }
        _ => Value::Null,
    }
}

fn cohere_embed_images(p: &Value, _: &Map<String, Value>) -> Value {
    let images: Vec<Value> = p["input"].as_array().into_iter().flatten().filter_map(|i| i["image"].get("base64").cloned()).collect();
    if images.is_empty() { Value::Null } else { Value::Array(images) }
}

fn encoding_format_array(p: &Value, _: &Map<String, Value>) -> Value {
    match &p["encoding_format"] {
        Value::String(s) => json!([s]),
        Value::Array(a) => Value::Array(a.clone()),
        _ => Value::Null,
    }
}

fn rerank_documents(p: &Value, _: &Map<String, Value>) -> Value {
    Value::Array(p["documents"].as_array().into_iter().flatten().map(|d| if d.is_string() { d.clone() } else { d["text"].clone() }).collect())
}

fn input_to_array(p: &Value, _: &Map<String, Value>) -> Value {
    if p["input"].is_array() { p["input"].clone() } else { json!([p["input"]]) }
}

fn azure_model(p: &Value, o: &Map<String, Value>) -> Value {
    if opt(o, "apiVersion").and_then(Value::as_str).map(str::trim) == Some("v1") {
        return o.get("deploymentId").cloned().unwrap_or(Value::Null);
    }
    json!(p["model"].as_str().unwrap_or(""))
}


// ------------------------------------------------- Bedrock Messages (Converse)

fn cache_point(out: &mut Vec<Value>, block: &Value) {
    if truthy(&block["cache_control"]) {
        out.push(json!({ "cachePoint": { "type": "default" } }));
    }
}

fn media_format(media_type: &Value) -> Value {
    match media_type.as_str() {
        Some(m) => m.split('/').nth(1).map(|f| json!(f)).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

fn bedrock_msg_image(out: &mut Vec<Value>, b: &Value) {
    let src = &b["source"];
    match src["type"].as_str() {
        Some("base64") => {
            out.push(json!({ "image": { "format": media_format(&src["media_type"]), "source": { "bytes": src["data"] } } }));
            cache_point(out, b);
        }
        Some("url") => {
            out.push(json!({ "image": { "format": media_format(&src["media_type"]), "source": { "s3Location": { "uri": src["url"] } } } }));
            cache_point(out, b);
        }
        _ => {}
    }
}

fn bedrock_msg_document(out: &mut Vec<Value>, b: &Value) {
    let src = &b["source"];
    let name = b["title"].as_str().filter(|t| !t.is_empty()).map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut doc = match src["type"].as_str() {
        Some("base64") => json!({ "name": name, "format": media_format(&src["media_type"]), "source": { "bytes": src["data"] } }),
        Some("url") => {
            let f = media_format(&src["media_type"]);
            json!({ "name": name, "format": if f.is_null() { json!("pdf") } else { f }, "source": { "s3Location": { "uri": src["url"] } } })
        }
        Some("text") => json!({ "name": name, "format": "txt", "source": { "text": src["data"] } }),
        _ => Value::Null,
    };
    if !doc.is_null() {
        if !b["citations"].is_null() {
            doc["citations"] = b["citations"].clone();
        }
        out.push(json!({ "document": doc }));
    }
    cache_point(out, b);
}

/// TS BedrockConverseMessagesConfig.messages.
fn bedrock_msgs_messages(p: &Value, _: &Map<String, Value>) -> Value {
    let mut out = Vec::new();
    for m in p["messages"].as_array().into_iter().flatten() {
        if let Some(text) = m["content"].as_str() {
            out.push(json!({ "role": m["role"], "content": [{ "text": text }] }));
            continue;
        }
        let Some(blocks) = m["content"].as_array() else { continue };
        let mut content = Vec::new();
        let (mut has_text, mut has_doc) = (false, false);
        for b in blocks {
            match b["type"].as_str() {
                Some("text") => {
                    has_text = true;
                    content.push(json!({ "text": b["text"] }));
                    cache_point(&mut content, b);
                }
                Some("image") => bedrock_msg_image(&mut content, b),
                Some("document") => {
                    has_doc = true;
                    bedrock_msg_document(&mut content, b);
                }
                Some("thinking") => content.push(json!({ "reasoningContent": { "reasoningText": { "text": b["thinking"], "signature": b["signature"] } } })),
                Some("redacted_thinking") => content.push(json!({ "reasoningContent": { "redactedContent": b["data"] } })),
                Some("tool_use") => {
                    content.push(json!({ "toolUse": { "input": b["input"], "name": b["name"], "toolUseId": b["id"] } }));
                    cache_point(&mut content, b);
                }
                Some("tool_result") => {
                    let mut inner = Vec::new();
                    match &b["content"] {
                        Value::String(s) => inner.push(json!({ "text": s })),
                        Value::Array(items) => {
                            for item in items {
                                match item["type"].as_str() {
                                    Some("text") => inner.push(json!({ "text": item["text"] })),
                                    Some("image") => bedrock_msg_image(&mut inner, item),
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                    content.push(json!({ "toolResult": { "toolUseId": b["tool_use_id"],
                        "status": if truthy(&b["is_error"]) { "error" } else { "success" }, "content": inner } }));
                    cache_point(&mut content, b);
                }
                _ => {}
            }
        }
        if has_doc && !has_text {
            content.insert(0, json!({ "text": " " }));
        }
        out.push(json!({ "role": m["role"], "content": content }));
    }
    Value::Array(out)
}

/// TS messagesUtils.transformInferenceConfig (truthiness checks).
fn bedrock_msgs_inference(p: &Value, _: &Map<String, Value>) -> Value {
    let mut c = Map::new();
    for (from, to) in [("max_tokens", "maxTokens"), ("temperature", "temperature"), ("top_p", "topP"), ("stop_sequences", "stopSequences")] {
        if truthy(&p[from]) {
            c.insert(to.into(), p[from].clone());
        }
    }
    Value::Object(c)
}

fn bedrock_msgs_system(p: &Value, _: &Map<String, Value>) -> Value {
    match &p["system"] {
        Value::String(s) => json!([{ "text": s }]),
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.push(json!({ "text": item["text"] }));
                cache_point(&mut out, item);
            }
            Value::Array(out)
        }
        _ => Value::Null,
    }
}

/// TS messagesUtils.transformToolsConfig: `{tools, toolChoice}` or null.
fn bedrock_msgs_tools(p: &Value, _: &Map<String, Value>) -> Value {
    let tc = &p["tool_choice"];
    let tool_choice = if truthy(tc) {
        match tc["type"].as_str() {
            Some("auto") => json!({ "auto": {} }),
            Some("any") => json!({ "any": {} }),
            Some("tool") => json!({ "tool": { "name": tc["name"] } }),
            _ => Value::Null,
        }
    } else {
        Value::Null
    };
    let mut tools = Vec::new();
    for t in p["tools"].as_array().into_iter().flatten() {
        if t["type"] == "custom" || !truthy(&t["type"]) {
            let mut spec = json!({ "name": t["name"], "inputSchema": { "json": t["input_schema"] } });
            if !t["description"].is_null() {
                spec["description"] = t["description"].clone();
            }
            tools.push(json!({ "toolSpec": spec }));
            cache_point(&mut tools, t);
        }
    }
    if tools.is_empty() {
        return Value::Null;
    }
    let mut out = json!({ "tools": tools });
    if !tool_choice.is_null() {
        out["toolChoice"] = tool_choice;
    }
    out
}

/// Ported transforms by TS function fingerprint.
fn registry(fingerprint: &str) -> Option<Transform> {
    Some(match fingerprint {
        "aaa605f69d" => anthropic_messages,
        "98a5cd2629" => anthropic_system,
        "a0c27b6d65" => anthropic_tools,
        "535a2054fc" => anthropic_tool_choice,
        "31f44a2e24" => anthropic_output_config,
        "4906657281" => anthropic_adaptive_thinking,
        "94f9dffe68" => anthropic_complete_prompt,
        "a77f366666" => stop_null_to_empty,
        "201b796e3c" | "a0d9bd1628" => gemini_contents,
        "68ae0e005c" => gemini_system,
        "f42c3f4d69" => gemini_generation_config,
        "fd0ed5f6e2" => gemini_tools,
        "94d1bbf5cd" => google_tool_config,
        "1f3a2b3e55" => vertex_tool_config,
        "c9496d22fc" => undefined,
        "a8cc2ed96e" | "8ad3e10d29" => vertex_anthropic_version,
        "4a695f7cfb" => |p, _| strip_model_prefix(p, "anthropic."),
        "8ddc6ba7a3" => vertex_meta_model,
        "be680ba7c0" => developer_to_system,
        "8872ce56b0" => |p, _| strip_model_prefix(p, "endpoints."),
        "e258721eed" => |p, _| strip_model_prefix(p, "mistralai."),
        "b729d3807d" => required_to_any,
        "16dc233977" => bedrock_messages,
        "95fd922646" => bedrock_system,
        "e1ca28204b" => bedrock_tool_config,
        "ada0cbe4a9" => bedrock_inference_config,
        "7d7bf63c1e" => bedrock_anthropic_fields,
        "0b9b3498db" => bedrock_generic_fields,
        "32508a6cec" => bedrock_cohere_fields,
        "05fb29e8aa" => bedrock_ai21_fields,
        "e3fdb8a3af" => cohere_messages,
        "40625998c6" => stop_to_array,
        "7004549e62" => cohere_strict,
        "8965f3d914" => cohere_tool_choice,
        "72015916dd" => cohere_embed_texts,
        "13982be7c0" => cohere_embed_images,
        "ea666c51a8" => encoding_format_array,
        "ef0bc7a5d4" => rerank_documents,
        "4181b89539" => input_to_array,
        "ab885b9944" => azure_model,
        "220578fd37" => bedrock_msgs_messages,
        "c5858cc5a6" => bedrock_msgs_inference,
        "737642a5c3" => bedrock_msgs_system,
        "ba61994525" => bedrock_msgs_tools,
        _ => return None,
    })
}

pub fn apply(fingerprint: &str, params: &Value, options: &Map<String, Value>) -> Option<Value> {
    registry(fingerprint).map(|f| f(params, options))
}

pub fn is_ported(fingerprint: &str) -> bool {
    registry(fingerprint).is_some()
}
