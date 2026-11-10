//! Provider requests and responses through the data-driven engine: the
//! Rust counterpart of the TS gateway's `tryPost` request building
//! (adapter, body transform, URL, headers, cloud auth) and its response
//! handlers (buffered and streaming transforms, Messages adapter).

use crate::engine::{self, responses::StreamTx};
use crate::policy::GatewayError;
use crate::adapter::{self, MessagesStream};
use crate::providers::Endpoint;
use bytes::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// Config keys whose values keep their own key style (TS `convertKeysToCamelCase`).
const PRESERVE: [&str; 14] = [
    "override_params", "params", "checks", "vertex_service_account_json", "vertexServiceAccountJson",
    "conditions", "input_guardrails", "output_guardrails", "default_input_guardrails",
    "default_output_guardrails", "virtualKeyDetails", "integrationDetails", "cb_config", "sticky",
];

const MESSAGES_FOR_ALL_MODELS: [&str; 2] = ["anthropic", "bedrock"];
const MESSAGES_FOR_CLAUDE: [&str; 2] = ["vertex-ai", "azure-ai"];
#[cfg(feature = "gateway")]
const BEDROCK_INVOKE_MODELS: [&str; 4] =
    ["cohere.command-light-text-v14", "cohere.command-text-v14", "ai21.j2-mid-v1", "ai21.j2-ultra-v1"];

pub fn to_camel(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        // `_x` -> `X` (a trailing `_` is kept, as in the TS regex).
        if c == '_' {
            if let Some(n) = chars.peek().copied().filter(|n| n.is_alphanumeric() || *n == '_') {
                chars.next();
                out.extend(n.to_uppercase());
                continue;
            }
        }
        out.push(c);
    }
    out
}

pub fn camel_keys(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(camel_keys).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    let x = if x.is_object() || x.is_array() {
                        if PRESERVE.contains(&k.as_str()) { x.clone() } else { camel_keys(x) }
                    } else {
                        x.clone()
                    };
                    (to_camel(k), x)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn to_snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The virtual-key slug a target refers to (`virtual_key`, or `provider: "@slug"`).
pub fn virtual_key_slug(target: &Value) -> Option<String> {
    if let Some(s) = target["virtual_key"].as_str().filter(|s| !s.is_empty()) {
        return Some(s.to_string());
    }
    target["provider"].as_str().and_then(|p| p.strip_prefix('@')).map(str::to_string)
}

/// Fills a (snake_case) target from a virtual key record, as the TS
/// `getApiKeyMappedConfig` does: provider, key, custom host and the
/// provider-specific `model_config` fields.
pub fn apply_virtual_key(target: &mut Map<String, Value>, vk: &Value, model: Option<&str>) -> Result<(), GatewayError> {
    let provider = vk["ai_provider_name"].as_str().unwrap_or("").to_string();
    target.insert("provider".into(), json!(provider));
    if provider != "vertex-ai" {
        target.insert("api_key".into(), vk["key"].clone());
    }
    let mc = vk["model_config"].as_object().cloned().unwrap_or_default();
    if let Some(h) = mc.get("customHost").filter(|h| !h.is_null()) {
        target.entry("custom_host").or_insert(h.clone());
    }
    let set = |t: &mut Map<String, Value>, k: &str, v: Option<&Value>| {
        if let Some(v) = v.filter(|v| !v.is_null()) {
            t.insert(k.into(), v.clone());
        }
    };
    match provider.as_str() {
        "azure-openai" => {
            let deployments = mc.get("deployments").and_then(Value::as_array);
            let alias = target.get("override_params").and_then(|o| o["model"].as_str()).or(model);
            let chosen = deployments.and_then(|d| {
                alias
                    .and_then(|a| d.iter().find(|c| c["alias"] == a))
                    .or_else(|| d.iter().find(|c| c["is_default"] == true))
            });
            if deployments.is_some() && chosen.is_none() {
                return Err(GatewayError::new(400, "No azure alias passed/default config found"));
            }
            set(target, "resource_name", mc.get("resourceName"));
            for k in ["azureAuthMode", "azureManagedClientId", "azureEntraClientId", "azureEntraClientSecret", "azureEntraTenantId"] {
                set(target, &to_snake(k), mc.get(k));
            }
            let src = chosen.and_then(Value::as_object).unwrap_or(&mc);
            set(target, "deployment_id", src.get("deploymentName"));
            set(target, "api_version", src.get("apiVersion"));
            set(target, "azure_model_name", src.get("aiModelName"));
        }
        "vertex-ai" => {
            set(target, "vertex_project_id", mc.get("vertexProjectId"));
            if target.get("vertex_region").is_none_or(Value::is_null) {
                set(target, "vertex_region", mc.get("vertexRegion"));
            }
            set(target, "vertex_service_account_json", mc.get("vertexServiceAccountJson"));
            set(target, "vertex_auth_type", mc.get("vertexAuthType"));
            set(target, "vertex_skip_ptu_cost_attribution", mc.get("vertexSkipPtuCostAttribution"));
        }
        // Everything else (bedrock, sagemaker, workers-ai, openai, oracle,
        // azure-ai...) uses model_config fields under their snake_case names.
        _ => {
            for (k, v) in &mc {
                if !matches!(k.as_str(), "customHost" | "customHeaders" | "deployments") {
                    set(target, &to_snake(k), Some(v));
                }
            }
        }
    }
    Ok(())
}

/// Engine function name for an endpoint.
pub fn fn_name(endpoint: Endpoint) -> &'static str {
    match endpoint {
        Endpoint::Messages => "messages",
        Endpoint::CountTokens => "messagesCountTokens",
        Endpoint::Complete | Endpoint::Completions => "complete",
        Endpoint::ChatCompletions => "chatComplete",
        Endpoint::Responses => "createModelResponse",
        Endpoint::Embeddings => "embed",
    }
}

pub fn supports_messages_natively(provider: &str, model: &str) -> bool {
    MESSAGES_FOR_ALL_MODELS.contains(&provider) || (MESSAGES_FOR_CLAUDE.contains(&provider) && model.contains("claude"))
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Adapter {
    None,
    /// Messages API served through the provider's chat completions.
    Messages,
}

/// How to turn the provider's response into what the client asked for.
#[derive(Clone)]
pub struct ResponseTx {
    pub provider: String,
    pub fn_name: String,
    pub family: Option<String>,
    pub strict: bool,
    pub adapter: Adapter,
    pub request: Arc<Value>,
    pub url: String,
}

/// A ready-to-send provider request.
pub struct Prepared {
    pub url: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// The provider-format body, for the log.
    pub sent: Arc<Value>,
    pub tx: ResponseTx,
}

#[cfg(feature = "gateway")]
mod full {
    use super::*;
    use crate::engine::{aws, gcp};

fn opt<'a>(options: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    options.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn not_supported(fn_name: &str, provider: &str) -> GatewayError {
    GatewayError::new(500, format!("{fn_name} is not supported by {provider}"))
}

/// Builds the provider request for `params` (overrides already applied).
#[allow(clippy::too_many_arguments)]
pub async fn prepare(
    http: &reqwest::Client,
    provider: &str,
    fn_name: &str,
    params: &Value,
    options: &Map<String, Value>,
    request_headers: &HeaderMap,
    strict: bool,
) -> Result<Prepared, GatewayError> {
    if provider.is_empty() {
        return Err(GatewayError::new(
            400,
            "Either x-portkey-provider needs to be passed. Or the x-portkey-config header should have a valid config with provider details in it.",
        ));
    }
    if !engine::exists(provider) {
        return Err(GatewayError::new(400, format!("Invalid provider passed: {provider}")));
    }
    let mut options = options.clone();
    if provider == "anthropic" && opt(&options, "apiKey").is_none() {
        if let Some(k) = opt(&options, "anthropicApiKey").map(str::to_string) {
            options.insert("apiKey".into(), json!(k));
        }
    }
    let model = params["model"].as_str().unwrap_or("").to_string();

    // Messages API on a provider without it: go through chat completions.
    let (fn_name, params, adapter, strict) = if fn_name == "messages" && !supports_messages_natively(provider, &model) {
        ("chatComplete", adapter::messages_to_chat(params), Adapter::Messages, false)
    } else {
        (fn_name, params.clone(), Adapter::None, strict)
    };
    let stream = params["stream"] == json!(true);
    let family = engine::family(provider, &model);

    if !engine::supports(provider, fn_name, &model) {
        return Err(not_supported(fn_name, provider));
    }
    let body = engine::transform_request(provider, fn_name, &params, &options).map_err(|e| GatewayError::new(500, e))?;

    let base = match opt(&options, "customHost") {
        Some(h) => h.trim_end_matches('/').to_string(),
        None => base_url(provider, fn_name, stream, &options, &params)?,
    };
    let endpoint = endpoint(provider, fn_name, stream, &options, &params)?;
    let url = format!("{base}{endpoint}");
    let bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_default());

    let mut headers: Vec<(String, String)> = vec![("content-type".into(), "application/json".into())];
    let put = |headers: &mut Vec<(String, String)>, k: &str, v: String| {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
        headers.push((k.to_lowercase(), v));
    };
    match provider {
        "azure-openai" => {
            if let Some(t) = opt(&options, "azureAdToken") {
                put(&mut headers, "authorization", format!("Bearer {}", t.replace("Bearer ", "")));
            } else if opt(&options, "azureAuthMode") == Some("entra") {
                let token = azure_entra_token(http, &options).await?;
                put(&mut headers, "authorization", format!("Bearer {token}"));
            } else {
                put(&mut headers, "api-key", opt(&options, "apiKey").unwrap_or("undefined").to_string());
            }
            if let Some(b) = opt(&options, "openaiBeta") {
                put(&mut headers, "openai-beta", b.to_string());
            }
        }
        "vertex-ai" => {
            let token = gcp::vertex_token(http, &options).await.map_err(|e| GatewayError::new(500, e))?;
            put(&mut headers, "authorization", format!("Bearer {token}"));
            let beta = opt(&options, "anthropicBeta").map(str::to_string).or_else(|| params["anthropic_beta"].as_str().map(str::to_string));
            if let Some(b) = beta {
                let b: Vec<&str> = b.split(',').map(str::trim).filter(|b| !b.is_empty() && *b != "prompt-caching-scope-2026-01-05").collect();
                put(&mut headers, "anthropic-beta", b.join(","));
            }
        }
        "bedrock" => {}
        _ => {
            for (k, v) in engine::render_headers(provider, fn_name, stream, &options, &params) {
                put(&mut headers, &k, v);
            }
        }
    }
    // Forwarded client headers.
    if let Some(list) = options.get("forwardHeaders").and_then(Value::as_array) {
        for h in list.iter().filter_map(Value::as_str) {
            let h = h.to_lowercase();
            if let Some(v) = request_headers.get(&h).and_then(|v| v.to_str().ok()) {
                put(&mut headers, &h, v.to_string());
            }
        }
    }
    if provider == "bedrock" {
        let service = opt(&options, "awsService").unwrap_or("bedrock").to_string();
        if opt(&options, "awsRegion").is_none() {
            options.insert("awsRegion".into(), json!(region_from_env()));
        }
        headers = aws::auth_headers(http, &options, "POST", &url, headers, &bytes, &service)
            .await
            .map_err(|e| GatewayError::new(500, e))?;
    }

    let mut map = HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
            map.insert(n, v);
        }
    }
    Ok(Prepared {
        url: url.clone(),
        headers: map,
        body: bytes,
        sent: Arc::new(body),
        tx: ResponseTx {
            provider: provider.to_string(),
            fn_name: fn_name.to_string(),
            family,
            strict,
            adapter,
            request: Arc::new(params),
            url,
        },
    })
}

fn region_from_env() -> String {
    std::env::var("AWS_REGION").or_else(|_| std::env::var("AWS_DEFAULT_REGION")).unwrap_or_else(|_| "us-east-1".into())
}

fn base_url(provider: &str, fn_name: &str, stream: bool, options: &Map<String, Value>, params: &Value) -> Result<String, GatewayError> {
    match provider {
        "vertex-ai" => Ok(match opt(options, "vertexRegion") {
            Some("global") => "https://aiplatform.googleapis.com".into(),
            region => format!("https://{}-aiplatform.googleapis.com", region.unwrap_or("undefined")),
        }),
        "bedrock" => {
            let host = if fn_name == "rerank" { "bedrock-agent-runtime" } else { "bedrock-runtime" };
            let region = opt(options, "awsRegion").map(str::to_string).unwrap_or_else(region_from_env);
            Ok(format!("https://{host}.{region}.amazonaws.com"))
        }
        "azure-openai" => Ok(format!("https://{}.openai.azure.com/openai", opt(options, "resourceName").unwrap_or("undefined"))),
        _ => {
            let t = engine::api_templates(provider, fn_name, stream).ok_or_else(|| not_supported(fn_name, provider))?;
            let template = t["baseURL"].as_str().unwrap_or("");
            engine::render(template, options, params)
                .ok_or_else(|| GatewayError::new(400, format!("{provider}: missing provider options for the base URL ({template})")))
        }
    }
}

fn endpoint(provider: &str, fn_name: &str, stream: bool, options: &Map<String, Value>, params: &Value) -> Result<String, GatewayError> {
    let model = params["model"].as_str().unwrap_or("");
    match provider {
        "vertex-ai" => {
            if model.is_empty() {
                return Err(GatewayError::new(400, "Model is required"));
            }
            let (publisher, model) = match model.split_once('.') {
                Some((p, m)) if ["google", "anthropic", "meta", "endpoints", "mistralai"].contains(&p) => (p, m),
                _ => ("google", model),
            };
            let project = options
                .get("vertexServiceAccountJson")
                .and_then(|sa| sa["project_id"].as_str())
                .or(opt(options, "vertexProjectId"))
                .unwrap_or("undefined");
            let version = if publisher == "meta" { "v1beta1" } else { "v1" };
            let region = opt(options, "vertexRegion").unwrap_or("undefined");
            let route = format!("/{version}/projects/{project}/locations/{region}");
            Ok(match (publisher, fn_name, stream) {
                ("google", "chatComplete", false) => format!("{route}/publishers/google/models/{model}:generateContent"),
                ("google", "chatComplete", true) => format!("{route}/publishers/google/models/{model}:streamGenerateContent?alt=sse"),
                ("google", "embed" | "imageGenerate", _) => format!("{route}/publishers/google/models/{model}:predict"),
                ("google", _, _) => route,
                ("anthropic" | "mistralai", "messagesCountTokens", _) => format!("{route}/publishers/{publisher}/models/count-tokens:rawPredict"),
                ("anthropic" | "mistralai", "chatComplete" | "messages", true) => format!("{route}/publishers/{publisher}/models/{model}:streamRawPredict"),
                ("anthropic" | "mistralai", _, _) => format!("{route}/publishers/{publisher}/models/{model}:rawPredict"),
                ("meta", _, _) => format!("{route}/endpoints/openapi/chat/completions"),
                ("endpoints", _, _) => format!("{route}/endpoints/{model}/chat/completions"),
                _ => route,
            })
        }
        "bedrock" => {
            let decoded = urlencoding::decode(model).map(|m| m.into_owned()).unwrap_or_else(|_| model.to_string());
            let encoded = urlencoding::encode(&decoded).into_owned();
            let without_region = engine::strip_bedrock_region(&decoded);
            let family = without_region.split('.').next().unwrap_or("");
            let converse = matches!(fn_name, "chatComplete" | "messages")
                && !(family == "anthropic" && fn_name == "messages")
                && !model.is_empty()
                && !BEDROCK_INVOKE_MODELS.contains(&model);
            Ok(match fn_name {
                "chatComplete" | "messages" | "complete" | "embed" | "imageGenerate" => {
                    let verb = match (converse, stream) {
                        (true, false) => "converse",
                        (true, true) => "converse-stream",
                        (false, false) => "invoke",
                        (false, true) => "invoke-with-response-stream",
                    };
                    let verb = if matches!(fn_name, "embed" | "imageGenerate") { "invoke" } else { verb };
                    format!("/model/{encoded}/{verb}")
                }
                "messagesCountTokens" => format!("/model/{}/count-tokens", urlencoding::encode(without_region)),
                "rerank" => "/rerank".into(),
                _ => return Err(not_supported(fn_name, provider)),
            })
        }
        "azure-openai" => {
            let version = opt(options, "apiVersion");
            let v1 = version.map(str::trim) == Some("v1");
            let prefix = if v1 { "/v1".to_string() } else { format!("/deployments/{}", opt(options, "deploymentId").unwrap_or("undefined")) };
            let query = match version {
                Some(v) if !v1 => format!("api-version={}", urlencoding::encode(v)),
                _ => String::new(),
            };
            let path = match fn_name {
                "complete" => "/completions",
                "chatComplete" => "/chat/completions",
                "embed" => "/embeddings",
                "imageGenerate" => "/images/generations",
                "imageEdit" => "/images/edits",
                "createSpeech" => "/audio/speech",
                "createTranscription" => "/audio/transcriptions",
                "createTranslation" => "/audio/translations",
                _ => return Err(not_supported(fn_name, provider)),
            };
            Ok(format!("{prefix}{path}?{query}"))
        }
        _ => {
            let t = engine::api_templates(provider, fn_name, stream).ok_or_else(|| not_supported(fn_name, provider))?;
            let Some(template) = t["endpoint"].as_str() else { return Err(not_supported(fn_name, provider)) };
            engine::render(template, options, params)
                .ok_or_else(|| GatewayError::new(400, format!("{provider}: missing provider options for the endpoint ({template})")))
        }
    }
}

/// Azure Entra ID client-credentials token (cached by the engine's HTTP layer per call).
async fn azure_entra_token(http: &reqwest::Client, options: &Map<String, Value>) -> Result<String, GatewayError> {
    let (Some(tenant), Some(id), Some(secret)) =
        (opt(options, "azureEntraTenantId"), opt(options, "azureEntraClientId"), opt(options, "azureEntraClientSecret"))
    else {
        return Err(GatewayError::new(400, "azure entra auth needs tenant id, client id and client secret"));
    };
    let scope = opt(options, "azureEntraScope").unwrap_or("https://cognitiveservices.azure.com/.default");
    let resp: Value = http
        .post(format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"))
        .form(&[("grant_type", "client_credentials"), ("client_id", id), ("client_secret", secret), ("scope", scope)])
        .send()
        .await
        .map_err(|e| GatewayError::new(500, e.to_string()))?
        .json()
        .await
        .map_err(|e| GatewayError::new(500, e.to_string()))?;
    resp["access_token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| GatewayError::new(500, format!("azure entra token failed: {resp}")))
}

}

#[cfg(feature = "gateway")]
pub use full::prepare;

/// The proxy build: Anthropic and OpenAI targets only, with translation in
/// both directions (Messages via the TS adapter, chat via the ported
/// Anthropic transforms). `--features gateway` has the full engine.
#[cfg(not(feature = "gateway"))]
mod slim {
    use super::*;
    use crate::engine::transforms;

    fn opt<'a>(options: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
        options.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
    }

    /// TS anthropic chatComplete param map (`transformUsingProviderConfig`).
    fn chat_to_anthropic(p: &Value, o: &Map<String, Value>) -> Value {
        let mut out = Map::new();
        let has = |k: &str| p.get(k).is_some();
        let mut put_fn = |out: &mut Map<String, Value>, target: &str, fp: &str| {
            if let Some(v) = transforms::apply(fp, p, o).filter(|v| !v.is_null()) {
                out.insert(target.into(), v);
            }
        };
        out.insert("model".into(), p.get("model").cloned().unwrap_or(json!("claude-sonnet-4-5")));
        if has("messages") {
            put_fn(&mut out, "messages", "aaa605f69d");
            put_fn(&mut out, "system", "98a5cd2629");
        }
        if has("tools") {
            put_fn(&mut out, "tools", "a0c27b6d65");
        }
        if has("tool_choice") {
            put_fn(&mut out, "tool_choice", "535a2054fc");
        }
        out.insert("max_tokens".into(), p.get("max_tokens").cloned().unwrap_or(json!(64000)));
        if let Some(v) = p.get("max_completion_tokens") {
            out.insert("max_tokens".into(), v.clone());
        }
        if let Some(v) = p.get("temperature") {
            out.insert("temperature".into(), v.as_f64().map(|t| json!(t.clamp(0.0, 1.0))).unwrap_or(v.clone()));
        }
        if let Some(v) = p.get("top_p") {
            out.insert("top_p".into(), v.as_f64().map(|t| json!(t.max(-1.0))).unwrap_or(v.clone()));
        }
        for (from, to) in [("top_k", "top_k"), ("stop", "stop_sequences"), ("stream", "stream"), ("thinking", "thinking")] {
            if let Some(v) = p.get(from) {
                out.insert(to.into(), v.clone());
            }
        }
        if let Some(u) = p.get("user") {
            out.insert("metadata".into(), json!({ "user_id": u }));
        }
        if has("response_format") || has("reasoning_effort") {
            put_fn(&mut out, "output_config", "31f44a2e24");
        }
        if has("reasoning_effort") {
            put_fn(&mut out, "thinking", "4906657281");
        }
        Value::Object(out)
    }

    pub async fn prepare(
        _http: &reqwest::Client,
        provider: &str,
        fn_name: &str,
        params: &Value,
        options: &Map<String, Value>,
        request_headers: &HeaderMap,
        strict: bool,
    ) -> Result<Prepared, GatewayError> {
        let unsupported = || {
            GatewayError::new(400, format!("{fn_name} on {provider} is not supported by the proxy build (rebuild with --features gateway)"))
        };
        let (base_default, path, body, fn_eff, adapter, strict) = match (provider, fn_name) {
            ("anthropic", "messages") => ("https://api.anthropic.com/v1", "/messages", params.clone(), fn_name, Adapter::None, strict),
            ("anthropic", "messagesCountTokens") => ("https://api.anthropic.com/v1", "/messages/count_tokens", params.clone(), fn_name, Adapter::None, strict),
            ("anthropic", "complete") => ("https://api.anthropic.com/v1", "/complete", params.clone(), fn_name, Adapter::None, strict),
            ("anthropic", "chatComplete") => ("https://api.anthropic.com/v1", "/messages", chat_to_anthropic(params, options), fn_name, Adapter::None, strict),
            ("openai", "messages") => ("https://api.openai.com/v1", "/chat/completions", adapter::messages_to_chat(params), "chatComplete", Adapter::Messages, false),
            ("openai", "chatComplete") => ("https://api.openai.com/v1", "/chat/completions", params.clone(), fn_name, Adapter::None, strict),
            ("openai", "complete") => ("https://api.openai.com/v1", "/completions", params.clone(), fn_name, Adapter::None, strict),
            ("openai", "embed") => ("https://api.openai.com/v1", "/embeddings", params.clone(), fn_name, Adapter::None, strict),
            ("openai", "createModelResponse") => ("https://api.openai.com/v1", "/responses", params.clone(), fn_name, Adapter::None, strict),
            ("", _) => {
                return Err(GatewayError::new(
                    400,
                    "Either x-portkey-provider needs to be passed. Or the x-portkey-config header should have a valid config with provider details in it.",
                ))
            }
            _ => return Err(unsupported()),
        };
        let base = opt(options, "customHost").map(|h| h.trim_end_matches('/').to_string()).unwrap_or_else(|| base_default.to_string());
        let url = format!("{base}{path}");
        let mut headers: Vec<(String, String)> = vec![("content-type".into(), "application/json".into())];
        if provider == "anthropic" {
            let key = opt(options, "apiKey").or(opt(options, "anthropicApiKey")).unwrap_or("");
            headers.push(("x-api-key".into(), key.into()));
            headers.push(("anthropic-beta".into(), opt(options, "anthropicBeta").unwrap_or("messages-2023-12-15").into()));
            headers.push(("anthropic-version".into(), opt(options, "anthropicVersion").unwrap_or("2023-06-01").into()));
        } else {
            headers.push(("authorization".into(), format!("Bearer {}", opt(options, "apiKey").unwrap_or("undefined"))));
            for (k, h) in [("openaiOrganization", "openai-organization"), ("openaiProject", "openai-project"), ("openaiBeta", "openai-beta")] {
                if let Some(v) = opt(options, k) {
                    headers.push((h.into(), v.into()));
                }
            }
        }
        if let Some(list) = options.get("forwardHeaders").and_then(Value::as_array) {
            for h in list.iter().filter_map(Value::as_str).map(str::to_lowercase) {
                if let Some(v) = request_headers.get(&h).and_then(|v| v.to_str().ok()) {
                    headers.retain(|(n, _)| *n != h);
                    headers.push((h.clone(), v.to_string()));
                }
            }
        }
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
                map.insert(n, v);
            }
        }
        let request = if adapter == Adapter::Messages { body.clone() } else { params.clone() };
        Ok(Prepared {
            url: url.clone(),
            headers: map,
            body: Bytes::from(serde_json::to_vec(&body).unwrap_or_default()),
            sent: Arc::new(body),
            tx: ResponseTx { provider: provider.into(), fn_name: fn_eff.into(), family: None, strict, adapter, request: Arc::new(request), url },
        })
    }
}

#[cfg(not(feature = "gateway"))]
pub use slim::prepare;

impl ResponseTx {
    /// Non-streaming: provider JSON -> client JSON.
    pub fn full_json(&self, status: u16, body: &Value) -> Value {
        let unified = engine::responses::transform(
            &self.provider,
            &self.fn_name,
            self.family.as_deref(),
            status,
            body,
            self.strict,
            &self.request,
        );
        match self.adapter {
            Adapter::None => unified,
            Adapter::Messages => adapter::chat_to_messages(&unified, status, &self.provider),
        }
    }

    pub fn full(&self, status: u16, bytes: &Bytes, is_sse: bool) -> Bytes {
        if is_sse {
            let mut s = self.stream();
            let mut out = s.push(bytes);
            out.push_str(&s.finish());
            return Bytes::from(out);
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(v) => Bytes::from(self.full_json(status, &v).to_string()),
            Err(_) if status >= 400 => Bytes::from(
                self.full_json(status, &json!({ "error": { "message": String::from_utf8_lossy(bytes) } })).to_string(),
            ),
            Err(_) => bytes.clone(),
        }
    }

    pub fn stream(&self) -> StreamChain {
        StreamChain {
            provider: StreamTx::needed(&self.provider, self.family.as_deref(), &self.fn_name).then(|| {
                StreamTx::new(&self.provider, self.family.as_deref(), &self.fn_name, &self.url, self.strict, (*self.request).clone())
            }),
            adapter: (self.adapter == Adapter::Messages).then(MessagesStream::new),
        }
    }

    /// Whether a stream needs any rewriting (else bytes pass through).
    pub fn rewrites_stream(&self) -> bool {
        self.adapter != Adapter::None || StreamTx::needed(&self.provider, self.family.as_deref(), &self.fn_name)
    }
}

/// Provider stream -> OpenAI SSE -> (optionally) Anthropic events.
pub struct StreamChain {
    provider: Option<StreamTx>,
    adapter: Option<MessagesStream>,
}

impl StreamChain {
    pub fn push(&mut self, bytes: &[u8]) -> String {
        let openai = match &mut self.provider {
            Some(p) => p.push(bytes),
            None => String::from_utf8_lossy(bytes).into_owned(),
        };
        match &mut self.adapter {
            Some(a) => a.push(openai.as_bytes()),
            None => openai,
        }
    }

    pub fn finish(&mut self) -> String {
        let tail = self.provider.as_mut().map(StreamTx::finish).unwrap_or_default();
        match &mut self.adapter {
            Some(a) => {
                let mut out = a.push(tail.as_bytes());
                out.push_str(&a.finish());
                out
            }
            None => tail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_virtual_keys() {
        let mut t = Map::new();
        t.insert("virtual_key".into(), json!("az-prod"));
        let vk = json!({"ai_provider_name":"azure-openai","key":"k","model_config":{"resourceName":"r",
            "deployments":[{"alias":"gpt-4o","deploymentName":"d1","apiVersion":"v1x","is_default":true}]}});
        apply_virtual_key(&mut t, &vk, Some("gpt-4o")).unwrap();
        assert_eq!(t["deployment_id"], "d1");
        assert_eq!(t["resource_name"], "r");
        let mut b = Map::new();
        apply_virtual_key(&mut b, &json!({"ai_provider_name":"bedrock","key":"x","model_config":{"awsRegion":"eu-west-1","awsAccessKeyId":"AK"}}), None).unwrap();
        assert_eq!(b["aws_region"], "eu-west-1");
        assert_eq!(virtual_key_slug(&json!({"provider":"@openai-prod"})).as_deref(), Some("openai-prod"));
    }

    #[test]
    fn camel_cases_like_ts() {
        assert_eq!(to_camel("aws_secret_access_key"), "awsSecretAccessKey");
        assert_eq!(to_camel("apiKey"), "apiKey");
        let v = camel_keys(&json!({"api_key":"k","override_params":{"max_tokens":1},"vertex_service_account_json":{"project_id":"p"}}));
        assert_eq!(v, json!({"apiKey":"k","overrideParams":{"max_tokens":1},"vertexServiceAccountJson":{"project_id":"p"}}));
    }

    fn opts(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[cfg(feature = "gateway")]
    #[tokio::test]
    async fn builds_provider_requests() {
        let http = reqwest::Client::new();
        let h = HeaderMap::new();
        let chat = json!({"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":5});

        let p = prepare(&http, "groq", "chatComplete", &chat, &opts(json!({"apiKey":"gk"})), &h, true).await.unwrap();
        assert_eq!(p.url, "https://api.groq.com/openai/v1/chat/completions");
        assert_eq!(p.headers["authorization"], "Bearer gk");

        let p = prepare(&http, "anthropic", "chatComplete", &chat, &opts(json!({"apiKey":"ak"})), &h, true).await.unwrap();
        assert_eq!(p.url, "https://api.anthropic.com/v1/messages");
        assert_eq!(p.headers["x-api-key"], "ak");
        assert_eq!(p.headers["anthropic-version"], "2023-06-01");

        let p = prepare(&http, "azure-openai", "chatComplete", &chat,
            &opts(json!({"apiKey":"az","resourceName":"r","deploymentId":"d","apiVersion":"2024-10-21"})), &h, true).await.unwrap();
        assert_eq!(p.url, "https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-10-21");
        assert_eq!(p.headers["api-key"], "az");

        let p = prepare(&http, "bedrock", "chatComplete", &json!({"model":"us.anthropic.claude-3-5-sonnet-20241022-v2:0","messages":[{"role":"user","content":"hi"}]}),
            &opts(json!({"awsAccessKeyId":"AK","awsSecretAccessKey":"SK","awsRegion":"us-west-2"})), &h, true).await.unwrap();
        assert_eq!(p.url, "https://bedrock-runtime.us-west-2.amazonaws.com/model/us.anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse");
        assert!(p.headers["authorization"].to_str().unwrap().starts_with("AWS4-HMAC-SHA256 Credential=AK/"));

        let p = prepare(&http, "vertex-ai", "messages", &json!({"model":"anthropic.claude-sonnet-4@20250514","messages":[],"max_tokens":5,"stream":true}),
            &opts(json!({"apiKey":"tok","vertexRegion":"us-east5","vertexProjectId":"proj"})), &h, true).await.unwrap();
        assert_eq!(p.url, "https://us-east5-aiplatform.googleapis.com/v1/projects/proj/locations/us-east5/publishers/anthropic/models/claude-sonnet-4@20250514:streamRawPredict");
        assert_eq!(p.headers["authorization"], "Bearer tok");

        // Messages on a provider without it goes through chat completions.
        let p = prepare(&http, "openai", "messages", &json!({"model":"gpt-4o","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}),
            &opts(json!({"apiKey":"ok"})), &h, true).await.unwrap();
        assert_eq!(p.url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(p.tx.adapter, Adapter::Messages);
    }
}
