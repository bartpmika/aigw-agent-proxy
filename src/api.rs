//! API mode: the gateway's own HTTP API on `PORT` (`/v1/chat/completions`,
//! `/v1/messages`, ...), configured per request with `x-portkey-*` headers
//! the way the TS gateway's `constructConfigFromRequestHeaders` does.

use crate::analytics::{self, Record};
use crate::body::{self, Body};
use crate::config::RouteConfig;
use crate::control_plane::GATEWAY_VERSION;
use crate::gateway::{client_headers, json_response, provider_error, Ctx, Gateway, Inherited};
use crate::guardrails::{self, CheckEnv, Stage};
use crate::policy::{check_access, GatewayError};
use crate::validate;
use crate::providers::{Endpoint, Usage};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

/// `x-portkey-*` headers that aren't provider options.
const NOT_OPTIONS: [&str; 22] = [
    "api-key", "config", "provider", "metadata", "trace-id", "virtual-key", "span-id", "span-name",
    "parent-span-id", "cache", "cache-force-refresh", "cache-namespace", "retry-count",
    "strict-open-ai-compliance", "default-input-guardrails", "default-output-guardrails", "debug",
    "prompt-id", "emit-event", "mode", "runtime", "runtime-version",
];

/// Snake_case option name for an `x-portkey-<name>` header.
fn option_name(header: &str) -> String {
    match header {
        "azure-resource-name" => "resource_name".into(),
        "azure-deployment-id" => "deployment_id".into(),
        "provider-file-name" => "filename".into(),
        other => other.replace('-', "_"),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok()).filter(|v| !v.is_empty())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    header(headers, "authorization").map(|a| a.replacen("Bearer ", "", 1))
}

/// Provider options carried in headers, snake_case like a config target.
fn header_options(headers: &HeaderMap) -> Map<String, Value> {
    let mut out = Map::new();
    for (name, value) in headers {
        let Some(rest) = name.as_str().strip_prefix("x-portkey-") else { continue };
        let Ok(value) = value.to_str() else { continue };
        if NOT_OPTIONS.contains(&rest) || value.is_empty() {
            continue;
        }
        let key = option_name(rest);
        let v = match rest {
            "vertex-service-account-json" => serde_json::from_str(value).unwrap_or(Value::Null),
            "forward-headers" => json!(value.split(',').map(str::trim).collect::<Vec<_>>()),
            "azure-api-version" => {
                out.insert("azure_api_version".into(), json!(value));
                json!(value)
            }
            _ => json!(value),
        };
        let key = if rest == "azure-api-version" { "api_version".into() } else { key };
        out.insert(key, v);
    }
    for (plain, key) in [("openai-beta", "openai_beta"), ("anthropic-beta", "anthropic_beta"), ("anthropic-version", "anthropic_version"), ("x-api-key", "anthropic_api_key")] {
        if let Some(v) = header(headers, plain) {
            out.entry(key).or_insert(json!(v));
        }
    }
    out
}

/// The request's config, as TS builds it from headers. Returns the config
/// and whether it's the default (no `x-portkey-config`), plus a model
/// rewrite for `@slug/model`.
fn config_from_headers(headers: &HeaderMap, body: &Value) -> Result<(RouteConfig, bool, Option<String>), GatewayError> {
    let mut model_rewrite = None;
    let model_vk = body["model"].as_str().and_then(|m| {
        let rest = m.strip_prefix('@').filter(|_| !m.starts_with("@cf/") && !m.starts_with("@hf/"))?;
        let (slug, model) = rest.split_once('/').unwrap_or((rest, ""));
        Some((slug.to_string(), model.to_string()))
    });
    let single = |mut target: Map<String, Value>| {
        target.extend(header_options(headers));
        if let Some(p) = header(headers, "x-portkey-provider") {
            target.insert("provider".into(), json!(p));
        }
        if let Some(k) = bearer(headers) {
            target.insert("api_key".into(), json!(k));
        }
        target
    };
    if let Some(raw) = header(headers, "x-portkey-config") {
        if !raw.trim_start().starts_with('{') {
            return Ok((RouteConfig::Slug(raw.to_string()), false, None));
        }
        let mut v: Value = serde_json::from_str(raw).map_err(|_| GatewayError::new(400, "Invalid config passed"))?;
        if v.get("provider").is_none() && v.get("targets").is_none() && v.get("virtual_key").is_none() {
            v = Value::Object(single(v.as_object().cloned().unwrap_or_default()));
        }
        return Ok((RouteConfig::Inline(v), false, None));
    }
    let mut target = single(Map::new());
    let header_vk = header(headers, "x-portkey-provider")
        .and_then(|p| p.strip_prefix('@'))
        .map(|p| p.split('/').next().unwrap_or(p).to_string())
        .or_else(|| header(headers, "x-portkey-virtual-key").map(str::to_string));
    let vk = header_vk.or_else(|| {
        model_vk.as_ref().map(|(slug, model)| {
            model_rewrite = Some(model.clone());
            slug.clone()
        })
    });
    if let Some(vk) = vk {
        target.remove("provider");
        target.insert("virtual_key".into(), json!(vk));
    }
    Ok((RouteConfig::Inline(Value::Object(target)), true, model_rewrite))
}

pub async fn serve(gateway: Arc<Gateway>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let gateway = gateway.clone();
                async move { Ok::<_, std::convert::Infallible>(route(gateway, req).await) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await {
                tracing::debug!("api connection ended: {e}");
            }
        });
    }
}

async fn route(gateway: Arc<Gateway>, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    match (req.method(), path.as_str()) {
        (&Method::GET, "/") => Response::new(body::full("AI Gateway says hey!")),
        (&Method::GET, "/v1/health") => json_response(
            200,
            &json!({ "status": "success", "message": "Server is healthy", "version": GATEWAY_VERSION, "implementation": "rust" }),
            &[],
        ),
        (&Method::POST, p) if p.starts_with("/v1/prompts/") && (p.ends_with("/completions") || p.ends_with("/render")) => {
            let slug = p.split('/').nth(3).unwrap_or("").to_string();
            let render = p.ends_with("/render");
            gateway.api_with_prompt(req, Endpoint::ChatCompletions, Some((slug, render))).await
        }
        (&Method::POST, p) => match Endpoint::from_path(p) {
            Some(endpoint) => gateway.api(req, endpoint).await,
            None => json_response(404, &json!({ "status": "failure", "message": format!("{p} is not supported by the Rust gateway yet") }), &[]),
        },
        _ => json_response(404, &json!({ "status": "failure", "message": "Not found" }), &[]),
    }
}

impl Gateway {
    /// Maps `virtual_key` / `provider: "@slug"` nodes from the control plane.
    fn resolve_virtual_keys<'a>(
        &'a self,
        node: &'a mut Value,
        key: &'a crate::control_plane::KeyDetails,
        api_key: &'a str,
        model: Option<&'a str>,
    ) -> futures_util::future::BoxFuture<'a, Result<(), GatewayError>> {
        Box::pin(async move {
            if let Some(slug) = crate::unified::virtual_key_slug(node) {
                let Some(vk) = self.control_plane.virtual_key(&slug, key, api_key).await else {
                    return Err(GatewayError::new(400, format!("Following keys are not valid: {slug}")));
                };
                if let Value::Object(m) = node {
                    crate::unified::apply_virtual_key(m, &vk, model)?;
                    m.remove("virtual_key");
                }
            }
            if let Some(targets) = node.get_mut("targets").and_then(Value::as_array_mut) {
                for t in targets {
                    self.resolve_virtual_keys(t, key, api_key, model).await?;
                }
            }
            Ok(())
        })
    }

    /// One API-mode request through the governed pipeline.
    pub async fn api(self: Arc<Self>, req: Request<Incoming>, endpoint: Endpoint) -> Response<Body> {
        self.api_with_prompt(req, endpoint, None).await
    }

    /// TS createRequestFromPromptData: the request body (and endpoint, virtual
    /// key) a prompt template renders to.
    async fn render_prompt(
        &self,
        slug: &str,
        body: &Value,
        key: &crate::control_plane::KeyDetails,
        api_key: &str,
    ) -> Result<(Value, Endpoint, Option<String>), (u16, String)> {
        let Some(prompt) = self.control_plane.prompt(slug, key, api_key).await else {
            return Err((404, "Invalid prompt id".into()));
        };
        let variables = body["variables"].as_object().cloned().unwrap_or_default();
        // Partials named in the template, plus variable partials from the request.
        let mut partial_slugs: Vec<String> = Vec::new();
        let mut missing_vars = Vec::new();
        if let Some(components) = prompt["variable_components"].as_str().and_then(|c| serde_json::from_str::<Value>(c).ok()) {
            for p in components["partials"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !partial_slugs.iter().any(|s| s == p) {
                    partial_slugs.push(p.to_string());
                }
            }
            for v in components["variablePartials"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                match variables.get(v) {
                    Some(name) => {
                        let name = name.as_str().map(str::to_string).unwrap_or_else(|| name.to_string());
                        if !partial_slugs.contains(&name) {
                            partial_slugs.push(name);
                        }
                    }
                    None => missing_vars.push(v.to_string()),
                }
            }
        }
        if !missing_vars.is_empty() {
            return Err((400, format!("Missing variable partials: {}", missing_vars.join(", "))));
        }
        let mut partials = Map::new();
        let mut missing = Vec::new();
        for p in &partial_slugs {
            match self.control_plane.prompt_partial(p, key, api_key).await {
                Some(rec) => {
                    partials.insert(p.clone(), rec);
                }
                None => missing.push(p.clone()),
            }
        }
        if !missing.is_empty() {
            return Err((400, format!("Missing prompt partials: {}", missing.join(", "))));
        }
        // Strings are JSON-escaped so they can sit inside the JSON template.
        let escape = |s: &str| {
            let j = serde_json::to_string(s).unwrap_or_default();
            j[1..j.len() - 1].to_string()
        };
        let vars: Map<String, Value> = variables
            .iter()
            .map(|(k, v)| (k.clone(), match v {
                Value::String(s) => json!(escape(s)),
                other => other.clone(),
            }))
            .collect();
        let vars = Value::Object(vars);
        let mut rendered_partials = Map::new();
        for (name, rec) in &partials {
            let rendered = crate::mustache::render(rec["string"].as_str().unwrap_or(""), &vars, &Map::new());
            rendered_partials.insert(name.clone(), json!(escape(&rendered)));
        }
        let prompt_string = crate::mustache::render(prompt["string"].as_str().unwrap_or(""), &vars, &rendered_partials);

        let mut out = prompt["parameters_object"].as_object().cloned().unwrap_or_default();
        out.remove("stream");
        for (k, v) in body.as_object().into_iter().flatten() {
            out.insert(k.clone(), v.clone());
        }
        out.remove("variables");
        if let Some(meta) = prompt["template_metadata"].as_str().and_then(|m| serde_json::from_str::<Value>(m).ok()) {
            if let Some(alias) = meta["azure_alias"].as_str().filter(|a| !a.is_empty()) {
                out.insert("model".into(), json!(alias));
            }
        }
        let endpoint = if prompt["ai_model_type"] == "chat" {
            let messages = serde_json::from_str::<Value>(&prompt_string)
                .map_err(|e| (400, format!("Error in parsing prompt template: {e}")))?;
            out.insert("messages".into(), messages);
            Endpoint::ChatCompletions
        } else {
            out.insert("prompt".into(), json!(prompt_string));
            Endpoint::Completions
        };
        let vk = prompt["provider_key_slug"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        Ok((Value::Object(out), endpoint, vk))
    }

    pub async fn api_with_prompt(self: Arc<Self>, req: Request<Incoming>, endpoint: Endpoint, prompt: Option<(String, bool)>) -> Response<Body> {
        let started = Instant::now();
        let (mut parts, incoming) = req.into_parts();
        let raw_body = match incoming.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return provider_error(&GatewayError::new(400, "bad request body"), ""),
        };
        let mut body: Value = serde_json::from_slice(&raw_body).unwrap_or(Value::Null);
        let mut endpoint = endpoint;
        if let Some((slug, render)) = &prompt {
            let api_key = header(&parts.headers, "x-portkey-api-key").map(str::to_string).or_else(|| bearer(&parts.headers));
            let key = match &api_key {
                Some(k) => self.control_plane.key_details(k).await,
                None => None,
            };
            let (Some(api_key), Some(key)) = (api_key, key) else {
                return provider_error(&GatewayError::portkey(401, "Invalid API Key", "03"), "");
            };
            if *render {
                if let Err(e) = crate::policy::check_access_for(&key, "prompts.render") {
                    return provider_error(&e, "");
                }
            }
            match self.render_prompt(slug, &body, &key, &api_key).await {
                Err((status, message)) => return json_response(status, &json!({ "status": "failure", "message": message }), &[]),
                Ok((rendered, ep, vk)) => {
                    if *render {
                        return json_response(200, &json!({ "success": true, "data": rendered }), &[]);
                    }
                    body = rendered;
                    endpoint = ep;
                    if let Some(vk) = vk.and_then(|v| hyper::header::HeaderValue::from_str(&v).ok()) {
                        parts.headers.insert("x-portkey-virtual-key", vk);
                    }
                }
            }
        }
        let raw_body = bytes::Bytes::from(body.to_string());
        let headers = &parts.headers;

        let Some(api_key) = header(headers, "x-portkey-api-key").map(str::to_string).or_else(|| bearer(headers)) else {
            return provider_error(&GatewayError::portkey(401, "Invalid API Key", "03"), "");
        };
        let Some(key) = self.control_plane.key_details(&api_key).await else {
            return provider_error(&GatewayError::portkey(401, "Invalid API Key", "03"), "");
        };
        if let Err(e) = check_access(&key) {
            return provider_error(&e, "");
        }
        let trace_id = header(headers, "x-portkey-trace-id").map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let fail = |message: &str| json_response(400, &json!({ "status": "failure", "message": message }), &[]);

        // TS requestValidator: header checks.
        if let Some(ct) = header(headers, "content-type").map(|c| c.split(';').next().unwrap_or("").trim().to_string()) {
            if ct != "application/json" && ct != "multipart/form-data" && !ct.starts_with("audio/") {
                return fail("Invalid content type passed");
            }
        }
        if let Some(p) = header(headers, "x-portkey-provider").filter(|p| !p.starts_with('@')) {
            if !validate::valid_provider(p) {
                return fail("Invalid provider passed");
            }
        }
        if header(headers, "x-portkey-custom-host").is_some_and(|h| !validate::valid_custom_host(h)) {
            return fail("Invalid custom host");
        }

        let (route, is_default, model_rewrite) = match config_from_headers(headers, &body) {
            Ok(c) => c,
            Err(e) => return provider_error(&e, ""),
        };
        if let Some(m) = model_rewrite {
            body["model"] = json!(m);
        }
        let explicit_config = !is_default;
        let (mut config, config_slug, config_version) = match self.resolve_config(route, is_default, &key, &api_key).await {
            Ok(c) => c,
            Err(e) => return provider_error(&e, ""),
        };
        // Virtual keys are mapped before validation, as in the TS middleware.
        if let Err(e) = self.resolve_virtual_keys(&mut config, &key, &api_key, body["model"].as_str()).await {
            return provider_error(&e, "");
        }
        let from_config = explicit_config || !config_slug.is_empty();
        if from_config {
            if header(headers, "x-portkey-provider").is_none() && config.get("provider").is_none() && config.get("targets").is_none() {
                return fail("Either x-portkey-provider needs to be passed. Or the x-portkey-config header should have a valid config with provider details in it.");
            }
            if let Some(errors) = validate::config_errors(&config) {
                return json_response(400, &errors, &[]);
            }
            if config.get("options").is_some() {
                return fail("This version of config is not supported in this route. Please migrate to the latest version");
            }
        } else if config.get("provider").is_none_or(|p| p.as_str().is_none_or(str::is_empty)) {
            return fail("Either x-portkey-config or x-portkey-provider header is required");
        }
        let (input_guardrails, output_guardrails) = match self.guardrails(&config, &key, &api_key).await {
            Ok(g) => g,
            Err(e) => return provider_error(&e, ""),
        };

        let mut metadata = Map::new();
        if let Some(Value::Object(md)) = header(headers, "x-portkey-metadata").and_then(|m| serde_json::from_str(m).ok()) {
            metadata = md;
        }
        metadata.extend(key.default_metadata());

        let check_env = CheckEnv {
            http: &self.http,
            control_plane: &self.control_plane,
            key: &key,
            api_key: &api_key,
            trace_id: &trace_id,
            airs_api_key: self.settings.airs_api_key.as_deref(),
        };
        let body = Arc::new(body);
        let mut record = Record {
            id: uuid::Uuid::new_v4().to_string(),
            trace_id: trace_id.clone(),
            provider: config["provider"].as_str().unwrap_or("").to_string(),
            model: body["model"].as_str().unwrap_or("").to_string(),
            request_url: parts.uri.path().to_string(),
            method: parts.method.to_string(),
            status: 0,
            is_streaming: body["stream"] == json!(true),
            usage: Usage::default(),
            response_time_ms: 0,
            ttlt_ms: 0,
            metadata: metadata.clone(),
            metadata_source: None,
            request_body: body.clone(),
            transformed_request_body: body.clone(),
            response_headers: Map::new(),
            response_body: Value::Null,
            portkey_headers: analytics::masked_portkey_headers(&api_key, &config.to_string(), "{}", &trace_id),
            hook_results: json!({ "before_request_hooks": [], "after_request_hooks": [] }),
            mode: config["strategy"]["mode"].as_str().unwrap_or("single").to_string(),
            last_used_option_index: -1,
            config_slug,
            api_key: api_key.clone(),
        };

        let input = if endpoint == Endpoint::CountTokens {
            guardrails::Outcome::default()
        } else {
            guardrails::run(&input_guardrails, Stage::Input, &guardrails::request_text(endpoint, &body), &check_env).await
        };
        record.hook_results["before_request_hooks"] = json!(input.results);
        if input.denied {
            return self.deny(record, &key, "", started).await;
        }

        let ctx = Ctx {
            endpoint,
            provider: String::new(),
            origin_url: String::new(),
            client_headers: client_headers(headers),
            raw_body,
            body,
            governance: Some((key.clone(), api_key.clone())),
            strict: header(headers, "x-portkey-strict-open-ai-compliance") != Some("false"),
            metadata: Value::Object(metadata),
            metadata_header: header(headers, "x-portkey-metadata").map(str::to_string),
            pathname: parts.uri.path().to_string(),
            headers_json: headers.iter().map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or("")))).collect(),
            config_version,
        };
        let upstream = match self.execute(&config, &Inherited::default(), &ctx, "config".into()).await {
            Ok(u) => u,
            Err(e) => {
                record.status = e.status;
                record.response_time_ms = started.elapsed().as_millis() as u64;
                self.finish(record, &key).await;
                return provider_error(&e, "");
            }
        };
        record.last_used_option_index = upstream.option_index;
        record.transformed_request_body = upstream.sent_body.clone();
        record.provider = upstream.provider.clone();
        record.request_url = upstream.url.clone();
        self.clone()
            .respond(upstream, record, key.clone(), endpoint, "", output_guardrails, &check_env, input.any_failed, started)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    #[test]
    fn builds_configs_from_headers() {
        let h = headers(&[
            ("x-portkey-provider", "azure-openai"),
            ("authorization", "Bearer az-key"),
            ("x-portkey-azure-resource-name", "res"),
            ("x-portkey-azure-deployment-id", "dep"),
            ("x-portkey-azure-api-version", "2024-10-21"),
        ]);
        let (RouteConfig::Inline(c), true, None) = config_from_headers(&h, &json!({})).unwrap() else { panic!() };
        assert_eq!(c, json!({"resource_name":"res","deployment_id":"dep","azure_api_version":"2024-10-21","api_version":"2024-10-21","provider":"azure-openai","api_key":"az-key"}));

        let (RouteConfig::Slug(s), false, _) = config_from_headers(&headers(&[("x-portkey-config", "pc-abc")]), &json!({})).unwrap() else { panic!() };
        assert_eq!(s, "pc-abc");

        let (RouteConfig::Inline(c), _, Some(m)) = config_from_headers(&headers(&[]), &json!({"model":"@openai-prod/gpt-4o"})).unwrap() else { panic!() };
        assert_eq!((c["virtual_key"].as_str(), m.as_str()), (Some("openai-prod"), "gpt-4o"));

        let (RouteConfig::Inline(c), false, _) = config_from_headers(
            &headers(&[("x-portkey-config", r#"{"retry":{"attempts":2}}"#), ("x-portkey-provider", "groq"), ("authorization", "Bearer g")]),
            &json!({}),
        ).unwrap() else { panic!() };
        assert_eq!((c["provider"].as_str(), c["api_key"].as_str(), c["retry"]["attempts"].as_u64()), (Some("groq"), Some("g"), Some(2)));
    }
}
