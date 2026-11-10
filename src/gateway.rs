//! The governed request pipeline for intercepted LLM traffic, plus raw
//! pass-through for everything else on intercepted hosts.

use crate::analytics::{self, Record, Sink};
use crate::body::{self, Body, Capture};
use crate::config::{RequestFacts, RouteConfig, Settings, ORIGIN_KEY};
use crate::control_plane::{ControlPlane, KeyDetails};
use crate::guardrails::{self, CheckEnv, Guardrail, Stage};
use crate::identity::{self, LocalClient};
use crate::policy::{check_access, GatewayError};
use crate::providers::{self, Endpoint, Usage};
use crate::router;
use crate::unified::{self, ResponseTx};
use bytes::Bytes;
use futures_util::future::{BoxFuture, Shared};
use futures_util::{FutureExt, StreamExt};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response};
use rand::Rng;
use serde_json::{json, Map, Value};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bytes of a response body kept for the log (the tail is always kept).
const LOG_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const RETRY_STATUS_CODES: [u16; 5] = [429, 500, 502, 503, 504];
/// Total time retries may spend waiting on retry-after (TS MAX_RETRY_LIMIT_MS).
const MAX_RETRY_WAIT_MS: u64 = 60_000;

/// `retry-after-ms`, `x-ms-retry-after-ms` (ms) or `retry-after` (seconds).
fn retry_after_ms(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    for (name, seconds) in [("retry-after-ms", false), ("x-ms-retry-after-ms", false), ("retry-after", true)] {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let n: u64 = v.trim().split('.').next()?.parse().ok()?;
            return Some(if seconds { n * 1000 } else { n }).filter(|n| *n > 0);
        }
    }
    None
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

const HOP_BY_HOP: [&str; 13] = [
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding",
    "expect",
];

/// Metadata keys only the proxy may set.
const RESERVED_METADATA: [&str; 15] = [
    "_user", "_agent", "_os_user", "_pid", "_process", "_process_path", "_process_version",
    "_process_args", "_cwd", "_parent_chain", "_signature_status", "_signature_id",
    "_signature_team", "_hostname", "_domain",
];

pub type ClientLookup = Shared<BoxFuture<'static, Option<LocalClient>>>;

/// One CONNECT tunnel from a client.
pub struct Tunnel {
    pub host: String,
    pub port: u16,
    /// TLS inside the tunnel (else plain HTTP).
    pub tls: bool,
    pub portkey_api_key: Option<String>,
    pub client: ClientLookup,
}

pub struct Gateway {
    pub settings: Settings,
    pub control_plane: Arc<ControlPlane>,
    pub sink: Sink,
    pub http: reqwest::Client,
    pub usage: Arc<crate::usage::UsageTracker>,
}

pub fn client_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let n = name.as_str();
        if !HOP_BY_HOP.contains(&n) && !n.starts_with("x-portkey-") {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

pub(crate) fn response_headers(upstream: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let n = name.as_str();
        if !matches!(n, "content-encoding" | "content-length" | "transfer-encoding" | "connection" | "keep-alive") {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

fn headers_json(h: &HeaderMap) -> Map<String, Value> {
    h.iter()
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or(""))))
        .collect()
}

pub(crate) fn with_headers(status: u16, headers: HeaderMap, body: Body) -> Response<Body> {
    let mut resp = Response::new(body);
    *resp.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    *resp.headers_mut() = headers;
    resp
}

pub(crate) fn json_response(status: u16, body: &Value, extra: &[(&str, String)]) -> Response<Body> {
    let mut h = HeaderMap::new();
    h.insert("content-type", HeaderValue::from_static("application/json"));
    for (k, v) in extra {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            h.insert(n, v);
        }
    }
    with_headers(status, h, body::full(body.to_string()))
}

/// A gateway-originated error. With a client provider (forward proxy) it's
/// rewritten into that provider's shape; without one (API mode) it's the
/// Portkey shape with the gateway's own status.
pub(crate) fn provider_error(err: &GatewayError, provider: &str) -> Response<Body> {
    if provider.is_empty() {
        let body = match &err.code {
            Some(code) => json!({ "status": "failure", "message": err.message, "error": { "message": err.message, "code": code } }),
            None => json!({ "status": "failure", "message": err.message }),
        };
        return json_response(err.status, &body, &[]);
    }
    let (status, body) = err.to_provider(provider);
    json_response(status, &body, &[("x-portkey-original-status", err.status.to_string())])
}

/// Merges `override_params` into a JSON body.
fn apply_overrides(body: &Value, overrides: &Map<String, Value>) -> Value {
    let mut b = body.clone();
    if let Value::Object(m) = &mut b {
        for (k, v) in overrides {
            m.insert(k.clone(), v.clone());
        }
    }
    b
}

pub(crate) enum UpstreamBody {
    Live(reqwest::Response),
    /// A body produced by the gateway (cache hit, timeout, network error).
    Ready(Bytes),
}

pub(crate) struct Upstream {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: UpstreamBody,
    pub provider: String,
    /// Response transform for provider targets; `None` for origin targets
    /// and cache hits, whose bodies are returned untouched.
    pub tx: Option<ResponseTx>,
    pub sent_body: Arc<Value>,
    /// The target's JSON path, e.g. `config.targets[1]`.
    pub path: String,
    /// Index of the top-level target used (-1 for a single target).
    pub option_index: i64,
    /// The URL the request was sent to.
    pub url: String,
    /// Retries made; -1 when retries ran out on a retriable status (TS).
    pub retry_count: i64,
    pub cache_status: &'static str,
    /// Where to store a successful response (key, TTL).
    pub cache_store: Option<(String, Duration)>,
}

impl Upstream {
    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Settings a config node passes down to its targets (TS
/// `currentInheritedConfig`).
#[derive(Clone, Default)]
pub(crate) struct Inherited {
    pub id: Option<String>,
    pub overrides: Map<String, Value>,
    pub retry: Option<Value>,
    pub cache: Option<Value>,
    pub custom_host: Option<Value>,
    pub request_timeout: Option<Value>,
    pub forward_headers: Option<Value>,
    pub strict: Option<bool>,
}

fn top_level_index(path: &str) -> i64 {
    path.strip_prefix("config.targets[")
        .and_then(|r| r.split(']').next())
        .and_then(|i| i.parse().ok())
        .unwrap_or(-1)
}

fn json_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h
}

/// Everything the target executor needs about the original request.
pub(crate) struct Ctx {
    pub endpoint: Endpoint,
    /// The intercepted provider (forward proxy); empty in API mode, where
    /// there is no original destination.
    pub provider: String,
    pub origin_url: String,
    pub client_headers: HeaderMap,
    pub raw_body: Bytes,
    pub body: Arc<Value>,
    /// Key context for virtual-key / integration targets.
    pub governance: Option<(KeyDetails, String)>,
    /// `x-portkey-strict-open-ai-compliance: false`.
    pub strict: bool,
    /// Request metadata (conditional routing, sticky sessions, cache key).
    pub metadata: Value,
    pub metadata_header: Option<String>,
    /// The request path (`url.pathname` in conditional queries).
    pub pathname: String,
    /// Incoming headers (lowercase names), for sticky `headers.*` fields.
    pub headers_json: Map<String, Value>,
    /// Control-plane config version (sticky sessions need one).
    pub config_version: Option<String>,
}

impl Ctx {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers_json.get(name).and_then(Value::as_str)
    }
}

impl Gateway {
    pub async fn handle(self: Arc<Self>, req: Request<Incoming>, tunnel: Arc<Tunnel>) -> Response<Body> {
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let origin_url = format!("{}{path}{query}", self.settings.origin_base_url(&tunnel.host, tunnel.port, tunnel.tls));
        let provider = self.settings.provider_for(&tunnel.host).map(str::to_string);
        match provider {
            Some(p) if self.settings.is_gateway_path(&p, req.method().as_str(), &path) => {
                self.governed(req, &tunnel, &p, &path, origin_url).await
            }
            Some(_) => self.passthrough(req, &origin_url).await,
            // A non-LLM host decrypted for web inspection.
            None => self.web(req, &tunnel, &origin_url).await,
        }
    }

    /// Forwards a request to its original destination untouched.
    pub async fn passthrough(&self, req: Request<Incoming>, url: &str) -> Response<Body> {
        let (parts, incoming) = req.into_parts();
        let has_body = !matches!(parts.method.as_str(), "GET" | "HEAD");
        let mut builder = self
            .http
            .request(parts.method.clone(), url)
            .headers(client_headers(&parts.headers));
        if has_body {
            let stream = incoming.into_data_stream().map(|r| r.map_err(io::Error::other));
            builder = builder.body(reqwest::Body::wrap_stream(stream));
        }
        match builder.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = response_headers(resp.headers());
                let stream = resp.bytes_stream().map(|r| r.map_err(io::Error::other));
                with_headers(status, headers, body::from_stream(stream))
            }
            Err(e) => {
                tracing::warn!("passthrough to {url} failed: {e}");
                json_response(502, &json!({ "error": "Bad Gateway" }), &[])
            }
        }
    }

    async fn governed(
        self: Arc<Self>,
        req: Request<Incoming>,
        tunnel: &Tunnel,
        provider: &str,
        path: &str,
        origin_url: String,
    ) -> Response<Body> {
        let started = Instant::now();
        let endpoint = Endpoint::from_path(path).expect("gateway path");
        let (parts, incoming) = req.into_parts();
        let raw_body = match incoming.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return json_response(400, &json!({ "error": "bad request body" }), &[]),
        };
        let body: Value = serde_json::from_slice(&raw_body).unwrap_or(Value::Null);
        let header = |n: &str| parts.headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let trace_id = header("x-portkey-trace-id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let user_agent = header("user-agent");

        let Some(api_key) = tunnel.portkey_api_key.clone().or(self.settings.portkey_api_key.clone()) else {
            let err = GatewayError::new(401, "Portkey forward proxy: no Portkey API key. Set FORWARD_PROXY_PORTKEY_API_KEY or use http://user:<portkey-api-key>@host:port as the proxy URL.");
            return provider_error(&err, provider);
        };
        let Some(key) = self.control_plane.key_details(&api_key).await else {
            return provider_error(&GatewayError::portkey(401, "Invalid API Key", "03"), provider);
        };
        if let Err(e) = check_access(&key) {
            return provider_error(&e, provider);
        }

        // Who is calling, from the OS. The lookup only blocks the request when
        // a route matches on user/agent; otherwise it finishes before logging.
        let (user, agent) = if self.settings.routes_use_identity() {
            let client = tunnel.client.clone().await;
            (
                self.settings.resolve_user(client.as_ref().and_then(|c| c.os_user.as_deref())),
                Some(identity::detect_agent(client.as_ref().and_then(|c| c.executable.as_deref()), user_agent.as_deref())),
            )
        } else {
            (None, None)
        };
        let metadata_source = {
            let gateway = self.clone();
            let client_md = header("x-portkey-metadata");
            let (lookup, origin_host, user_agent, key) =
                (tunnel.client.clone(), tunnel.host.clone(), user_agent.clone(), key.clone());
            async move {
                let (client, host) = tokio::join!(lookup, identity::host_identity());
                gateway.metadata(client_md, &origin_host, client, host, user_agent, &key)
            }
            .boxed()
        };

        // Route and config.
        let facts = RequestFacts {
            host: tunnel.host.clone(),
            path: path.to_string(),
            provider: provider.to_string(),
            model: body["model"].as_str().map(str::to_string),
            user,
            agent,
        };
        let (route, is_default) = self.settings.resolve_route(&facts);
        let (config, config_slug, config_version) = match self.resolve_config(route, is_default, &key, &api_key).await {
            Ok(c) => c,
            Err(e) => return provider_error(&e, provider),
        };
        let (input_guardrails, output_guardrails) = match self.guardrails(&config, &key, &api_key).await {
            Ok(g) => g,
            Err(e) => return provider_error(&e, provider),
        };
        let check_env = CheckEnv {
            http: &self.http,
            control_plane: &self.control_plane,
            key: &key,
            api_key: &api_key,
            trace_id: &trace_id,
            airs_api_key: self.settings.airs_api_key.as_deref(),
        };
        let config_header = config.to_string();
        let body = Arc::new(body);
        let mut record = Record {
            id: uuid::Uuid::new_v4().to_string(),
            trace_id: trace_id.clone(),
            provider: provider.to_string(),
            model: body["model"].as_str().unwrap_or("").to_string(),
            request_url: origin_url.clone(),
            method: parts.method.to_string(),
            status: 0,
            is_streaming: body["stream"] == json!(true),
            usage: Usage::default(),
            response_time_ms: 0,
            ttlt_ms: 0,
            metadata: Map::new(),
            metadata_source: Some(metadata_source),
            request_body: body.clone(),
            transformed_request_body: body.clone(),
            response_headers: Map::new(),
            response_body: Value::Null,
            portkey_headers: analytics::masked_portkey_headers(&api_key, &config_header, "{}", &trace_id),
            hook_results: json!({ "before_request_hooks": [], "after_request_hooks": [] }),
            mode: config["strategy"]["mode"].as_str().unwrap_or("single").to_string(),
            last_used_option_index: -1,
            config_slug,
            api_key: api_key.clone(),
        };

        // Input guardrails.
        let input = if endpoint == Endpoint::CountTokens {
            guardrails::Outcome::default()
        } else {
            let text = guardrails::request_text(endpoint, &body);
            let out = guardrails::run(&input_guardrails, Stage::Input, &text, &check_env).await;
            tracing::debug!("input guardrails: {} guardrails, {} chars, denied={}", input_guardrails.len(), text.len(), out.denied);
            out
        };
        record.hook_results["before_request_hooks"] = json!(input.results);
        if input.denied {
            return self.deny(record, &key, provider, started).await;
        }

        // Targets.
        let ctx = Ctx {
            endpoint,
            provider: provider.to_string(),
            origin_url,
            client_headers: client_headers(&parts.headers),
            raw_body,
            body,
            governance: Some((key.clone(), api_key.clone())),
            strict: true,
            metadata: header("x-portkey-metadata").and_then(|m| serde_json::from_str(&m).ok()).unwrap_or(json!({})),
            metadata_header: header("x-portkey-metadata"),
            pathname: path.to_string(),
            headers_json: headers_json(&parts.headers),
            config_version,
        };
        let upstream = match self.execute(&config, &Inherited::default(), &ctx, "config".into()).await {
            Ok(u) => u,
            Err(e) => {
                record.status = e.status;
                record.response_time_ms = started.elapsed().as_millis() as u64;
                self.finish(record, &key).await;
                return provider_error(&e, provider);
            }
        };
        record.last_used_option_index = upstream.option_index;
        record.transformed_request_body = upstream.sent_body.clone();
        if let Some(m) = upstream.sent_body["model"].as_str() {
            record.model = m.to_string();
        }
        record.provider = upstream.provider.clone();
        self.clone()
            .respond(upstream, record, key.clone(), ctx.endpoint, provider, output_guardrails, &check_env, input.any_failed, started)
            .await
    }

    pub(crate) fn metadata(
        &self,
        client_md: Option<String>,
        origin_host: &str,
        client: Option<LocalClient>,
        host: identity::HostIdentity,
        user_agent: Option<String>,
        key: &KeyDetails,
    ) -> Map<String, Value> {
        let user = self.settings.resolve_user(client.as_ref().and_then(|c| c.os_user.as_deref()));
        let agent = identity::detect_agent(client.as_ref().and_then(|c| c.executable.as_deref()), user_agent.as_deref());
        let mut md = self.settings.metadata.clone();
        if let Some(Value::Object(client_md)) = client_md.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()) {
            for (k, v) in client_md {
                if !RESERVED_METADATA.contains(&k.as_str()) {
                    md.insert(k, v);
                }
            }
        }
        md.insert("_source".into(), json!("forward-proxy"));
        md.insert("_origin_host".into(), json!(origin_host));
        md.insert("_agent".into(), json!(agent));
        let mut put = |k: &str, v: Option<String>| {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                md.insert(k.into(), json!(v));
            }
        };
        put("_user", user);
        if let Some(c) = &client {
            put("_os_user", c.os_user.clone());
            put("_pid", Some(c.pid.to_string()));
            put("_process", c.executable.clone());
            put("_process_path", c.executable_path.clone());
            put("_process_version", c.version.clone());
            put("_process_args", c.args.clone());
            put("_cwd", c.cwd.clone());
            put("_parent_chain", c.parent_chain.clone());
            if let Some(s) = &c.signature {
                put("_signature_status", Some(s.status.to_string()));
                put("_signature_id", s.identifier.clone());
                put("_signature_team", s.team_id.clone());
            }
        }
        put("_hostname", Some(host.hostname.clone()));
        put("_domain", host.domain.clone());
        put("_user_agent", user_agent);
        // Key and workspace defaults win, as in the TS gateway.
        for (k, v) in key.default_metadata() {
            md.insert(k, v);
        }
        md
    }

    /// Picks the config: local route, or the key's/workspace's default.
    pub(crate) async fn resolve_config(
        &self,
        route: RouteConfig,
        is_default: bool,
        key: &KeyDetails,
        api_key: &str,
    ) -> Result<(Value, String, Option<String>), GatewayError> {
        let default_slug = key.default_config_slug();
        let route = match (&default_slug, is_default) {
            (Some(slug), true) => RouteConfig::Slug(slug.clone()),
            (Some(_), false) if !key.allow_config_override() => {
                return Err(GatewayError::new(400, "Cannot override default config set for this API key."));
            }
            _ => route,
        };
        match route {
            RouteConfig::Inline(v) => Ok((v, String::new(), None)),
            RouteConfig::Slug(slug) => match self.control_plane.config(&slug, key, api_key).await {
                Some((mut v, version)) => {
                    // Circuit breakers apply to stored configs, keyed by slug.
                    router::apply_breakers(&mut v, &router::breaker_config_id(&slug, key.workspace_id(), key.org_id()));
                    Ok((v, slug, version))
                }
                None => Err(GatewayError::new(400, "Invalid config id passed")),
            },
        }
    }

    /// Input and output guardrails from the config plus org/workspace defaults.
    pub(crate) async fn guardrails(
        &self,
        config: &Value,
        key: &KeyDetails,
        api_key: &str,
    ) -> Result<(Vec<Guardrail>, Vec<Guardrail>), GatewayError> {
        let slugs = |field: &str, defaults: &str| -> Vec<String> {
            let mut s: Vec<String> = config[field]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|g| g.as_str().map(str::to_string).or_else(|| g["id"].as_str().map(str::to_string)))
                        .collect()
                })
                .unwrap_or_default();
            s.extend(key.default_guardrails(defaults));
            s.dedup();
            s
        };
        let mut out = (Vec::new(), Vec::new());
        for (field, defaults, stage) in [
            ("input_guardrails", "input_guardrails", 0),
            ("output_guardrails", "output_guardrails", 1),
        ] {
            for slug in slugs(field, defaults) {
                let Some(record) = self.control_plane.guardrail(&slug, key, api_key).await else {
                    return Err(GatewayError::new(400, format!("Following default guardrails are not valid: {slug}")));
                };
                let g = Guardrail { slug, record };
                if stage == 0 { out.0.push(g) } else { out.1.push(g) }
            }
        }
        Ok(out)
    }

    /// Walks the config's targets (TS `tryTargetsRecursively`): fallback,
    /// loadbalance (with sticky sessions), conditional, single; skipping
    /// targets whose circuit breaker is open.
    pub(crate) fn execute<'a>(
        &'a self,
        node: &'a Value,
        inherited: &'a Inherited,
        ctx: &'a Ctx,
        path: String,
    ) -> BoxFuture<'a, Result<Upstream, GatewayError>> {
        Box::pin(async move {
            let pick = |k: &str, from: &Option<Value>| node.get(k).filter(|v| truthy(v)).cloned().or_else(|| from.clone());
            let mut cur = Inherited {
                id: inherited.id.clone().or_else(|| node["id"].as_str().map(str::to_string)),
                overrides: inherited.overrides.clone(),
                retry: pick("retry", &inherited.retry),
                cache: pick("cache", &inherited.cache),
                custom_host: pick("custom_host", &inherited.custom_host),
                request_timeout: pick("request_timeout", &inherited.request_timeout),
                forward_headers: pick("forward_headers", &inherited.forward_headers),
                strict: node["strict_open_ai_compliance"].as_bool().or(inherited.strict),
            };
            if let Some(o) = node["override_params"].as_object() {
                cur.overrides.extend(o.clone());
            }
            let mode = node["strategy"]["mode"].as_str();
            let all: Vec<(usize, &Value)> = node["targets"].as_array().map(|t| t.iter().enumerate().collect()).unwrap_or_default();
            let Some(mode) = mode.filter(|_| !all.is_empty()) else {
                let result = self.call_target(node, &cur, ctx, path.clone()).await;
                if let (Some(id), Ok(u)) = (&cur.id, &result) {
                    router::record_breaker(id, &path, &node["cb_config"], u.status);
                }
                return result;
            };
            // Circuit breaker: skip open targets unless all are open.
            let mut targets: Vec<(usize, &Value)> = if cur.id.is_some() {
                all.iter().copied().filter(|(_, t)| t["is_open"] != true).collect()
            } else {
                all.clone()
            };
            if targets.is_empty() {
                targets = all;
            }
            let child = |i: usize| format!("{path}.targets[{i}]");
            match mode {
                "fallback" => {
                    let codes: Option<Vec<u16>> = node["strategy"]["on_status_codes"]
                        .as_array()
                        .map(|c| c.iter().filter_map(|s| s.as_u64().map(|s| s as u16)).collect());
                    let mut last = Err(GatewayError::new(500, "No targets to try"));
                    for (i, t) in targets {
                        let result = self.execute(t, &cur, ctx, child(i)).await;
                        let stop = match &result {
                            Ok(u) => match &codes {
                                Some(c) => !c.contains(&u.status),
                                None => u.ok(),
                            },
                            // A gateway exception ends the fallback chain.
                            Err(e) => e.exception,
                        };
                        if stop {
                            return result;
                        }
                        last = result;
                    }
                    last
                }
                "loadbalance" => {
                    let weights: Vec<f64> = targets.iter().map(|(_, t)| t["weight"].as_f64().unwrap_or(1.0)).collect();
                    let total: f64 = weights.iter().sum();
                    let sticky = &node["strategy"]["sticky"];
                    let mut selected = None;
                    let mut sticky_hash = None;
                    if sticky["enabled"] == true {
                        if let Some(version) = &ctx.config_version {
                            let fields: Vec<String> = sticky["hash_fields"]
                                .as_array()
                                .map(|f| f.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                                .unwrap_or_default();
                            sticky_hash = router::sticky_hash(ctx.header("x-portkey-api-key"), &fields, &ctx.body, &ctx.metadata, &ctx.headers_json);
                            if let Some(h) = &sticky_hash {
                                selected = router::sticky_get(version, h).filter(|i| *i < targets.len());
                            }
                        }
                    }
                    let index = match selected {
                        Some(i) => i,
                        None => {
                            let mut r = rand::thread_rng().gen_range(0.0..total.max(f64::MIN_POSITIVE));
                            let mut chosen = 0;
                            for (i, w) in weights.iter().enumerate() {
                                if r < *w {
                                    chosen = i;
                                    break;
                                }
                                r -= w;
                            }
                            if sticky["enabled"] == true {
                                if let (Some(version), Some(h)) = (&ctx.config_version, &sticky_hash) {
                                    router::sticky_set(version, h, chosen, sticky["ttl"].as_u64().filter(|t| *t > 0).unwrap_or(300));
                                }
                            }
                            chosen
                        }
                    };
                    let (orig, t) = targets[index];
                    self.execute(t, &cur, ctx, child(orig)).await
                }
                "conditional" => {
                    let filtered = json!({ "strategy": node["strategy"], "targets": targets.iter().map(|(_, t)| (*t).clone()).collect::<Vec<_>>() });
                    let context = json!({ "metadata": ctx.metadata, "params": *ctx.body, "url": { "pathname": ctx.pathname } });
                    let index = router::resolve_conditional(&filtered, &context).map_err(|e| GatewayError::new(400, e))?;
                    let (orig, t) = targets[index];
                    self.execute(t, &cur, ctx, child(orig)).await
                }
                "single" => {
                    let (orig, t) = targets[0];
                    self.execute(t, &cur, ctx, child(orig)).await
                }
                other => Err(GatewayError::new(400, format!("Invalid strategy mode: {other}"))),
            }
        })
    }

    async fn call_target(&self, node: &Value, inherited: &Inherited, ctx: &Ctx, path: String) -> Result<Upstream, GatewayError> {
        // The leaf target with inherited settings applied.
        let mut target = node.clone();
        for (k, v) in [
            ("custom_host", &inherited.custom_host),
            ("request_timeout", &inherited.request_timeout),
            ("forward_headers", &inherited.forward_headers),
        ] {
            if let Some(v) = v {
                target[k] = v.clone();
            }
        }
        if let Some(strict) = inherited.strict {
            target["strict_open_ai_compliance"] = json!(strict);
        }
        let target = &target;
        let overrides = &inherited.overrides;
        let target_provider = target["provider"].as_str().unwrap_or("");
        let api_key = target["api_key"].as_str();
        let is_origin = !ctx.provider.is_empty()
            && ((api_key == Some(ORIGIN_KEY) && target_provider == ctx.provider)
                || (api_key.is_none()
                    && unified::virtual_key_slug(target).is_none()
                    && (target_provider.is_empty() || target_provider == ctx.provider)));

        let (url, headers, body, sent_body, tx, provider) = if is_origin {
            if overrides.is_empty() {
                // Exact original bytes: nothing to change.
                (ctx.origin_url.clone(), ctx.client_headers.clone(), ctx.raw_body.clone(), ctx.body.clone(), None, ctx.provider.clone())
            } else {
                let changed = Arc::new(apply_overrides(&ctx.body, overrides));
                (ctx.origin_url.clone(), ctx.client_headers.clone(), Bytes::from(changed.to_string()), changed, None, ctx.provider.clone())
            }
        } else {
            let mut t = target.as_object().cloned().unwrap_or_default();
            if let Some(slug) = unified::virtual_key_slug(target) {
                let Some((key, portkey_key)) = &ctx.governance else {
                    return Err(GatewayError::new(400, "Virtual key targets need a Portkey API key"));
                };
                let Some(vk) = self.control_plane.virtual_key(&slug, key, portkey_key).await else {
                    return Err(GatewayError::new(400, format!("Following keys are not valid: {slug}")));
                };
                let model = overrides.get("model").and_then(Value::as_str).or(ctx.body["model"].as_str());
                unified::apply_virtual_key(&mut t, &vk, model)?;
            }
            let options = match unified::camel_keys(&Value::Object(t)) {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            let provider = options.get("provider").and_then(Value::as_str).unwrap_or("").to_string();
            let strict = ctx.strict && options.get("strictOpenAiCompliance") != Some(&json!(false));
            let params = apply_overrides(&ctx.body, overrides);
            let p = unified::prepare(&self.http, &provider, unified::fn_name(ctx.endpoint), &params, &options, &ctx.client_headers, strict)
                .await?;
            (p.url, p.headers, p.body, p.sent, Some(p.tx), provider)
        };
        let option_index = top_level_index(&path);
        let base = |status: u16, headers: reqwest::header::HeaderMap, body: UpstreamBody| Upstream {
            status,
            headers,
            body,
            provider: provider.clone(),
            tx: tx.clone(),
            sent_body: sent_body.clone(),
            path: path.clone(),
            option_index,
            url: url.clone(),
            retry_count: 0,
            cache_status: "DISABLED",
            cache_store: None,
        };

        // Simple cache (semantic falls back to simple without a vector store).
        let adapter_active = tx.as_ref().is_some_and(|t| t.adapter != unified::Adapter::None);
        let streaming = sent_body["stream"] == json!(true) || ctx.body["stream"] == json!(true);
        let mut cache_status = "DISABLED";
        let mut cache_store = None;
        if let (Some((mode, max_age)), false, false) =
            (inherited.cache.as_ref().and_then(router::cache_options), adapter_active, streaming)
        {
            if matches!(mode.as_str(), "simple" | "semantic") {
                let org = ctx.governance.as_ref().map(|(k, _)| k.org_id().to_string()).unwrap_or_default();
                let key = router::cache_key(&org, &url, &sent_body, ctx.metadata_header.as_deref(), ctx.header("x-portkey-cache-namespace"));
                let ttl = router::cache_ttl(max_age);
                if ctx.header("x-portkey-cache-force-refresh").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
                    router::cache_delete(&key);
                    cache_status = "REFRESH";
                } else if let Some(hit) = router::cache_get(&key) {
                    let mut u = base(200, json_headers(), UpstreamBody::Ready(hit));
                    u.tx = None;
                    u.cache_status = "HIT";
                    return Ok(u);
                } else {
                    cache_status = "MISS";
                }
                cache_store = Some((key, ttl));
            }
        }

        // Retries (TS retryRequest): exponential backoff from 1 s; on 429
        // optionally wait for the provider's retry-after.
        let retry = inherited.retry.as_ref();
        let attempts = retry.and_then(|r| r["attempts"].as_u64()).unwrap_or(0) as u32;
        let retry_codes: Vec<u16> = if attempts > 0 {
            retry
                .and_then(|r| r["on_status_codes"].as_array())
                .map(|c| c.iter().filter_map(|s| s.as_u64().map(|s| s as u16)).collect())
                .unwrap_or_else(|| RETRY_STATUS_CODES.to_vec())
        } else {
            Vec::new()
        };
        let follow_retry_after = retry.is_some_and(|r| r["use_retry_after_header"] == true);
        let timeout = target["request_timeout"].as_u64().filter(|t| *t > 0);
        let mut remaining_wait = MAX_RETRY_WAIT_MS;
        let mut attempt: u32 = 0;
        loop {
            let mut req = self.http.post(&url).headers(headers.clone()).body(body.clone());
            if let Some(t) = timeout {
                req = req.timeout(Duration::from_millis(t));
            }
            let finish = |mut u: Upstream| {
                let exhausted = attempts > 0 && attempt == attempts && retry_codes.contains(&u.status);
                u.retry_count = if exhausted { -1 } else { attempt as i64 };
                u.cache_status = cache_status;
                u.cache_store = cache_store.clone();
                Ok(u)
            };
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let retryable = retry_codes.contains(&status) && attempt < attempts;
                    if !retryable {
                        let h = resp.headers().clone();
                        return finish(base(status, h, UpstreamBody::Live(resp)));
                    }
                    let mut wait = 1000u64 << attempt.min(16);
                    if status == 429 && follow_retry_after {
                        if let Some(ms) = retry_after_ms(resp.headers()) {
                            if ms > MAX_RETRY_WAIT_MS || ms > remaining_wait {
                                // Too long to wait: give up retrying.
                                let h = resp.headers().clone();
                                return finish(base(status, h, UpstreamBody::Live(resp))).map(|mut u| {
                                    u.retry_count = -1;
                                    u
                                });
                            }
                            remaining_wait -= ms;
                            wait = ms;
                        }
                    }
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }
                Err(e) if e.is_timeout() && timeout.is_some() => {
                    let body = json!({ "error": {
                        "message": format!("Request exceeded the timeout sent in the request: {}ms", timeout.unwrap_or(0)),
                        "type": "timeout_error", "param": null, "code": null } });
                    return finish(base(408, json_headers(), UpstreamBody::Ready(Bytes::from(body.to_string()))));
                }
                Err(e) if attempt < attempts => {
                    tracing::warn!("upstream {url} failed, retrying: {e}");
                    tokio::time::sleep(Duration::from_millis(1000u64 << attempt.min(16))).await;
                    attempt += 1;
                }
                Err(e) => {
                    let status = if e.is_connect() && e.to_string().contains("timed out") { 503 } else { 500 };
                    let text = format!("Message: {e} Cause: NA Name: Error");
                    return finish(base(status, reqwest::header::HeaderMap::new(), UpstreamBody::Ready(Bytes::from(text))));
                }
            }
        }
    }

    pub(crate) async fn deny(&self, mut record: Record, key: &KeyDetails, provider: &str, started: Instant) -> Response<Body> {
        let err = GatewayError::guardrail();
        record.status = 446;
        record.response_body = json!({
            "error": { "message": err.message, "type": "hooks_failed", "param": null, "code": null },
            "hook_results": record.hook_results,
        });
        record.response_time_ms = started.elapsed().as_millis() as u64;
        let body = record.response_body.clone();
        self.finish(record, key).await;
        if provider.is_empty() {
            return json_response(446, &body, &[]);
        }
        provider_error(&err, provider)
    }

    pub(crate) async fn finish(&self, record: Record, key: &KeyDetails) {
        if (200..300).contains(&record.status) {
            let cost = analytics::cost(&record.provider, &record.model, &record.usage);
            self.usage.record(key, &record.api_key, cost, record.usage.total());
        }
        self.sink.record(record, key).await;
        self.control_plane.resync(key.org_id());
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn respond(
        self: Arc<Self>,
        upstream: Upstream,
        mut record: Record,
        key: KeyDetails,
        endpoint: Endpoint,
        client_provider: &str,
        output_guardrails: Vec<Guardrail>,
        check_env: &CheckEnv<'_>,
        input_failed: bool,
        started: Instant,
    ) -> Response<Body> {
        let Upstream { status, headers: upstream_headers, body: upstream_body, tx, provider, path, retry_count, cache_status, cache_store, .. } = upstream;
        let first_byte = started.elapsed().as_millis() as u64;
        let mut headers = response_headers(&upstream_headers);
        // Provider targets stream in their own framing (e.g. AWS event
        // stream); the client always gets SSE for a successful stream.
        let is_sse = match &tx {
            Some(t) => t.request["stream"] == json!(true) && (200..300).contains(&status),
            None => headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|c| c.contains("text/event-stream")),
        };
        let extra = [
            ("x-portkey-trace-id", record.trace_id.clone()),
            ("x-portkey-provider", provider.clone()),
            ("x-portkey-last-used-option-index", path),
            ("x-portkey-cache-status", cache_status.to_string()),
            ("x-portkey-retry-attempt-count", retry_count.to_string()),
        ];
        for (k, v) in &extra {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                headers.insert(n, v);
            }
        }
        if tx.is_some() {
            headers.remove("content-length");
            let ct = if is_sse { "text/event-stream" } else { "application/json" };
            headers.insert("content-type", HeaderValue::from_static(ct));
        }
        record.status = status;
        record.response_time_ms = first_byte;
        record.response_headers = headers_json(&headers);
        let scan_output = !output_guardrails.is_empty() && (200..300).contains(&status);

        // Non-streaming, or streaming that must be scanned: read it all.
        if !is_sse || scan_output {
            let bytes = match upstream_body {
                UpstreamBody::Ready(b) => b,
                UpstreamBody::Live(r) => match r.bytes().await {
                    Ok(b) => b,
                    Err(e) => return provider_error(&GatewayError::new(502, format!("upstream body failed: {e}")), client_provider),
                },
            };
            let bytes = match &tx {
                Some(t) => t.full(status, &bytes, is_sse),
                None => bytes,
            };
            let text = String::from_utf8_lossy(&bytes);
            let complete = if is_sse {
                providers::assemble_stream(endpoint, &text).unwrap_or(Value::Null)
            } else {
                serde_json::from_slice(&bytes).unwrap_or(Value::Null)
            };
            record.usage = if is_sse { Usage::from_sse(&text) } else { Usage::from_json(&complete) };
            record.response_body = complete.clone();
            record.ttlt_ms = started.elapsed().as_millis() as u64;
            let mut output_failed = false;
            if scan_output {
                let out = guardrails::run(&output_guardrails, Stage::Output, &guardrails::response_text(endpoint, &complete), check_env).await;
                record.hook_results["after_request_hooks"] = json!(out.results);
                if out.denied {
                    // Never release the denied content.
                    return self.deny(record, &key, client_provider, started).await;
                }
                output_failed = out.any_failed;
            }
            let mut status = status;
            if (input_failed || output_failed) && status == 200 {
                // API mode reports the gateway status; agents need a 200.
                if client_provider.is_empty() {
                    status = 246;
                } else {
                    headers.insert("x-portkey-original-status", HeaderValue::from_static("246"));
                }
            }
            if let Some((cache_key, ttl)) = cache_store.filter(|_| status == 200 && !is_sse) {
                router::cache_put(&cache_key, bytes.clone(), ttl);
            }
            self.finish(record, &key).await;
            return with_headers(status, headers, body::full(bytes));
        }

        // Live stream: pass chunks through, capture a copy for the log.
        let mut status = status;
        if input_failed && status == 200 {
            if client_provider.is_empty() {
                status = 246;
            } else {
                headers.insert("x-portkey-original-status", HeaderValue::from_static("246"));
            }
        }
        let gateway = self.clone();
        let capture = Arc::new(Mutex::new(Capture::new(LOG_CAPTURE_BYTES, move |bytes, _truncated| {
            record.ttlt_ms = started.elapsed().as_millis() as u64;
            // Parsing runs off the connection, so the next request isn't delayed.
            tokio::spawn(async move {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                record.usage = Usage::from_sse(&text);
                record.response_body = providers::assemble_stream(endpoint, &text).unwrap_or(Value::Null);
                gateway.finish(record, &key).await;
            });
        })));
        let translator = tx.filter(ResponseTx::rewrites_stream).map(|t| Arc::new(Mutex::new(t.stream())));
        let tail_translator = translator.clone();
        let tail_capture = capture.clone();
        let source = match upstream_body {
            UpstreamBody::Live(r) => r.bytes_stream().boxed(),
            UpstreamBody::Ready(b) => futures_util::stream::once(async move { Ok::<Bytes, reqwest::Error>(b) }).boxed(),
        };
        let stream = source
            .map(move |chunk| {
                let chunk = chunk.map_err(io::Error::other)?;
                let out = match &translator {
                    Some(t) => Bytes::from(t.lock().unwrap().push(&chunk)),
                    None => chunk,
                };
                capture.lock().unwrap().push(&out);
                Ok(out)
            })
            .chain(futures_util::stream::once(async move {
                let tail = Bytes::from(tail_translator.map(|t| t.lock().unwrap().finish()).unwrap_or_default());
                tail_capture.lock().unwrap().push(&tail);
                Ok::<Bytes, io::Error>(tail)
            }))
            .filter(|c| futures_util::future::ready(!matches!(c, Ok(b) if b.is_empty())));
        with_headers(status, headers, body::from_stream(stream))
    }
}
