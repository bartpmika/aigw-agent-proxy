//! Settings: environment variables plus `forward-proxy.json`, with the same
//! names and schema as the TypeScript gateway.

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

/// Sentinel `api_key` marking a config target as the client's original
/// destination. Never sent upstream.
pub const ORIGIN_KEY: &str = "forward-proxy-origin";

pub const ANTHROPIC: &str = "anthropic";
pub const OPENAI: &str = "openai";

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileConfig {
    port: Option<u16>,
    listen_host: Option<String>,
    portkey_api_key: Option<String>,
    ca_dir: Option<String>,
    #[serde(default)]
    intercept: HashMap<String, Option<String>>,
    #[serde(default)]
    upstream_overrides: HashMap<String, String>,
    #[serde(default)]
    metadata: Map<String, Value>,
    #[serde(default)]
    identity: IdentityConfig,
    #[serde(default)]
    routes: Vec<Route>,
    #[serde(default)]
    web_inspection: WebInspectionFile,
}

/// Inspection of the agent's other web traffic (curl, git, pip, WebFetch...).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebInspectionFile {
    enabled: Option<bool>,
    guardrails: Option<Vec<String>>,
    response_guardrails: Option<Vec<String>>,
    bypass_hosts: Option<Vec<String>>,
    scan_responses: Option<bool>,
    max_scan_bytes: Option<usize>,
}

/// Hosts tunneled without decryption by default: the agent's own control
/// traffic (auth, telemetry), which never carries user content worth scanning.
pub const DEFAULT_WEB_BYPASS: [&str; 6] =
    ["*.anthropic.com", "claude.ai", "*.claude.ai", "*.statsig.com", "*.sentry.io", "*.datadoghq.com"];

#[derive(Debug, Clone)]
pub struct WebInspection {
    pub enabled: bool,
    /// Guardrail slugs; `None` uses the workspace/org default input guardrails.
    pub guardrails: Option<Vec<String>>,
    /// Response guardrail slugs; `None` uses the default output guardrails.
    pub response_guardrails: Option<Vec<String>>,
    pub bypass_hosts: Vec<String>,
    pub scan_responses: bool,
    pub max_scan_bytes: usize,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityConfig {
    #[serde(default)]
    pub users: HashMap<String, String>,
    pub user_domain: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouteMatch {
    pub host: Option<String>,
    pub path: Option<String>,
    pub model: Option<String>,
    pub user: Option<String>,
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    #[serde(rename = "match", default)]
    pub matcher: RouteMatch,
    /// A control-plane config id/slug, or an inline config.
    pub config: Value,
}

/// What routing can match on for one intercepted request.
#[derive(Debug, Clone, Default)]
pub struct RequestFacts {
    pub host: String,
    pub path: String,
    pub provider: String,
    pub model: Option<String>,
    pub user: Option<String>,
    pub agent: Option<String>,
}

/// The config chosen for a request.
#[derive(Debug, Clone)]
pub enum RouteConfig {
    /// Inline config (origin targets already expanded).
    Inline(Value),
    /// Config stored in the control plane.
    Slug(String),
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub port: u16,
    pub listen_host: String,
    pub portkey_api_key: Option<String>,
    pub ca_dir: PathBuf,
    pub metadata: Map<String, Value>,
    pub identity: IdentityConfig,
    pub routes: Vec<Route>,
    intercept: HashMap<String, String>,
    upstream_overrides: HashMap<String, String>,
    // Control plane connection.
    pub albus_basepath: Option<String>,
    pub control_plane_basepath: Option<String>,
    pub client_auth: Option<String>,
    pub organisations_to_sync: Vec<String>,
    pub sync_interval_ms: u64,
    pub health_port: Option<u16>,
    pub airs_api_key: Option<String>,
    pub web: WebInspection,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Settings {
    pub fn load() -> anyhow::Result<Self> {
        let explicit = env("FORWARD_PROXY_CONFIG");
        let path = explicit.clone().unwrap_or_else(|| "forward-proxy.json".into());
        let file: FileConfig = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("invalid {path}: {e}"))?,
            Err(_) if explicit.is_none() => FileConfig::default(),
            Err(e) => anyhow::bail!("Forward proxy config not found: {path} ({e})"),
        };
        Ok(Self::from_parts(file))
    }

    fn from_parts(file: FileConfig) -> Self {
        let mut intercept: HashMap<String, String> = [
            ("api.anthropic.com".to_string(), ANTHROPIC.to_string()),
            ("api.openai.com".to_string(), OPENAI.to_string()),
            // Codex signed in with ChatGPT calls the ChatGPT backend (same
            // Responses format, ChatGPT token, subscription billing).
            ("chatgpt.com".to_string(), OPENAI.to_string()),
        ]
        .into();
        for (host, provider) in file.intercept {
            match provider {
                Some(p) => intercept.insert(host.to_lowercase(), p),
                None => intercept.remove(&host.to_lowercase()),
            };
        }
        let mut upstream_overrides: HashMap<String, String> = file
            .upstream_overrides
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        if let Some(raw) = env("FORWARD_PROXY_UPSTREAM_OVERRIDES") {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&raw) {
                for (k, v) in map {
                    upstream_overrides.insert(k.to_lowercase(), v);
                }
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Self {
            port: env("FORWARD_PROXY_PORT")
                .and_then(|p| p.parse().ok())
                .or(file.port)
                .unwrap_or(8789),
            listen_host: env("FORWARD_PROXY_HOST")
                .or(file.listen_host)
                .unwrap_or_else(|| "127.0.0.1".into()),
            portkey_api_key: env("FORWARD_PROXY_PORTKEY_API_KEY").or(file.portkey_api_key),
            ca_dir: env("FORWARD_PROXY_CA_DIR")
                .or(file.ca_dir)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(home).join(".aigw-agent-proxy")),
            metadata: file.metadata,
            identity: file.identity,
            routes: file.routes,
            intercept,
            upstream_overrides,
            albus_basepath: env("ALBUS_BASEPATH").map(|s| s.trim_end_matches('/').to_string()),
            control_plane_basepath: env("CONTROL_PLANE_BASEPATH")
                .map(|s| s.trim_end_matches('/').to_string()),
            client_auth: env("PORTKEY_CLIENT_AUTH"),
            organisations_to_sync: env("ORGANISATIONS_TO_SYNC")
                .map(|s| s.split(',').map(|o| o.trim().to_string()).filter(|o| !o.is_empty()).collect())
                .unwrap_or_default(),
            sync_interval_ms: env("CONTROL_PLANE_SYNC_INTERVAL_MS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60_000),
            health_port: env("PORT").and_then(|p| p.parse().ok()),
            airs_api_key: env("AIRS_API_KEY"),
            web: WebInspection {
                enabled: env("FORWARD_PROXY_WEB_INSPECTION")
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "off"))
                    .or(file.web_inspection.enabled)
                    .unwrap_or(true),
                guardrails: file.web_inspection.guardrails,
                response_guardrails: file.web_inspection.response_guardrails,
                bypass_hosts: file
                    .web_inspection
                    .bypass_hosts
                    .unwrap_or_else(|| DEFAULT_WEB_BYPASS.iter().map(|s| s.to_string()).collect()),
                scan_responses: env("FORWARD_PROXY_WEB_RESPONSES")
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "off"))
                    .or(file.web_inspection.scan_responses)
                    .unwrap_or(true),
                max_scan_bytes: file.web_inspection.max_scan_bytes.unwrap_or(256 * 1024),
            },
        }
    }

    /// Whether a CONNECT to `host` is decrypted: LLM hosts always, other
    /// hosts on HTTP ports when web inspection is on and the host isn't bypassed.
    pub fn inspects_web(&self, host: &str, port: u16) -> bool {
        let host = host.to_lowercase();
        self.web.enabled
            && matches!(port, 80 | 443 | 8080 | 8443)
            && !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
            && !self.web.bypass_hosts.iter().any(|g| glob_matches(&Some(g.to_lowercase()), Some(&host)))
    }

    pub fn provider_for(&self, host: &str) -> Option<&str> {
        self.intercept.get(&host.to_lowercase()).map(String::as_str)
    }

    pub fn origin_base_url(&self, host: &str, port: u16, tls: bool) -> String {
        if let Some(o) = self.upstream_overrides.get(&host.to_lowercase()) {
            return o.trim_end_matches('/').to_string();
        }
        match (tls, port) {
            (true, 443) => format!("https://{host}"),
            (true, _) => format!("https://{host}:{port}"),
            (false, 80) => format!("http://{host}"),
            (false, _) => format!("http://{host}:{port}"),
        }
    }

    /// Endpoints handled by the governed pipeline; everything else is raw.
    pub fn is_gateway_path(&self, provider: &str, method: &str, path: &str) -> bool {
        if method != "POST" {
            return false;
        }
        match provider {
            ANTHROPIC => matches!(path, "/v1/messages" | "/v1/messages/count_tokens" | "/v1/complete"),
            OPENAI => matches!(
                path,
                "/v1/chat/completions" | "/v1/completions" | "/v1/responses" | "/v1/embeddings"
                    | "/backend-api/codex/responses"
            ),
            _ => false,
        }
    }

    /// Routes that match on user or agent need the caller identity up front.
    pub fn routes_use_identity(&self) -> bool {
        self.routes.iter().any(|r| r.matcher.user.is_some() || r.matcher.agent.is_some())
    }

    pub fn resolve_user(&self, os_user: Option<&str>) -> Option<String> {
        let os_user = os_user?;
        if let Some(mapped) = self.identity.users.get(os_user) {
            return Some(mapped.clone());
        }
        Some(match &self.identity.user_domain {
            Some(domain) => format!("{os_user}@{domain}"),
            None => os_user.to_string(),
        })
    }

    /// The first matching route, or the plain pass-through config.
    /// Returns (config, is_default).
    pub fn resolve_route(&self, facts: &RequestFacts) -> (RouteConfig, bool) {
        let matched = self.routes.iter().find(|r| {
            let m = &r.matcher;
            glob_matches(&m.host, Some(&facts.host))
                && glob_matches(&m.path, Some(&facts.path))
                && glob_matches(&m.model, facts.model.as_deref())
                && glob_matches(&m.user, facts.user.as_deref())
                && glob_matches(&m.agent, facts.agent.as_deref())
        });
        match matched {
            None => (
                RouteConfig::Inline(json!({ "provider": facts.provider, "api_key": ORIGIN_KEY })),
                true,
            ),
            Some(route) => match &route.config {
                Value::String(slug) => (RouteConfig::Slug(slug.clone()), false),
                inline => (RouteConfig::Inline(expand_origin_targets(inline, &facts.provider)), false),
            },
        }
    }
}

pub fn glob_matches(glob: &Option<String>, value: Option<&str>) -> bool {
    let Some(glob) = glob else { return true };
    let Some(value) = value else { return false };
    let pattern = format!("^{}$", regex::escape(glob).replace("\\*", ".*"));
    Regex::new(&pattern).map(|re| re.is_match(value)).unwrap_or(false)
}

/// Replaces `{ "origin": true }` targets with the origin-sentinel target.
pub fn expand_origin_targets(config: &Value, provider: &str) -> Value {
    let Value::Object(map) = config else { return config.clone() };
    let mut out = map.clone();
    if out.remove("origin") == Some(Value::Bool(true)) {
        out.insert("provider".into(), json!(provider));
        out.insert("api_key".into(), json!(ORIGIN_KEY));
    }
    if let Some(Value::Array(targets)) = out.get("targets").cloned() {
        out.insert(
            "targets".into(),
            Value::Array(targets.iter().map(|t| expand_origin_targets(t, provider)).collect()),
        );
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_chatgpt_backend_is_governed() {
        let s = Settings::from_parts(FileConfig::default());
        assert_eq!(s.provider_for("chatgpt.com"), Some(OPENAI));
        assert!(s.is_gateway_path(OPENAI, "POST", "/backend-api/codex/responses"));
        assert!(!s.is_gateway_path(OPENAI, "GET", "/backend-api/wham/usage"));
        assert_eq!(crate::providers::Endpoint::from_path("/backend-api/codex/responses"), Some(crate::providers::Endpoint::Responses));
    }


    fn settings(json: &str) -> Settings {
        Settings::from_parts(serde_json::from_str(json).unwrap())
    }

    fn facts() -> RequestFacts {
        RequestFacts {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            provider: ANTHROPIC.into(),
            ..Default::default()
        }
    }

    #[test]
    fn default_route_is_origin_passthrough() {
        let (config, is_default) = settings("{}").resolve_route(&facts());
        assert!(is_default);
        match config {
            RouteConfig::Inline(v) => assert_eq!(v, json!({"provider":"anthropic","api_key":ORIGIN_KEY})),
            _ => panic!("expected inline"),
        }
    }

    #[test]
    fn routes_match_on_model_user_and_agent() {
        let s = settings(
            r#"{"routes":[
              {"match":{"agent":"codex"},"config":"pc-codex"},
              {"match":{"model":"claude-opus-*"},"config":"pc-opus"},
              {"match":{"user":"*@contractor.example"},"config":"pc-strict"}]}"#,
        );
        let pick = |model: Option<&str>, user: Option<&str>, agent: Option<&str>| {
            let mut f = facts();
            f.model = model.map(Into::into);
            f.user = user.map(Into::into);
            f.agent = agent.map(Into::into);
            match s.resolve_route(&f).0 {
                RouteConfig::Slug(slug) => slug,
                RouteConfig::Inline(_) => "default".into(),
            }
        };
        assert_eq!(pick(None, None, Some("codex")), "pc-codex");
        assert_eq!(pick(Some("claude-opus-4-1"), None, Some("claude-code")), "pc-opus");
        assert_eq!(pick(None, Some("jo@contractor.example"), None), "pc-strict");
        assert_eq!(pick(Some("claude-haiku-4-5"), Some("alice"), Some("claude-code")), "default");
    }

    #[test]
    fn expands_nested_origin_targets() {
        let v = expand_origin_targets(
            &json!({"strategy":{"mode":"fallback"},"targets":[{"origin":true,"override_params":{"model":"m"}},{"provider":"openai","api_key":"sk"}]}),
            ANTHROPIC,
        );
        assert_eq!(v["targets"][0]["api_key"], ORIGIN_KEY);
        assert_eq!(v["targets"][0]["provider"], ANTHROPIC);
        assert_eq!(v["targets"][1]["api_key"], "sk");
    }

    #[test]
    fn identity_mapping() {
        let s = settings(r#"{"identity":{"users":{"svc":"build-bot"},"userDomain":"example.com"}}"#);
        assert_eq!(s.resolve_user(Some("alice")).as_deref(), Some("alice@example.com"));
        assert_eq!(s.resolve_user(Some("svc")).as_deref(), Some("build-bot"));
        assert_eq!(s.resolve_user(None), None);
    }
}
