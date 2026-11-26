//! Control plane ("albus") client: API key details, guardrails, configs,
//! integrations, the periodic sync (heartbeat + cache invalidation) and the
//! usage resync. Same endpoints and headers as the TypeScript gateway.

use crate::config::Settings;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub const GATEWAY_VERSION: &str = "2.2.3";
const CACHE_TTL: Duration = Duration::from_secs(10 * 60);
static KEY_TTL: std::sync::LazyLock<Duration> = std::sync::LazyLock::new(|| {
    Duration::from_millis(std::env::var("KEY_DETAILS_TTL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(60_000))
});

struct Cached {
    at: Instant,
    value: Option<Value>,
}

#[derive(Clone)]
pub struct ControlPlane {
    http: reqwest::Client,
    albus: Option<String>,
    client_auth: Option<String>,
    cache: Arc<RwLock<HashMap<String, Cached>>>,
    sync_identifier: String,
}

/// The parts of `/v2/api-keys/self/details` the pipeline uses.
#[derive(Debug, Clone)]
pub struct KeyDetails {
    pub raw: Value,
}

impl KeyDetails {
    pub fn key(&self) -> &Value { &self.raw["api_key_details"] }
    pub fn org(&self) -> &Value { &self.raw["organisation_details"] }
    pub fn workspace(&self) -> &Value { &self.raw["workspace_details"] }
    pub fn org_id(&self) -> &str { self.org()["organisation_id"].as_str().unwrap_or("") }
    pub fn workspace_id(&self) -> &str { self.workspace()["id"].as_str().unwrap_or("") }
    pub fn workspace_slug(&self) -> &str { self.workspace()["slug"].as_str().unwrap_or("") }
    pub fn key_id(&self) -> &str { self.key()["id"].as_str().unwrap_or("") }
    pub fn has_scope(&self, scope: &str) -> bool {
        self.key()["scopes"].as_array().is_some_and(|s| s.iter().any(|v| v == scope))
    }
    /// Default config slug from the key, else the workspace.
    pub fn default_config_slug(&self) -> Option<String> {
        self.key()["defaults"]["config_slug"]
            .as_str()
            .or_else(|| self.workspace()["defaults"]["config_slug"].as_str())
            .map(str::to_string)
    }
    pub fn allow_config_override(&self) -> bool {
        self.key()["defaults"]["allow_config_override"].as_bool() != Some(false)
    }
    /// Default guardrail slugs from org and workspace defaults.
    pub fn default_guardrails(&self, which: &str) -> Vec<String> {
        let mut out = Vec::new();
        for defaults in [&self.org()["defaults"], &self.workspace()["defaults"]] {
            if let Some(list) = defaults[which].as_array() {
                out.extend(list.iter().filter_map(|g| g["slug"].as_str().map(str::to_string)));
            }
        }
        out
    }
    /// Metadata defaults (key, then workspace) merged over request metadata.
    pub fn default_metadata(&self) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        for md in [&self.key()["defaults"]["metadata"], &self.workspace()["defaults"]["metadata"]] {
            if let Some(map) = md.as_object() {
                out.extend(map.clone());
            }
        }
        out
    }
}

impl ControlPlane {
    pub fn new(settings: &Settings, http: reqwest::Client) -> Self {
        Self {
            http,
            albus: settings.albus_basepath.clone(),
            client_auth: settings.client_auth.clone(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            sync_identifier: format!("SYNC_ID_{}", uuid::Uuid::new_v4()),
        }
    }

    async fn cached_get(&self, cache_key: String, url: String, api_key: &str) -> Option<Value> {
        // Key details carry budget status: refresh them often, so a budget
        // exhausted by other machines takes effect quickly.
        let ttl = if cache_key.starts_with("key:") { *KEY_TTL } else { CACHE_TTL };
        if let Some(c) = self.cache.read().await.get(&cache_key) {
            if c.at.elapsed() < ttl {
                return c.value.clone();
            }
        }
        let mut req = self.http.get(&url).header("content-type", "application/json");
        if let Some(auth) = &self.client_auth {
            req = req.header("authorization", auth);
        }
        req = req.header("x-portkey-api-key", api_key);
        let value = match req.send().await {
            Ok(resp) if resp.status().is_success() => resp.json::<Value>().await.ok(),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!("control plane GET {url} failed: {e}");
                return None; // don't cache transport errors
            }
        };
        self.cache
            .write()
            .await
            .insert(cache_key, Cached { at: Instant::now(), value: value.clone() });
        value
    }

    pub async fn key_details(&self, api_key: &str) -> Option<KeyDetails> {
        let albus = self.albus.as_ref()?;
        let url = format!("{albus}/v2/api-keys/self/details?include_organisation=true&include_workspace=true");
        let v = self.cached_get(format!("key:{api_key}"), url, api_key).await?;
        let data = v.get("data").cloned().unwrap_or(v);
        data.get("api_key_details")?;
        Some(KeyDetails { raw: data })
    }

    pub async fn guardrail(&self, slug: &str, key: &KeyDetails, api_key: &str) -> Option<Value> {
        let albus = self.albus.as_ref()?;
        let url = format!(
            "{albus}/v2/guardrails/{slug}?organisation_id={}&workspace_id={}",
            key.org_id(), key.workspace_id()
        );
        let v = self.cached_get(format!("guardrail:{slug}"), url, api_key).await?;
        Some(v.get("data").cloned().unwrap_or(v))
    }

    /// A stored config and its version id.
    pub async fn config(&self, slug: &str, key: &KeyDetails, api_key: &str) -> Option<(Value, Option<String>)> {
        let albus = self.albus.as_ref()?;
        let url = format!(
            "{albus}/v2/configs/{slug}?organisation_id={}&workspace_id={}",
            key.org_id(), key.workspace_id()
        );
        let v = self.cached_get(format!("config:{slug}"), url, api_key).await?;
        let v = v.get("data").cloned().unwrap_or(v);
        let version = v["version_id"].as_str().map(str::to_string);
        let config = match &v["config"] {
            Value::String(s) => serde_json::from_str(s).ok(),
            Value::Object(_) => Some(v["config"].clone()),
            _ => None,
        }?;
        Some((config, version))
    }

    /// A virtual key / integration provider record (`virtual_key` or `@slug`).
    pub async fn virtual_key(&self, slug: &str, key: &KeyDetails, api_key: &str) -> Option<Value> {
        let albus = self.albus.as_ref()?;
        let url = format!(
            "{albus}/v2/virtual-keys/{slug}?organisation_id={}&workspace_id={}",
            key.org_id(), key.workspace_id()
        );
        let v = self.cached_get(format!("virtual_key:{slug}"), url, api_key).await?;
        Some(v.get("data").cloned().unwrap_or(v))
    }

    /// A prompt template record (`/v2/prompts/{slug}`).
    pub async fn prompt(&self, slug: &str, key: &KeyDetails, api_key: &str) -> Option<Value> {
        let albus = self.albus.as_ref()?;
        let url = format!("{albus}/v2/prompts/{slug}?organisation_id={}&workspace_id={}", key.org_id(), key.workspace_id());
        let v = self.cached_get(format!("prompt:{slug}"), url, api_key).await?;
        Some(v.get("data").cloned().unwrap_or(v))
    }

    /// A prompt partial record (`/v2/prompts/partials/{slug}`).
    pub async fn prompt_partial(&self, slug: &str, key: &KeyDetails, api_key: &str) -> Option<Value> {
        let albus = self.albus.as_ref()?;
        let url = format!("{albus}/v2/prompts/partials/{slug}?organisation_id={}&workspace_id={}", key.org_id(), key.workspace_id());
        let v = self.cached_get(format!("prompt_partial:{slug}"), url, api_key).await?;
        Some(v.get("data").cloned().unwrap_or(v))
    }

    /// Credentials for a guardrail provider (e.g. "panw-prisma-airs").
    pub async fn integration_credentials(&self, provider: &str, key: &KeyDetails, api_key: &str) -> Value {
        let Some(albus) = self.albus.as_ref() else { return json!({}) };
        let url = format!("{albus}/v2/integrations/?organisation_id={}", key.org_id());
        let v = self.cached_get(format!("integrations:{}", key.org_id()), url, api_key).await;
        let list = v.as_ref().and_then(|v| v.get("data").cloned().or_else(|| Some(v.clone())));
        list.and_then(|l| l.as_array().cloned())
            .and_then(|items| {
                items.into_iter().find(|i| i["integration_slug"] == provider).map(|i| i["credentials"].clone())
            })
            .unwrap_or_else(|| json!({}))
    }

    /// Pulls changes; any reported change clears the matching cached entries.
    /// The call itself is the gateway's heartbeat in the control plane.
    pub async fn sync(&self, org_id: &str) {
        let Some(albus) = &self.albus else { return };
        let url = format!(
            "{albus}/v1/organisation/{org_id}/sync/0?version={GATEWAY_VERSION}&identifier={}",
            self.sync_identifier
        );
        let mut req = self.http.get(&url);
        if let Some(auth) = &self.client_auth {
            req = req.header("authorization", auth);
        }
        let data = match req.send().await {
            Ok(r) if r.status().is_success() => r.json::<Value>().await.ok(),
            Ok(r) => {
                tracing::warn!("sync failed: HTTP {}", r.status());
                None
            }
            Err(e) => {
                tracing::warn!("sync failed: {e}");
                None
            }
        };
        let Some(data) = data.map(|d| d.get("data").cloned().unwrap_or(d)) else { return };
        let changed = |field: &str| data[field].as_array().is_some_and(|a| !a.is_empty());
        let mut cache = self.cache.write().await;
        if ["configsV2", "configs"].iter().any(|f| changed(f)) {
            cache.retain(|k, _| !k.starts_with("config:"));
        }
        if ["guardrailsV2"].iter().any(|f| changed(f)) {
            cache.retain(|k, _| !k.starts_with("guardrail:"));
        }
        if ["virtualKeys", "virtualKeysV2", "virtualKeysWithBudgets"].iter().any(|f| changed(f)) {
            cache.retain(|k, _| !k.starts_with("virtual_key:"));
        }
        if ["promptsV2", "prompts"].iter().any(|f| changed(f)) {
            cache.retain(|k, _| !k.starts_with("prompt:"));
        }
        if ["promptPartialsV2", "promptPartials"].iter().any(|f| changed(f)) {
            cache.retain(|k, _| !k.starts_with("prompt_partial:"));
        }
        if ["integrationsV2"].iter().any(|f| changed(f)) {
            cache.retain(|k, _| !k.starts_with("integrations:"));
        }
        if ["apiKeyIds", "apiKeysToReset", "apiKeysToResetV2", "apiKeyIdsWithBudgets"]
            .iter()
            .any(|f| changed(f))
        {
            cache.retain(|k, _| !k.starts_with("key:"));
        }
    }

    /// Usage resync, sent after requests like the TypeScript gateway does.
    pub fn resync(&self, org_id: &str) {
        let Some(albus) = self.albus.clone() else { return };
        let mut req = self
            .http
            .post(format!("{albus}/v1/organisation/{org_id}/resync"))
            .json(&json!({ "version": GATEWAY_VERSION, "markFirstGenerationDone": true }));
        if let Some(auth) = &self.client_auth {
            req = req.header("authorization", auth);
        }
        tokio::spawn(async move {
            let _ = req.send().await;
        });
    }

    /// Sends usage deltas (resync format). Returns false if it didn't arrive.
    pub async fn send_usage(&self, org_id: &str, body: &Value) -> bool {
        let Some(albus) = &self.albus else { return true };
        let mut req = self.http.post(format!("{albus}/v1/organisation/{org_id}/resync")).json(body);
        if let Some(auth) = &self.client_auth {
            req = req.header("authorization", auth);
        }
        match req.send().await {
            Ok(r) if r.status().is_success() => true,
            Ok(r) => {
                tracing::warn!("usage resync failed: HTTP {}", r.status());
                false
            }
            Err(e) => {
                tracing::warn!("usage resync failed: {e}");
                false
            }
        }
    }

    pub fn spawn_sync_loop(self: &Arc<Self>, orgs: Vec<String>, interval: Duration) {
        if orgs.is_empty() || self.albus.is_none() {
            return;
        }
        let cp = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                for org in &orgs {
                    cp.sync(org).await;
                }
            }
        });
        tracing::info!("syncing with the control plane every {}s", interval.as_secs());
    }
}
