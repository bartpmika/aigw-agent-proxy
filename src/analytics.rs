//! Spend and logs: the `generations` analytics row (batched to
//! `/dp/metrics`) and the full log object (`/dp/logs`), in the same shape as
//! the TypeScript gateway. Cost uses the gateway's bundled pricing tables.

use crate::control_plane::{KeyDetails, GATEWAY_VERSION};
use crate::providers::Usage;
use serde_json::{json, Map, Value};
use futures_util::future::BoxFuture;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Mutex;

const BATCH_INTERVAL: Duration = Duration::from_secs(3);
/// Log uploads in flight before bodies are left out of new logs. Analytics
/// rows (spend, metadata) are always recorded.
const MAX_LOGS_IN_FLIGHT: usize = 64;

static PRICING: LazyLock<Map<String, Value>> = LazyLock::new(|| {
    let mut all = Map::new();
    for (provider, raw) in [
        ("anthropic", include_str!("../data/pricing/anthropic.json")),
        ("openai", include_str!("../data/pricing/openai.json")),
    ] {
        all.insert(provider.into(), serde_json::from_str(raw).unwrap_or(json!({})));
    }
    all
});

/// Pricing rates (cents per token) for a model: exact id, else the dated
/// variant of an undated alias (e.g. "claude-haiku-4-5" -> "-20251001").
fn rates(provider: &str, model: &str) -> Option<&'static Value> {
    let table = PRICING.get(provider)?.as_object()?;
    if let Some(v) = table.get(model) {
        return Some(&v["pricing_config"]["pay_as_you_go"]);
    }
    let prefix = format!("{model}-");
    table
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix) && k[prefix.len()..].chars().all(|c| c.is_ascii_digit()))
        .max_by_key(|(k, _)| k.as_str())
        .map(|(_, v)| &v["pricing_config"]["pay_as_you_go"])
}

/// Cost in cents, like the TypeScript gateway (`requestCost + responseCost`).
pub fn cost(provider: &str, model: &str, usage: &Usage) -> f64 {
    let Some(r) = rates(provider, model) else { return 0.0 };
    let price = |k: &str| r[k]["price"].as_f64().unwrap_or(0.0);
    let regular_req = usage.req_units.saturating_sub(usage.cache_read + usage.cache_write);
    regular_req as f64 * price("request_token")
        + usage.cache_read as f64 * price("cache_read_input_token")
        + usage.cache_write as f64 * price("cache_write_input_token")
        + usage.res_units as f64 * price("response_token")
}

/// Metadata resolved when the log is written (the OS lookup of the calling
/// process runs off the request path).
pub type MetadataSource = BoxFuture<'static, Map<String, Value>>;

/// Everything known about one governed request, for logging.
pub struct Record {
    pub id: String,
    pub trace_id: String,
    pub provider: String,
    pub model: String,
    pub request_url: String,
    pub method: String,
    pub status: u16,
    pub is_streaming: bool,
    pub usage: Usage,
    pub response_time_ms: u64,
    pub ttlt_ms: u64,
    pub metadata: Map<String, Value>,
    pub metadata_source: Option<MetadataSource>,
    pub request_body: Arc<Value>,
    pub transformed_request_body: Arc<Value>,
    pub response_headers: Map<String, Value>,
    pub response_body: Value,
    pub portkey_headers: Map<String, Value>,
    pub hook_results: Value,
    pub mode: String,
    pub last_used_option_index: i64,
    pub config_slug: String,
    /// The Portkey API key used (for usage accounting; never logged).
    pub api_key: String,
}

fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 6 {
        return "********".into();
    }
    format!(
        "{}********{}",
        chars[..2].iter().collect::<String>(),
        chars[chars.len() - 3..].iter().collect::<String>()
    )
}

pub fn masked_portkey_headers(api_key: &str, config: &str, metadata: &str, trace_id: &str) -> Map<String, Value> {
    let masked_config = serde_json::from_str::<Value>(config)
        .ok()
        .map(|mut c| {
            mask_api_keys(&mut c);
            c.to_string()
        })
        .unwrap_or_else(|| config.to_string());
    let mut h = Map::new();
    h.insert("x-portkey-api-key".into(), json!(mask(api_key)));
    h.insert("x-portkey-config".into(), json!(masked_config));
    h.insert("x-portkey-metadata".into(), json!(metadata));
    h.insert("x-portkey-trace-id".into(), json!(trace_id));
    h
}

fn mask_api_keys(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if k == "api_key" {
                    if let Some(s) = val.as_str() {
                        *val = json!(mask(s));
                    }
                } else {
                    mask_api_keys(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(mask_api_keys),
        _ => {}
    }
}

/// The `generations` analytics row (60 columns, same as the TS gateway).
pub fn analytics_row(r: &Record, key: &KeyDetails) -> Value {
    let created_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let (md_keys, md_values): (Vec<Value>, Vec<Value>) = r
        .metadata
        .iter()
        .map(|(k, v)| (json!(k), json!(v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))))
        .unzip();
    let str_md = |k: &str| r.metadata.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let is_success = (200..300).contains(&r.status);
    json!({
        "id": r.id,
        "organisation_id": key.org_id(),
        "organisation_name": key.org()["name"].as_str().unwrap_or(""),
        "user_id": key.key()["user_id"].as_str().unwrap_or(""),
        "prompt_id": "",
        "prompt_version_id": "",
        "config_id": "",
        "created_at": created_at,
        "is_success": is_success,
        "ai_org": r.provider,
        "ai_org_auth_hash": "",
        "ai_model": r.model,
        "req_units": r.usage.req_units,
        "res_units": r.usage.res_units,
        "total_units": r.usage.total(),
        "cost": if is_success { cost(&r.provider, &r.model, &r.usage) } else { 0.0 },
        "cost_currency": "USD",
        "request_url": r.request_url,
        "request_method": r.method,
        "response_status_code": r.status,
        "response_time": r.response_time_ms,
        "is_proxy_call": false,
        "cache_status": "DISABLED",
        "cache_type": "",
        "stream_mode": if r.is_streaming { json!(true) } else { json!(0) },
        "retry_success_count": "0",
        "_environment": str_md("_environment"),
        "_user": str_md("_user"),
        "_organisation": str_md("_organisation"),
        "_prompt": str_md("_prompt"),
        "trace_id": r.trace_id,
        "span_id": r.id,
        "span_name": "llm",
        "parent_span_id": "",
        "extra_key": "is_raw_logging_enabled",
        "extra_value": "true",
        "mode": r.mode,
        "virtual_key": "",
        "source": "rubeus-2",
        "runtime": "",
        "runtime_version": "",
        "sdk_version": "",
        "config": r.config_slug,
        "internal_trace_id": uuid::Uuid::new_v4().to_string(),
        "last_used_option_index": r.last_used_option_index,
        "config_version_id": "",
        "prompt_slug": "",
        "workspace_slug": key.workspace_slug(),
        "log_store_file_path_format": "v1",
        "metadata.key": md_keys,
        "metadata.value": md_values,
        "api_key_id": key.key_id(),
        "request_parsing_time": 0,
        "pre_processing_time": 0,
        "cache_processing_time": 0,
        "response_parsing_time": 0,
        "gateway_version": GATEWAY_VERSION,
        "ttlt": r.ttlt_ms,
        "gateway_processing_time": 0,
        "upstream_response_time": r.response_time_ms,
    })
}

pub fn log_object(r: &Record, key: &KeyDetails, row: &Value) -> Value {
    json!({
        "_id": r.id,
        "request": {
            "url": r.request_url,
            "method": r.method,
            "headers": { "content-type": "application/json" },
            "body": r.request_body,
            "portkeyHeaders": r.portkey_headers,
        },
        "response": {
            "status": r.status,
            "headers": r.response_headers,
            "body": r.response_body,
            "responseTime": r.response_time_ms,
            "lastUsedOptionJsonPath": "config",
        },
        "organisation_id": key.org_id(),
        "created_at": chrono::Utc::now().to_rfc2822(),
        "metrics": row,
        "finalUntransformedRequest": { "body": r.request_body },
        "transformedRequest": { "body": r.transformed_request_body, "headers": {} },
        "hook_results": r.hook_results,
    })
}

/// Uploads logs immediately and analytics rows in 3-second batches.
#[derive(Clone)]
pub struct Sink {
    http: reqwest::Client,
    base: Option<String>,
    client_auth: Option<String>,
    batch: Arc<Mutex<Vec<Value>>>,
    logs_in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

impl Sink {
    pub fn new(http: reqwest::Client, base: Option<String>, client_auth: Option<String>) -> Self {
        let sink = Self {
            http,
            base,
            client_auth,
            batch: Arc::new(Mutex::new(Vec::new())),
            logs_in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let flusher = sink.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BATCH_INTERVAL);
            loop {
                ticker.tick().await;
                flusher.flush().await;
            }
        });
        sink
    }

    pub async fn record(&self, mut r: Record, key: &KeyDetails) {
        if let Some(source) = r.metadata_source.take() {
            r.metadata = source.await;
            r.portkey_headers.insert(
                "x-portkey-metadata".into(),
                json!(Value::Object(r.metadata.clone()).to_string()),
            );
        }
        let row = analytics_row(&r, key);
        use std::sync::atomic::Ordering;
        if self.logs_in_flight.load(Ordering::Relaxed) >= MAX_LOGS_IN_FLIGHT {
            // Backlog: keep memory bounded by leaving the bodies out.
            let omitted = Arc::new(json!({ "_omitted": "log upload backlog" }));
            r.request_body = omitted.clone();
            r.transformed_request_body = omitted.clone();
            r.response_body = (*omitted).clone();
        }
        let log = log_object(&r, key, &row);
        let org = key.org_id().to_string();
        self.batch.lock().await.push(row);
        let Some(base) = self.base.clone() else { return };
        let body = json!({
            "logObject": log,
            "logOptions": {
                "organisationId": org,
                "filePath": format!("30/{org}/{}.json", r.id),
                "mongoCollectionName": "",
            },
        });
        let req = self.authorized(self.http.post(format!("{base}/dp/logs")).json(&body));
        drop(body);
        let in_flight = self.logs_in_flight.clone();
        in_flight.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            for attempt in 0..3u32 {
                match req.try_clone().expect("json body clones").send().await {
                    Ok(r) if r.status().is_success() => break,
                    Ok(r) => tracing::warn!("log upload failed: HTTP {}", r.status()),
                    Err(e) => tracing::warn!("log upload failed: {e}"),
                }
                tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt))).await;
            }
            in_flight.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn authorized(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.client_auth {
            Some(auth) => req.header("authorization", auth),
            None => req,
        }
    }

    pub async fn flush(&self) {
        let rows: Vec<Value> = std::mem::take(&mut *self.batch.lock().await);
        let Some(base) = &self.base else { return };
        if rows.is_empty() {
            return;
        }
        let body = json!({ "table": "generations", "data": rows });
        let req = self.authorized(self.http.post(format!("{base}/dp/metrics")).json(&body));
        match req.send().await {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => tracing::warn!("analytics push failed: HTTP {}", r.status()),
            Err(e) => tracing::warn!("analytics push failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_known_models_and_dated_aliases() {
        let usage = Usage { req_units: 1000, res_units: 100, cache_read: 0, cache_write: 0 };
        let dated = cost("anthropic", "claude-haiku-4-5-20251001", &usage);
        assert!(dated > 0.0);
        assert_eq!(cost("anthropic", "claude-haiku-4-5", &usage), dated);
        assert_eq!(cost("anthropic", "not-a-model", &usage), 0.0);
    }

    #[test]
    fn masks_secrets() {
        assert_eq!(mask("pk-basic"), "pk********sic");
        let h = masked_portkey_headers("pk-basic", r#"{"provider":"anthropic","api_key":"forward-proxy-origin"}"#, "{}", "t");
        assert_eq!(h["x-portkey-config"], r#"{"provider":"anthropic","api_key":"fo********gin"}"#);
    }
}
