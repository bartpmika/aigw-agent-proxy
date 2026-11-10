//! Budgets that hold across machines, without Redis.
//!
//! Each proxy adds up the spend it has not reported yet (cost in cents,
//! tokens) for every API-key and workspace usage limit, and sends those
//! deltas to the control plane on a timer, in the TS gateway's resync
//! format. The control plane totals all gateways and marks the key or
//! workspace exhausted; proxies see that on their next key-details refresh
//! (at most `KEY_DETAILS_TTL_MS`, sooner when sync reports a budget change)
//! and block, so a budget holds across every laptop using it.

use crate::control_plane::{KeyDetails, GATEWAY_VERSION};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct Pending {
    /// (API key, counter type) -> amount.
    api_keys: HashMap<(String, String), f64>,
    /// (workspace id, counter type, usage limit id) -> amount.
    workspaces: HashMap<(String, String, String), f64>,
}

#[derive(Default)]
pub struct UsageTracker {
    pending: Mutex<HashMap<String, Pending>>,
}

/// The amount a request adds to one usage limit, if the limit is active.
fn amount_for(limit: &Value, cost_cents: f64, tokens: u64) -> Option<(String, f64)> {
    if limit["status"] == "exhausted" || !limit["credit_limit"].as_f64().is_some_and(|c| c > 0.0) {
        return None;
    }
    let counter = limit["type"].as_str().filter(|t| !t.is_empty()).unwrap_or("cost").to_string();
    let amount = if counter == "cost" { cost_cents } else { tokens as f64 };
    (amount > 0.0).then_some((counter, amount))
}

fn limits(entity: &Value) -> Vec<Value> {
    match &entity["usage_limits"] {
        Value::Array(a) => a.clone(),
        v @ Value::Object(_) => vec![v.clone()],
        _ => Vec::new(),
    }
}

impl UsageTracker {
    /// Adds one request's spend to the pending deltas.
    pub fn record(&self, key: &KeyDetails, api_key: &str, cost_cents: f64, tokens: u64) {
        if cost_cents <= 0.0 && tokens == 0 {
            return;
        }
        let mut all = self.pending.lock().unwrap();
        let pending = all.entry(key.org_id().to_string()).or_default();
        // API-key limits apply only when the organisation enables them (as in TS).
        if key.org()["settings"]["is_api_key_limit_enabled"] == true {
            for limit in limits(key.key()) {
                if let Some((counter, amount)) = amount_for(&limit, cost_cents, tokens) {
                    *pending.api_keys.entry((api_key.to_string(), counter)).or_default() += amount;
                }
            }
        }
        for limit in limits(key.workspace()) {
            if let Some((counter, amount)) = amount_for(&limit, cost_cents, tokens) {
                let id = limit["id"].as_str().unwrap_or("").to_string();
                *pending.workspaces.entry((key.workspace_id().to_string(), counter, id)).or_default() += amount;
            }
        }
    }

    /// Takes the pending deltas as resync bodies, one per organisation.
    pub fn take(&self) -> Vec<(String, Value)> {
        let drained: Vec<(String, Pending)> = self.pending.lock().unwrap().drain().collect();
        drained
            .into_iter()
            .filter(|(_, p)| !p.api_keys.is_empty() || !p.workspaces.is_empty())
            .map(|(org, p)| {
                let api_keys: Vec<Value> = p.api_keys.into_iter().map(|((id, _), usage)| json!({ "id": id, "usage": usage })).collect();
                let keys: Vec<Value> = p
                    .workspaces
                    .into_iter()
                    .map(|((ws, counter, limit_id), usage)| {
                        let mut v = json!({ "key": ws, "type": "WORKSPACE", "counterType": counter, "usage": usage });
                        if !limit_id.is_empty() {
                            v["usageLimitId"] = json!(limit_id);
                        }
                        v
                    })
                    .collect();
                let mut body = json!({ "version": GATEWAY_VERSION });
                if !api_keys.is_empty() {
                    body["apiKeysToUpdateUsage"] = json!(api_keys);
                }
                if !keys.is_empty() {
                    body["keysToUpdateUsage"] = json!(keys);
                }
                (org, body)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_and_drains_deltas() {
        let key = KeyDetails {
            raw: json!({
                "api_key_details": { "id": "k1", "usage_limits": [{ "id": "ul-k", "type": "tokens", "credit_limit": 1000, "status": "active" }] },
                "organisation_details": { "organisation_id": "org1", "settings": { "is_api_key_limit_enabled": true } },
                "workspace_details": { "id": "ws1", "usage_limits": [{ "id": "ul-w", "type": "cost", "credit_limit": 5, "status": "active" },
                                                                    { "id": "ul-x", "type": "cost", "credit_limit": 5, "status": "exhausted" }] },
            }),
        };
        let t = UsageTracker::default();
        t.record(&key, "pk-1", 2.5, 100);
        t.record(&key, "pk-1", 1.5, 50);
        let out = t.take();
        assert_eq!(out.len(), 1);
        let (org, body) = &out[0];
        assert_eq!(org, "org1");
        assert_eq!(body["apiKeysToUpdateUsage"], json!([{ "id": "pk-1", "usage": 150.0 }]));
        assert_eq!(body["keysToUpdateUsage"], json!([{ "key": "ws1", "type": "WORKSPACE", "counterType": "cost", "usage": 4.0, "usageLimitId": "ul-w" }]));
        assert!(t.take().is_empty(), "deltas are cleared once taken");
    }
}
