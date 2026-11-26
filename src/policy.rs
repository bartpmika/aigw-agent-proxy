//! Access policy (scopes, exhausted/expired keys and workspaces, request rate
//! limits) and gateway error responses in the client's provider format.

use crate::config::ANTHROPIC;
use crate::control_plane::KeyDetails;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// An error produced by the gateway itself (not by the upstream provider).
#[derive(Debug, Clone)]
pub struct GatewayError {
    /// The gateway's own status (e.g. 446 guardrail, 412 budget).
    pub status: u16,
    pub message: String,
    /// A gateway exception (bad config, missing options): fallback stops
    /// here instead of trying the next target, as in the TS gateway.
    pub exception: bool,
    /// Portkey error code (e.g. "033") for `generateApiErrorResponse` errors.
    pub code: Option<String>,
}

impl GatewayError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), exception: true, code: None }
    }

    /// Like the TS gateway's generateApiErrorResponse.
    pub fn portkey(status: u16, message: &str, code: &str) -> Self {
        let mut e = Self::new(status, format!("Portkey Error: {message}. Error Code: {code}"));
        e.code = Some(code.to_string());
        e
    }

    pub fn guardrail() -> Self {
        Self::new(
            446,
            "The guardrail checks defined in the config failed. You can find more information in the `hook_results` object.",
        )
    }

    /// Status and body in the provider's own error shape. 446 and 412 become
    /// non-retryable client errors; the original status is kept in a header.
    pub fn to_provider(&self, provider: &str) -> (u16, Value) {
        let status = match self.status {
            446 => 400,
            412 => 403,
            s => s,
        };
        let error_type = match status {
            401 => "authentication_error",
            403 => "permission_error",
            429 => "rate_limit_error",
            s if s >= 500 => "api_error",
            _ => "invalid_request_error",
        };
        let body = if provider == ANTHROPIC {
            json!({ "type": "error", "error": { "type": error_type, "message": self.message } })
        } else {
            json!({ "error": { "message": self.message, "type": error_type, "code": null } })
        };
        (status, body)
    }
}

fn exhausted(entity: &Value) -> bool {
    entity["status"] == "exhausted"
        || entity["usage_limits"]
            .as_array()
            .is_some_and(|l| l.iter().any(|u| u["status"] == "exhausted"))
}

/// Pre-request checks done by the TS gateway's authN/authZ middleware.
pub fn check_access(key: &KeyDetails) -> Result<(), GatewayError> {
    check_access_for(key, "completions.write")
}

/// authN checks (exhausted/expired key and workspace), then the route's
/// scope (authZ), then request rate limits — in the TS middleware order.
pub fn check_access_for(key: &KeyDetails, scope: &str) -> Result<(), GatewayError> {
    let (k, ws) = (key.key(), key.workspace());
    if exhausted(k) {
        return Err(GatewayError::portkey(412, "Portkey API Key Usage Limit Exceeded", "04"));
    }
    if k["status"] == "expired" {
        return Err(GatewayError::portkey(401, "Portkey API Key Expired", "01"));
    }
    if exhausted(ws) {
        return Err(GatewayError::portkey(412, "Portkey Workspace Usage Limit Exceeded", "04"));
    }
    if ws["status"] == "expired" {
        return Err(GatewayError::portkey(401, "Portkey Workspace Expired", "01"));
    }
    if !key.has_scope(scope) {
        return Err(GatewayError::portkey(403, "Forbidden!", "033"));
    }
    for (entity, id, label) in [(ws, key.workspace_id(), "workspace"), (k, key.key_id(), "apikey")] {
        for limit in entity["rate_limits"].as_array().cloned().unwrap_or_default() {
            if limit["type"] != "requests" {
                continue;
            }
            let (Some(unit), Some(value)) = (limit["unit"].as_str(), limit["value"].as_u64()) else { continue };
            if !allow_request(id, unit, value) {
                let msg = if label == "workspace" {
                    format!("workspace {} rate limit exceeded", short_hash(id))
                } else {
                    format!("apikey {} rate limit exceded", short_hash(id))
                };
                return Err(GatewayError::portkey(429, &msg, "05"));
            }
        }
    }
    Ok(())
}

fn short_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:x}", h.finish())[..8].to_string()
}

static WINDOWS: LazyLock<Mutex<HashMap<String, (u64, u64)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Fixed-window request counter per entity and unit.
fn allow_request(entity: &str, unit: &str, limit: u64) -> bool {
    let window = match unit {
        "rps" => 1,
        "rpm" => 60,
        "rph" => 3600,
        "rpd" => 86_400,
        "rpw" => 604_800,
        _ => return true,
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let bucket = now / window;
    let mut windows = WINDOWS.lock().unwrap();
    let entry = windows.entry(format!("{entity}:{unit}")).or_insert((bucket, 0));
    if entry.0 != bucket {
        *entry = (bucket, 0);
    }
    entry.1 += 1;
    entry.1 <= limit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(v: Value) -> KeyDetails {
        KeyDetails { raw: v }
    }

    #[test]
    fn enforces_scopes_budgets_and_rate_limits() {
        let base = json!({"api_key_details":{"id":"k1","scopes":["completions.write"]},"workspace_details":{"id":"w1"}});
        assert!(check_access(&key(base.clone())).is_ok());
        let mut no_scope = base.clone();
        no_scope["api_key_details"]["scopes"] = json!([]);
        assert_eq!(check_access(&key(no_scope)).unwrap_err().status, 403);
        let mut spent = base.clone();
        spent["api_key_details"]["usage_limits"] = json!([{"status":"exhausted"}]);
        let err = check_access(&key(spent)).unwrap_err();
        assert_eq!((err.status, err.to_provider(ANTHROPIC).0), (412, 403));
        let mut limited = base.clone();
        limited["api_key_details"]["id"] = json!("k-rate");
        limited["api_key_details"]["rate_limits"] = json!([{"type":"requests","unit":"rpm","value":2}]);
        let k = key(limited);
        assert!(check_access(&k).is_ok() && check_access(&k).is_ok());
        assert_eq!(check_access(&k).unwrap_err().to_provider("openai").0, 429);
    }
}
