//! API-mode request validation: port of the TS `requestValidator`
//! middleware and its zod config schema, with the same messages. Zod
//! semantics are kept: a node's field errors abort its refinements; failing
//! refinements are all reported.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

static VALID_PROVIDERS: LazyLock<Vec<String>> =
    LazyLock::new(|| serde_json::from_str(include_str!("../data/valid_providers.json")).expect("valid_providers.json"));

pub fn valid_provider(p: &str) -> bool {
    VALID_PROVIDERS.iter().any(|v| v == p)
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

struct Issues(Vec<String>);

impl Issues {
    fn push(&mut self, path: &[String], message: impl Into<String>) {
        self.0.push(format!("path: {}, message: {}", path.join(","), message.into()));
    }
    /// Zod's type check. Returns false (and records) on mismatch.
    fn expect(&mut self, path: &[String], v: &Value, ty: &str) -> bool {
        if type_name(v) == ty {
            return true;
        }
        let msg = if v.is_null() { "Required".to_string() } else { format!("Expected {ty}, received {}", type_name(v)) };
        self.push(path, msg);
        false
    }
}

fn at(path: &[String], key: impl ToString) -> Vec<String> {
    let mut p = path.to_vec();
    p.push(key.to_string());
    p
}

fn number_array(issues: &mut Issues, path: &[String], v: &Value) {
    if issues.expect(path, v, "array") {
        for (i, x) in v.as_array().unwrap().iter().enumerate() {
            issues.expect(&at(path, i), x, "number");
        }
    }
}

fn object_array(issues: &mut Issues, path: &[String], v: &Value) {
    if issues.expect(path, v, "array") {
        for (i, x) in v.as_array().unwrap().iter().enumerate() {
            issues.expect(&at(path, i), x, "object");
        }
    }
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

/// Validates one config node; returns false if its fields failed (zod abort).
fn node(issues: &mut Issues, path: &[String], c: &Value) -> bool {
    if !issues.expect(path, c, "object") {
        return false;
    }
    let before = issues.0.len();
    let present = |k: &str| c.get(k).is_some_and(|v| !v.is_null());
    if present("strategy") {
        let sp = at(path, "strategy");
        let s = &c["strategy"];
        if issues.expect(&sp, s, "object") {
            let mp = at(&sp, "mode");
            if issues.expect(&mp, &s["mode"], "string")
                && !["single", "loadbalance", "fallback", "conditional"].contains(&s["mode"].as_str().unwrap_or(""))
            {
                issues.push(&mp, "Invalid 'mode' value. Must be one of: single, loadbalance, fallback, conditional");
            }
            if !s["on_status_codes"].is_null() {
                number_array(issues, &at(&sp, "on_status_codes"), &s["on_status_codes"]);
            }
            if !s["conditions"].is_null() {
                let cp = at(&sp, "conditions");
                if issues.expect(&cp, &s["conditions"], "array") {
                    for (i, cond) in s["conditions"].as_array().unwrap().iter().enumerate() {
                        let ip = at(&cp, i);
                        if issues.expect(&ip, cond, "object") {
                            issues.expect(&at(&ip, "query"), &cond["query"], "object");
                            issues.expect(&at(&ip, "then"), &cond["then"], "string");
                        }
                    }
                }
            }
            if !s["sticky"].is_null() {
                let stp = at(&sp, "sticky");
                let st = &s["sticky"];
                if issues.expect(&stp, st, "object") {
                    issues.expect(&at(&stp, "enabled"), &st["enabled"], "boolean");
                    if !st["hash_fields"].is_null() {
                        let hp = at(&stp, "hash_fields");
                        if issues.expect(&hp, &st["hash_fields"], "array") {
                            for (i, f) in st["hash_fields"].as_array().unwrap().iter().enumerate() {
                                let fp = at(&hp, i);
                                if issues.expect(&fp, f, "string") {
                                    let f = f.as_str().unwrap();
                                    if !(f.starts_with("metadata.") || f.starts_with("params.") || f.starts_with("headers.")) {
                                        issues.push(&fp, r#"hash_fields must start with "metadata.", "params.", or "headers.""#);
                                    }
                                }
                            }
                        }
                    }
                    if !st["ttl"].is_null() {
                        let tp = at(&stp, "ttl");
                        if issues.expect(&tp, &st["ttl"], "number") && st["ttl"].as_f64().unwrap_or(0.0) <= 0.0 {
                            issues.push(&tp, "Number must be greater than 0");
                        }
                    }
                }
            }
        }
    }
    if present("provider") {
        let pp = at(path, "provider");
        if issues.expect(&pp, &c["provider"], "string") && !valid_provider(c["provider"].as_str().unwrap()) {
            issues.push(&pp, format!("Invalid 'provider' value. Must be one of: {}", VALID_PROVIDERS.join(", ")));
        }
    }
    if present("cache") {
        let cp = at(path, "cache");
        if issues.expect(&cp, &c["cache"], "object") {
            let mp = at(&cp, "mode");
            if issues.expect(&mp, &c["cache"]["mode"], "string") && !["simple", "semantic"].contains(&c["cache"]["mode"].as_str().unwrap()) {
                issues.push(&mp, "Invalid 'cache.mode' value. Must be one of: simple, semantic");
            }
        }
    }
    if present("retry") {
        let rp = at(path, "retry");
        if issues.expect(&rp, &c["retry"], "object") {
            issues.expect(&at(&rp, "attempts"), &c["retry"]["attempts"], "number");
            if !c["retry"]["on_status_codes"].is_null() {
                number_array(issues, &at(&rp, "on_status_codes"), &c["retry"]["on_status_codes"]);
            }
        }
    }
    if present("on_status_codes") {
        number_array(issues, &at(path, "on_status_codes"), &c["on_status_codes"]);
    }
    if present("targets") {
        let tp = at(path, "targets");
        if issues.expect(&tp, &c["targets"], "array") {
            for (i, t) in c["targets"].as_array().unwrap().iter().enumerate() {
                node(issues, &at(&tp, i), t);
            }
        }
    }
    if present("forward_headers") {
        let fp = at(path, "forward_headers");
        if issues.expect(&fp, &c["forward_headers"], "array") {
            for (i, h) in c["forward_headers"].as_array().unwrap().iter().enumerate() {
                issues.expect(&at(&fp, i), h, "string");
            }
        }
    }
    for k in ["after_request_hooks", "before_request_hooks"] {
        if present(k) {
            object_array(issues, &at(path, k), &c[k]);
        }
    }
    for k in ["input_guardrails", "output_guardrails"] {
        if present(k) {
            let gp = at(path, k);
            if issues.expect(&gp, &c[k], "array") {
                let items = c[k].as_array().unwrap();
                let all_strings = items.iter().all(Value::is_string);
                let all_objects = items.iter().all(Value::is_object);
                if !all_strings && !all_objects {
                    issues.push(&gp, "Invalid input");
                }
            }
        }
    }
    if present("vertex_service_account_json") {
        let vp = at(path, "vertex_service_account_json");
        if issues.expect(&vp, &c["vertex_service_account_json"], "object") {
            for (k, v) in c["vertex_service_account_json"].as_object().unwrap() {
                issues.expect(&at(&vp, k), v, "string");
            }
        }
    }
    if issues.0.len() > before {
        return false;
    }

    // Refinements (all run once the fields are valid).
    let provider = c["provider"].as_str();
    let ok = (present("provider") && c.get("api_key").is_some())
        || (present("strategy") && present("targets"))
        || truthy(&c["cache"])
        || truthy(&c["retry"])
        || truthy(&c["request_timeout"])
        || provider == Some("ollama")
        || provider == Some("triton")
        || (truthy(&c["aws_access_key_id"]) && truthy(&c["aws_secret_access_key"]))
        || (provider == Some("vertex-ai") && truthy(&c["vertex_region"]) && (truthy(&c["vertex_service_account_json"]) || truthy(&c["vertex_project_id"])))
        || (provider == Some("azure-openai") && (truthy(&c["api_key"]) || truthy(&c["azure_ad_token"])))
        || ["after_request_hooks", "before_request_hooks", "input_guardrails", "output_guardrails"].iter().any(|k| truthy(&c[*k]));
    if !ok {
        issues.push(path, "Invalid configuration. It must have either 'provider' and 'api_key', or 'strategy' and 'targets', or 'cache', or 'retry', or 'request_timeout'");
    }
    if let Some(h) = c["custom_host"].as_str().filter(|h| !h.is_empty()) {
        if !valid_custom_host(h) {
            issues.push(path, "Invalid custom host");
        }
    }
    let vertex_fields = (truthy(&c["vertex_project_id"]) && truthy(&c["vertex_region"]))
        || (truthy(&c["vertex_region"]) && truthy(&c["vertex_service_account_json"]));
    if provider == Some("vertex-ai") && !vertex_fields {
        issues.push(path, "Invalid configuration. ('vertex_project_id' and 'vertex_region') or ('vertex_service_account_json' and 'vertex_region') are required for 'vertex-ai' provider. Example: { 'provider': 'vertex-ai', 'vertex_project_id': 'my-project-id', 'vertex_region': 'us-central1', api_key: 'ya29...' }");
    }
    true
}

/// The `Invalid config passed` error body, or None when the config is valid.
pub fn config_errors(config: &Value) -> Option<Value> {
    let mut issues = Issues(Vec::new());
    node(&mut issues, &[], config);
    if issues.0.is_empty() {
        return None;
    }
    Some(json!({ "status": "failure", "message": "Invalid config passed", "errors": issues.0 }))
}

// ---------------------------------------------------------------- custom host

static TRUSTED_HOSTS: LazyLock<HashSet<String>> = LazyLock::new(|| match std::env::var("TRUSTED_CUSTOM_HOSTS").ok().filter(|v| !v.is_empty()) {
    Some(v) => v.split(',').map(|h| h.trim().to_lowercase()).filter(|h| !h.is_empty()).collect(),
    None => ["localhost", "127.0.0.1", "::1", "host.docker.internal"].iter().map(|s| s.to_string()).collect(),
});

const BLOCKED_HOSTS: [&str; 6] = ["0.0.0.0", "169.254.169.254", "metadata.google.internal", "metadata", "metadata.azure.com", "instance-data"];
const BLOCKED_TLDS: [&str; 11] = [".local", ".localdomain", ".internal", ".intranet", ".lan", ".home", ".corp", ".test", ".invalid", ".onion", ".localhost"];

fn ipv4_private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

fn ipv4_reserved(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 127 || (o[0] == 169 && o[1] == 254) || (o[0] == 100 && (64..=127).contains(&o[1])) || o[0] == 0 || o[0] >= 224
}

fn strict_ipv4(parts: &[&str]) -> Option<Ipv4Addr> {
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        o[i] = p.parse::<u16>().ok().filter(|n| *n <= 255)? as u8;
    }
    Some(Ipv4Addr::from(o))
}

fn alternative_ip(host: &str, parts: &[&str]) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if digits(host) && host.len() <= 10 && host.parse::<u64>().is_ok_and(|n| n <= 0xffff_ffff) {
        return true;
    }
    if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
        if (1..=8).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
    }
    (2..4).contains(&parts.len()) && parts.iter().all(|p| digits(p) && p.parse::<u64>().is_ok_and(|n| n <= 255))
}

/// TS isValidCustomHost (SSRF guard).
pub fn valid_custom_host(custom_host: &str) -> bool {
    let value = custom_host.trim().to_lowercase();
    if value.is_empty() || custom_host.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return false;
    }
    if value.contains("api.portkey") || ["file://", "data:", "gopher:", "ftp://", "ftps://"].iter().any(|s| value.starts_with(s)) {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(custom_host.trim()) else { return false };
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() || custom_host.contains('@') {
        return false;
    }
    let host = match url.host() {
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        Some(h) => h.to_string().to_lowercase(),
        None => return false,
    };
    if host.is_empty() || host.contains('%') || host.chars().any(|c| c.is_whitespace() || "<>{}|\\^`".contains(c)) {
        return false;
    }
    let is_v6 = host.contains(':');
    if !is_v6 && !host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') {
        return false;
    }
    if host.ends_with('.') || host.split('.').count() > 10 {
        return false;
    }
    let trusted = TRUSTED_HOSTS.contains(&host) || (TRUSTED_HOSTS.contains("localhost") && host.ends_with(".localhost"));
    if trusted {
        return true;
    }
    if BLOCKED_HOSTS.contains(&host.as_str()) || host.starts_with("169.254.169.") || host.starts_with("fd00:ec2::") {
        return false;
    }
    if BLOCKED_TLDS.iter().any(|t| host.ends_with(t) && host != "localhost") {
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if let Some(ip) = strict_ipv4(&parts) {
        if ipv4_private(ip) || ipv4_reserved(ip) {
            return false;
        }
    } else if !is_v6 && alternative_ip(&host, &parts) {
        return false;
    }
    if is_v6 {
        if host == "::1" || host == "::" || host.starts_with("fc") || host.starts_with("fd") || host.starts_with("fe80") || host.starts_with("fec0") {
            return false;
        }
        if let Some(v4) = host.rsplit("::ffff:").next().filter(|_| host.contains("::ffff:")).or_else(|| host.rsplit("::").next()) {
            if let Some(ip) = strict_ipv4(&v4.split('.').collect::<Vec<_>>()) {
                if ipv4_private(ip) || ipv4_reserved(ip) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_schema_matches_ts() {
        assert!(config_errors(&json!({"provider":"openai","api_key":"x"})).is_none());
        let e = config_errors(&json!({"strategy":{"mode":"fallback"},"targets":[{"provider":"nope","api_key":"x"}]})).unwrap();
        assert!(e["errors"][0].as_str().unwrap().starts_with("path: targets,0,provider, message: Invalid 'provider' value."));
        let e = config_errors(&json!({"provider":"openai"})).unwrap();
        assert_eq!(e["errors"][0], "path: , message: Invalid configuration. It must have either 'provider' and 'api_key', or 'strategy' and 'targets', or 'cache', or 'retry', or 'request_timeout'");
        let e = config_errors(&json!({"retry":{"attempts":"3"}})).unwrap();
        assert_eq!(e["errors"][0], "path: retry,attempts, message: Expected number, received string");
    }

    #[test]
    fn custom_hosts() {
        assert!(valid_custom_host("https://api.example.com/v1"));
        assert!(valid_custom_host("http://127.0.0.1:9300/x"));
        assert!(!valid_custom_host("http://10.0.0.5/v1"));
        assert!(!valid_custom_host("http://169.254.169.254/latest"));
        // WHATWG parsing normalizes numeric hosts (as in JS): 0x0a000001 -> 10.0.0.1.
        assert!(!valid_custom_host("http://0x0a000001/"));
        assert!(!valid_custom_host("http://foo.internal/"));
        assert!(!valid_custom_host("file:///etc/passwd"));
    }
}
