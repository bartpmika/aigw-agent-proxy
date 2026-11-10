//! Config-engine state and rules, ported from the TS gateway:
//! conditional router (`conditionalRouter.ts`), sticky load balancing
//! (`stickySessionManager.ts`), circuit breaker (`utils/circuitBreaker.ts`)
//! and the simple response cache (`kreacher`). State is in memory, as in the
//! TS gateway without Redis.

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ---------------------------------------------------------------- conditional

fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// JS parseFloat: leading numeric prefix, else NaN.
fn parse_float(v: &Value) -> f64 {
    if let Some(n) = v.as_f64() {
        return n;
    }
    let s = js_string(v);
    let s = s.trim_start();
    let end = s
        .char_indices()
        .take_while(|(i, c)| c.is_ascii_digit() || *c == '.' || ((*c == '-' || *c == '+') && *i == 0) || *c == 'e' || *c == 'E')
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    (0..=end).rev().find_map(|e| s[..e].parse::<f64>().ok()).unwrap_or(f64::NAN)
}

fn context_value<'a>(context: &'a Value, key: &str) -> &'a Value {
    let mut parts = key.split('.');
    let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    &context[a][b]
}

fn evaluate_operator(ops: &Map<String, Value>, value: &Value) -> Result<bool, String> {
    for (op, cmp) in ops {
        match op.as_str() {
            "$eq" if value != cmp => return Ok(false),
            "$ne" if value == cmp => return Ok(false),
            "$gt" if !(parse_float(value) > parse_float(cmp)) => return Ok(false),
            "$gte" if !(parse_float(value) >= parse_float(cmp)) => return Ok(false),
            "$lt" if !(parse_float(value) < parse_float(cmp)) => return Ok(false),
            "$lte" if !(parse_float(value) <= parse_float(cmp)) => return Ok(false),
            "$in" if !cmp.as_array().is_some_and(|a| a.contains(value)) => return Ok(false),
            "$nin" if !cmp.as_array().is_some_and(|a| !a.contains(value)) => return Ok(false),
            // TS returns the regex result directly, ignoring later operators.
            "$regex" => return Ok(Regex::new(&js_string(cmp)).map(|re| re.is_match(&js_string(value))).unwrap_or(false)),
            "$eq" | "$ne" | "$gt" | "$gte" | "$lt" | "$lte" | "$in" | "$nin" => {}
            other => return Err(format!("Unsupported operator used in the query router: {other}")),
        }
    }
    Ok(true)
}

fn evaluate_query(query: &Value, context: &Value) -> Result<bool, String> {
    for (key, value) in query.as_object().into_iter().flatten() {
        if key == "$or" {
            if let Some(subs) = value.as_array() {
                for s in subs {
                    if evaluate_query(s, context)? {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
        }
        if key == "$and" {
            if let Some(subs) = value.as_array() {
                for s in subs {
                    if !evaluate_query(s, context)? {
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
        }
        let actual = context_value(context, key);
        match value {
            Value::Object(ops) => {
                if !evaluate_operator(ops, actual)? {
                    return Ok(false);
                }
            }
            v if actual != v => return Ok(false),
            _ => {}
        }
    }
    Ok(true)
}

/// TS ConditionalRouter.resolveTarget: the index of the chosen target.
/// `context` is `{metadata, params, url: {pathname}}`.
pub fn resolve_conditional(node: &Value, context: &Value) -> Result<usize, String> {
    let strategy = &node["strategy"];
    let Some(conditions) = strategy["conditions"].as_array() else {
        return Err("No conditions passed in the query router".into());
    };
    let find = |name: &Value| -> Result<usize, String> {
        node["targets"]
            .as_array()
            .and_then(|t| t.iter().position(|t| &t["name"] == name))
            .ok_or_else(|| format!("Invalid target name found in the query router: {}", js_string(name)))
    };
    for c in conditions {
        if evaluate_query(&c["query"], context)? {
            return find(&c["then"]);
        }
    }
    if !strategy["default"].is_null() {
        return find(&strategy["default"]);
    }
    Err("Query router did not resolve to any valid target".into())
}

// ---------------------------------------------------------------- TTL store

struct TtlMap<V> {
    entries: HashMap<String, (Instant, Duration, V)>,
}

impl<V: Clone> TtlMap<V> {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }
    fn get(&mut self, key: &str) -> Option<V> {
        match self.entries.get(key) {
            Some((at, ttl, v)) if at.elapsed() < *ttl => Some(v.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }
    fn set(&mut self, key: String, value: V, ttl: Duration) {
        if self.entries.len() > 50_000 {
            self.entries.retain(|_, (at, ttl, _)| at.elapsed() < *ttl);
        }
        self.entries.insert(key, (Instant::now(), ttl, value));
    }
    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

// ---------------------------------------------------------------- sticky

static STICKY: LazyLock<Mutex<TtlMap<usize>>> = LazyLock::new(|| Mutex::new(TtlMap::new()));

fn nested<'a>(v: &'a Value, path: &str) -> &'a Value {
    path.split('.').fold(v, |cur, k| &cur[k])
}

/// TS StickySessionManager identifier: the Portkey key plus `hash_fields`
/// values (`params.x`, `metadata.x`, `headers.x`). Returns its hash.
pub fn sticky_hash(api_key: Option<&str>, hash_fields: &[String], params: &Value, metadata: &Value, headers: &Map<String, Value>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(k) = api_key.filter(|k| !k.is_empty()) {
        parts.push(k.to_string());
    }
    for field in hash_fields {
        let Some((prefix, path)) = field.split_once('.') else { continue };
        let value = match prefix {
            "params" => nested(params, path),
            "metadata" => nested(metadata, path),
            "headers" => headers.get(&path.to_lowercase()).unwrap_or(&Value::Null),
            _ => &Value::Null,
        };
        if !value.is_null() {
            let s = js_string(value);
            if !s.is_empty() {
                parts.push(format!("{field}:{s}"));
            }
        }
    }
    let identifier = parts.join("|");
    (!identifier.is_empty()).then(|| sha256_hex(&identifier))
}

pub fn sticky_get(config_version: &str, hash: &str) -> Option<usize> {
    STICKY.lock().unwrap().get(&format!("sticky:loadbalance:{config_version}:{hash}"))
}

pub fn sticky_set(config_version: &str, hash: &str, index: usize, ttl_secs: u64) {
    STICKY.lock().unwrap().set(format!("sticky:loadbalance:{config_version}:{hash}"), index, Duration::from_secs(ttl_secs));
}

// ---------------------------------------------------------------- circuit breaker

#[derive(Default, Clone)]
struct PathStats {
    failures: u64,
    successes: u64,
    first_failure_ms: Option<u64>,
}

static BREAKERS: LazyLock<Mutex<HashMap<String, HashMap<String, PathStats>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// TS generateCircuitBreakerConfigId.
pub fn breaker_config_id(slug: &str, workspace_id: &str, org_id: &str) -> String {
    format!("{org_id}:{workspace_id}:{slug}")
}

fn cb_config_of(node: &Value) -> Option<Value> {
    let c = &node["strategy"]["cb_config"];
    let has_threshold = c["failure_threshold"].as_f64().is_some_and(|v| v != 0.0) || c["failure_threshold_percentage"].as_f64().is_some_and(|v| v != 0.0);
    if !has_threshold || !c["cooldown_interval"].as_f64().is_some_and(|v| v != 0.0) {
        return None;
    }
    let mut out = json!({
        "failure_threshold": c["failure_threshold"],
        "cooldown_interval": c["cooldown_interval"].as_f64().unwrap_or(0.0).max(30000.0) as u64,
    });
    for k in ["failure_threshold_percentage", "minimum_requests", "failure_status_codes"] {
        if !c[k].is_null() {
            out[k] = c[k].clone();
        }
    }
    Some(out)
}

/// TS extractCircuitBreakerConfigs: target path -> breaker config, for
/// virtual-key targets under a node with `strategy.cb_config`.
fn extract(node: &Value, path: &str, inherited: Option<Value>, out: &mut HashMap<String, Value>) {
    let mut current = cb_config_of(node).or(inherited);
    if node["virtual_key"].is_string() {
        if let Some(c) = &current {
            out.insert(path.to_string(), c.clone());
        }
    }
    if node["strategy"]["mode"] == "conditional" {
        current = None;
    }
    for (i, t) in node["targets"].as_array().into_iter().flatten().enumerate() {
        extract(t, &format!("{path}.targets[{i}]"), current.clone(), out);
    }
}

/// Marks targets `is_open`/`cb_config` from the breaker state, as the TS
/// middleware does before routing. Returns true when any breaker applies
/// (the config then gets `id` so the router skips open targets).
pub fn apply_breakers(config: &mut Value, config_id: &str) -> bool {
    let mut configs = HashMap::new();
    extract(config, "config", None, &mut configs);
    if configs.is_empty() {
        return false;
    }
    let now = now_ms();
    let mut open: HashMap<String, bool> = HashMap::new();
    {
        let mut all = BREAKERS.lock().unwrap();
        let stats = all.entry(config_id.to_string()).or_default();
        for (path, cfg) in &configs {
            let s = stats.get(path).cloned().unwrap_or_default();
            let min = cfg["minimum_requests"].as_u64().filter(|m| *m > 0).unwrap_or(5);
            let pct = if (s.failures > 0 || s.successes > 0) && s.failures + s.successes >= min {
                100.0 * s.failures as f64 / (s.failures + s.successes) as f64
            } else {
                0.0
            };
            let cooldown = cfg["cooldown_interval"].as_u64().unwrap_or(30000);
            let is_open = if s.first_failure_ms.is_some_and(|f| now.saturating_sub(f) > cooldown) {
                stats.remove(path);
                false
            } else {
                cfg["failure_threshold"].as_u64().is_some_and(|t| t > 0 && s.failures >= t)
                    || cfg["failure_threshold_percentage"].as_f64().is_some_and(|t| t > 0.0 && pct >= t)
            };
            open.insert(path.clone(), is_open);
        }
    }
    fn mark(node: &mut Value, path: &str, open: &HashMap<String, bool>, configs: &HashMap<String, Value>) -> bool {
        let mut all_open = true;
        let mut has_targets = false;
        if let Some(targets) = node.get_mut("targets").and_then(Value::as_array_mut) {
            has_targets = true;
            for (i, t) in targets.iter_mut().enumerate() {
                let tp = format!("{path}.targets[{i}]");
                let child_open = mark(t, &tp, open, configs);
                if let Some(o) = open.get(&tp) {
                    t["is_open"] = json!(*o || child_open);
                    t["cb_config"] = configs[&tp].clone();
                }
                if t["is_open"] != true {
                    all_open = false;
                }
            }
        }
        if let Some(o) = open.get(path) {
            node["is_open"] = json!(*o || (has_targets && all_open));
            node["cb_config"] = configs[path].clone();
            return node["is_open"] == true;
        }
        has_targets && all_open
    }
    mark(config, "config", &open, &configs);
    config["id"] = json!(config_id);
    true
}

/// TS handleCircuitBreakerResponse for one target response.
pub fn record_breaker(config_id: &str, path: &str, cb_config: &Value, status: u16) {
    if cb_config.is_null() {
        return;
    }
    let mut all = BREAKERS.lock().unwrap();
    let s = all.entry(config_id.to_string()).or_default().entry(path.to_string()).or_default();
    if (200..300).contains(&status) {
        s.successes += 1;
        return;
    }
    let failure = match cb_config["failure_status_codes"].as_array() {
        Some(codes) => codes.iter().any(|c| c.as_u64() == Some(status as u64)),
        None => status >= 500,
    };
    if failure {
        s.failures += 1;
        s.first_failure_ms.get_or_insert(now_ms());
    }
}

// ---------------------------------------------------------------- response cache

const DEFAULT_CACHE_AGE: u64 = 604_800;
const MIN_CACHE_AGE: u64 = 60;
const MAX_CACHE_AGE: u64 = 7_776_000;

static CACHE: LazyLock<Mutex<TtlMap<bytes::Bytes>>> = LazyLock::new(|| Mutex::new(TtlMap::new()));

/// Cache mode and max age from a target's `cache` (`{mode, max_age}` or a
/// mode string). `None` when caching is off.
pub fn cache_options(cache: &Value) -> Option<(String, Option<u64>)> {
    match cache {
        Value::String(m) if !m.is_empty() => Some((m.clone(), None)),
        Value::Object(o) => {
            let mode = o.get("mode").and_then(Value::as_str).filter(|m| !m.is_empty())?;
            let age = o.get("max_age").or(o.get("maxAge")).and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));
            Some((mode.to_string(), age))
        }
        _ => None,
    }
}

/// TS getCacheKey: `OUTPUT_` + sha256(org + url + body + cache headers).
pub fn cache_key(org_id: &str, url: &str, body: &Value, metadata_header: Option<&str>, namespace: Option<&str>) -> String {
    let headers = match namespace {
        Some(ns) => json!(ns),
        None => {
            let mut h = Map::new();
            if let Some(m) = metadata_header {
                h.insert("x-portkey-metadata".into(), json!(m));
            }
            Value::Object(h)
        }
    };
    format!("OUTPUT_{}", sha256_hex(&format!("{org_id}{url}{body}{headers}")))
}

pub fn cache_ttl(max_age: Option<u64>) -> Duration {
    let age = max_age.filter(|a| *a > 0).unwrap_or(DEFAULT_CACHE_AGE);
    let age = if (MIN_CACHE_AGE..=MAX_CACHE_AGE).contains(&age) { age } else { DEFAULT_CACHE_AGE };
    Duration::from_secs(age)
}

pub fn cache_get(key: &str) -> Option<bytes::Bytes> {
    CACHE.lock().unwrap().get(key)
}

pub fn cache_put(key: &str, body: bytes::Bytes, ttl: Duration) {
    CACHE.lock().unwrap().set(key.to_string(), body, ttl);
}

pub fn cache_delete(key: &str) {
    CACHE.lock().unwrap().remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_router_matches_ts() {
        let node = json!({"strategy":{"mode":"conditional","conditions":[
            {"query":{"metadata.tier":{"$eq":"pro"}},"then":"big"},
            {"query":{"$or":[{"params.model":{"$regex":"^gpt"}},{"metadata.n":{"$gt":"5"}}]},"then":"small"}],
            "default":"small"},
            "targets":[{"name":"big"},{"name":"small"}]});
        let ctx = |md: Value, params: Value| json!({"metadata": md, "params": params, "url": {"pathname": "/v1/chat/completions"}});
        assert_eq!(resolve_conditional(&node, &ctx(json!({"tier":"pro"}), json!({}))), Ok(0));
        assert_eq!(resolve_conditional(&node, &ctx(json!({"n":"7"}), json!({}))), Ok(1));
        assert_eq!(resolve_conditional(&node, &ctx(json!({}), json!({"model":"gpt-4o"}))), Ok(1));
        let bad = json!({"strategy":{"mode":"conditional","conditions":[{"query":{"metadata.a":{"$foo":1}},"then":"x"}]},"targets":[]});
        assert!(resolve_conditional(&bad, &ctx(json!({"a":1}), json!({}))).unwrap_err().contains("Unsupported operator"));
    }

    #[test]
    fn breaker_opens_after_threshold() {
        let mut cfg = json!({"strategy":{"mode":"fallback","cb_config":{"failure_threshold":2,"cooldown_interval":60000}},
            "targets":[{"virtual_key":"a"},{"virtual_key":"b"}]});
        let id = "org:ws:pc-cb-test";
        assert!(apply_breakers(&mut cfg.clone(), id));
        for _ in 0..2 {
            record_breaker(id, "config.targets[0]", &json!({"failure_threshold":2}), 503);
        }
        apply_breakers(&mut cfg, id);
        assert_eq!(cfg["targets"][0]["is_open"], true);
        assert_eq!(cfg["targets"][1]["is_open"], false);
        assert_eq!(cfg["id"], id);
    }

    #[test]
    fn cache_key_and_ttl() {
        let k = cache_key("org", "https://x/v1/chat", &json!({"a":1}), Some("{\"u\":1}"), None);
        assert!(k.starts_with("OUTPUT_") && k.len() == 71);
        assert_eq!(cache_ttl(Some(10)), Duration::from_secs(DEFAULT_CACHE_AGE));
        assert_eq!(cache_ttl(Some(120)), Duration::from_secs(120));
        assert_eq!(cache_options(&json!({"mode":"simple","max_age":300})), Some(("simple".into(), Some(300))));
    }
}
