//! Provider engine for the unified gateway API.
//!
//! Provider definitions (param maps, base URLs, endpoints, headers) are data
//! extracted from the TypeScript gateway (`tools/extract-providers.mts` ->
//! `data/providers.json`). Code that can't be data (param transforms,
//! response transforms, auth signing) is ported by hand in `transforms`,
//! `responses` and the provider modules.

pub mod aws;
pub mod gcp;
pub mod responses;
pub mod transforms;

use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

static DATA: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(include_str!("../../data/providers.json")).expect("providers.json"));

/// Transforms referenced by provider data that aren't ported yet (for the
/// parity harness / logs).
pub static MISSING_TRANSFORMS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn provider_names() -> Vec<String> {
    DATA.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default()
}

pub fn exists(provider: &str) -> bool {
    DATA.get(provider).is_some()
}

/// Model family for providers whose config depends on the model.
pub fn family(provider: &str, model: &str) -> Option<String> {
    match provider {
        "bedrock" => {
            let m = strip_bedrock_region(model);
            Some(m.split('.').next().unwrap_or("").to_string())
        }
        "vertex-ai" => {
            let first = model.split('.').next().unwrap_or("");
            let has_dot = model.contains('.');
            Some(if has_dot && ["google", "anthropic", "meta", "endpoints", "mistralai"].contains(&first) {
                first.to_string()
            } else {
                "google".to_string()
            })
        }
        _ => None,
    }
}

pub fn strip_bedrock_region(model: &str) -> &str {
    for prefix in ["us.", "eu.", "apac.", "au.", "ca.", "jp.", "global."] {
        if let Some(rest) = model.strip_prefix(prefix) {
            return rest;
        }
    }
    model
}

/// The family config for a model: the sample whose family matches, else
/// Bedrock's default branch (models outside the named families).
fn family_config(provider: &str, model: &str) -> Option<(&'static Value, String)> {
    let fam = family(provider, model)?;
    let families = DATA.get(provider)?["families"].as_object()?;
    let label = |sample: &str| format!("{provider}[{}]", sample.split(['.', '@', '-']).next().unwrap_or(""));
    if let Some((sample, cfg)) = families.iter().find(|(s, _)| family(provider, s).as_deref() == Some(fam.as_str())) {
        return Some((cfg, label(sample)));
    }
    if provider == "bedrock" {
        return families.iter().find(|(s, _)| s.starts_with("deepseek")).map(|(s, c)| (c, label(s)));
    }
    None
}

/// Data for a provider (or its model family) and one function.
fn function_config(provider: &str, fn_name: &str, model: &str) -> Option<(&'static Value, String)> {
    if let Some((cfg, label)) = family_config(provider, model) {
        if let Some(f) = cfg["functions"].get(fn_name) {
            return Some((f, label));
        }
    }
    DATA.get(provider)?["functions"].get(fn_name).map(|f| (f, provider.to_string()))
}

pub fn supports(provider: &str, fn_name: &str, model: &str) -> bool {
    function_config(provider, fn_name, model).is_some()
}

fn set_nested(obj: &mut Map<String, Value>, path: &str, value: Value) {
    let mut parts = path.split('.').peekable();
    let mut current = obj;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            current.insert(part.to_string(), value);
            return;
        }
        let entry = current.entry(part.to_string()).or_insert_with(|| json!({}));
        if !entry.is_object() {
            *entry = json!({});
        }
        current = entry.as_object_mut().unwrap();
    }
}

/// Applies a provider's param map to a request (TS transformUsingProviderConfig).
pub fn transform_request(provider: &str, fn_name: &str, params: &Value, options: &Map<String, Value>) -> Result<Value, String> {
    let model = params["model"].as_str().unwrap_or("");
    let Some((config, key_prefix)) = function_config(provider, fn_name, model) else {
        return Err(format!("{fn_name} is not supported by {provider}"));
    };
    let mut out = Map::new();
    let Some(config) = config.as_object() else { return Ok(Value::Object(out)) };
    let input = params.as_object().cloned().unwrap_or_default();
    for (config_param, specs) in config {
        for spec in specs.as_array().into_iter().flatten() {
            let Some(target) = spec["param"].as_str() else { continue };
            if input.contains_key(config_param) {
                let transform = spec["transform"].as_str().and_then(|t| t.strip_prefix("__fn__:"));
                let mut value = if let Some(fp) = transform {
                    match transforms::apply(fp, params, options) {
                        Some(v) => v,
                        None => {
                            MISSING_TRANSFORMS.lock().unwrap().insert(format!("{key_prefix}.{fn_name}.{config_param} {fp}"));
                            input[config_param].clone()
                        }
                    }
                } else {
                    input[config_param].clone()
                };
                if value == "portkey-default" && !spec["default"].is_null() {
                    value = spec["default"].clone();
                }
                if let Some(n) = value.as_f64() {
                    if let Some(min) = spec["min"].as_f64().filter(|m| n < *m) {
                        value = json!(min);
                    } else if let Some(max) = spec["max"].as_f64().filter(|m| n > *m) {
                        value = json!(max);
                    }
                }
                // Transforms can return undefined (omit) in TS.
                if !(value.is_null() && transform.is_some()) {
                    set_nested(&mut out, target, value);
                }
            } else if spec["required"] == true && !spec["default"].is_null() {
                let value = if let Some(fp) = spec["default"].as_str().and_then(|d| d.strip_prefix("__fn__:")) {
                    match transforms::apply(fp, params, options) {
                        Some(v) => v,
                        None => {
                            MISSING_TRANSFORMS.lock().unwrap().insert(format!("{key_prefix}.{fn_name}.{config_param} default {fp}"));
                            continue;
                        }
                    }
                } else {
                    spec["default"].clone()
                };
                // A function default returning undefined adds nothing in TS.
                if !value.is_null() {
                    set_nested(&mut out, target, value);
                }
            }
        }
    }
    Ok(Value::Object(out))
}

/// Renders `${name}` placeholders from provider options and the body.
/// Returns None when a placeholder has no value.
pub fn render(template: &str, options: &Map<String, Value>, body: &Value) -> Option<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find('}')? + start;
        let name = &rest[start + 2..end];
        let value = if let Some(field) = name.strip_prefix("body.") { body.get(field) } else { options.get(name) };
        let text = match value {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            _ => return None,
        };
        out.push_str(&text);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Base URL + endpoint and headers for a provider function, from the
/// extracted templates. Headers whose placeholders have no value are left out.
pub fn api_templates(provider: &str, fn_name: &str, stream: bool) -> Option<&'static Value> {
    let api = &DATA.get(provider)?["api"];
    let key = if stream { format!("{fn_name}:stream") } else { fn_name.to_string() };
    api.get(&key).or_else(|| api.get(fn_name)).filter(|v| !v.is_null())
}

pub fn render_headers(provider: &str, fn_name: &str, stream: bool, options: &Map<String, Value>, body: &Value) -> Vec<(String, String)> {
    let Some(t) = api_templates(provider, fn_name, stream) else { return Vec::new() };
    let defaults = t["headerDefaults"].as_object();
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in t["headers"].as_object().into_iter().flatten() {
        // A template that can't render falls back to the provider's default
        // for that header (captured with empty options), else is omitted.
        let value = v
            .as_str()
            .and_then(|v| render(v, options, body))
            .or_else(|| defaults.and_then(|d| d.get(k)).and_then(Value::as_str).map(str::to_string));
        if let Some(v) = value {
            out.push((k.to_lowercase(), v));
        }
    }
    for (k, v) in defaults.into_iter().flatten() {
        if !out.iter().any(|(n, _)| n.eq_ignore_ascii_case(k)) {
            if let Some(v) = v.as_str() {
                out.push((k.to_lowercase(), v.to_string()));
            }
        }
    }
    out
}

/// Fingerprint of a provider's response transform (shared implementations
/// share fingerprints).
pub fn response_transform_id(provider: &str, fn_name: &str, model: &str) -> Option<String> {
    if let Some((cfg, _)) = family_config(provider, model) {
        if let Some(id) = cfg["responseTransforms"][fn_name].as_str() {
            return Some(id.to_string());
        }
    }
    DATA.get(provider)?["responseTransforms"][fn_name].as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_all_providers_and_maps_params() {
        assert!(provider_names().len() >= 76);
        let out = transform_request("groq", "chatComplete", &json!({"model":"m","messages":[],"temperature":0.2,"extra":1}), &Map::new()).unwrap();
        assert_eq!(out["model"], "m");
        assert_eq!(out["temperature"], 0.2);
        assert!(out.get("extra").is_none());
    }

    #[test]
    fn renders_templates() {
        let mut o = Map::new();
        o.insert("resourceName".into(), json!("acme"));
        assert_eq!(render("https://${resourceName}.openai.azure.com", &o, &json!({})).as_deref(), Some("https://acme.openai.azure.com"));
        assert_eq!(render("Bearer ${apiKey}", &o, &json!({})), None);
        assert_eq!(render("/model/${body.model}/converse", &o, &json!({"model":"m"})).as_deref(), Some("/model/m/converse"));
    }

    #[test]
    fn resolves_families() {
        assert_eq!(family("bedrock", "us.anthropic.claude-3").as_deref(), Some("anthropic"));
        assert_eq!(family("vertex-ai", "gemini-1.5-pro").as_deref(), Some("google"));
        assert_eq!(family("vertex-ai", "anthropic.claude-3-5-sonnet@20240620").as_deref(), Some("anthropic"));
        assert!(supports("bedrock", "chatComplete", "meta.llama3-1-70b-instruct-v1:0"));
    }
}
