//! Google Cloud auth for Vertex AI: service-account JSON -> signed JWT ->
//! OAuth access token (cached), or a caller-supplied token, or the metadata
//! server (workload identity).

use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const TOKEN_TTL: Duration = Duration::from_secs(50 * 60);

static TOKENS: LazyLock<Mutex<HashMap<String, (Instant, String)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// RS256-signed JWT assertion for the token endpoint.
pub fn jwt_assertion(sa: &Value, now: i64) -> Result<String, String> {
    let email = sa["client_email"].as_str().ok_or("service account missing client_email")?;
    let key_pem = sa["private_key"].as_str().ok_or("service account missing private_key")?;
    let token_uri = sa["token_uri"].as_str().unwrap_or("https://oauth2.googleapis.com/token");
    let header = b64(json!({ "alg": "RS256", "typ": "JWT", "kid": sa["private_key_id"] }).to_string().as_bytes());
    let claims = b64(
        json!({ "iss": email, "scope": SCOPE, "aud": token_uri, "iat": now, "exp": now + 3600 })
            .to_string()
            .as_bytes(),
    );
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem).map_err(|e| format!("bad service account key: {e}"))?;
    let signing_input = format!("{header}.{claims}");
    let signature = SigningKey::<Sha256>::new(key).sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64(&signature.to_bytes())))
}

async fn service_account_token(http: &reqwest::Client, sa: &Value) -> Result<String, String> {
    let cache_key = format!("sa:{}", sa["client_email"].as_str().unwrap_or(""));
    if let Some((at, t)) = TOKENS.lock().unwrap().get(&cache_key) {
        if at.elapsed() < TOKEN_TTL {
            return Ok(t.clone());
        }
    }
    let assertion = jwt_assertion(sa, chrono::Utc::now().timestamp())?;
    let token_uri = sa["token_uri"].as_str().unwrap_or("https://oauth2.googleapis.com/token");
    let resp: Value = http
        .post(token_uri)
        .form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let token = resp["access_token"].as_str().ok_or_else(|| format!("token exchange failed: {resp}"))?.to_string();
    TOKENS.lock().unwrap().insert(cache_key, (Instant::now(), token.clone()));
    Ok(token)
}

async fn metadata_token(http: &reqwest::Client) -> Result<String, String> {
    if let Some((at, t)) = TOKENS.lock().unwrap().get("metadata") {
        if at.elapsed() < TOKEN_TTL {
            return Ok(t.clone());
        }
    }
    let resp: Value = http
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let token = resp["access_token"].as_str().ok_or("no token from metadata server")?.to_string();
    TOKENS.lock().unwrap().insert("metadata".into(), (Instant::now(), token.clone()));
    Ok(token)
}

/// Bearer token for a Vertex AI target.
pub async fn vertex_token(http: &reqwest::Client, options: &Map<String, Value>) -> Result<String, String> {
    if let Some(sa) = options.get("vertexServiceAccountJson").filter(|v| v.is_object()) {
        return service_account_token(http, sa).await;
    }
    if let Some(key) = options.get("apiKey").and_then(Value::as_str).filter(|k| !k.is_empty()) {
        return Ok(key.to_string());
    }
    metadata_token(http).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_verifiable_jwt() {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let jwt = jwt_assertion(&json!({"client_email":"sa@p.iam.gserviceaccount.com","private_key":pem}), 1_700_000_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "sa@p.iam.gserviceaccount.com");
        assert_eq!(claims["exp"], 1_700_003_600);
    }
}
