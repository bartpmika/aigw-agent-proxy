//! AWS SigV4 request signing (Bedrock, SageMaker, STS) and credential modes:
//! static keys, assumed role (STS AssumeRole), service role (environment),
//! and Bedrock API keys (bearer).

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// RFC 3986 escaping as used by SigV4 (unreserved characters kept).
fn uri_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Signs a request; returns the headers to send (including the input ones).
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    service: &str,
    region: &str,
    creds: &Credentials,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<(String, String)> {
    let parsed = reqwest::Url::parse(url).expect("valid url");
    let host = parsed.host_str().unwrap_or("").to_string()
        + &parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let region = if region.is_empty() { "us-east-1" } else { region };

    let mut all: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_lowercase(), v.trim().to_string())).collect();
    all.retain(|(k, _)| k != "host" && k != "x-amz-date" && k != "x-amz-security-token");
    all.push(("host".into(), host));
    all.push(("x-amz-date".into(), amz_date.clone()));
    if let Some(t) = &creds.session_token {
        all.push(("x-amz-security-token".into(), t.clone()));
    }
    all.sort_by(|a, b| a.0.cmp(&b.0));

    // Non-S3 services escape each (already encoded) path segment again.
    let canonical_uri = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().split('/').map(uri_escape).collect::<Vec<_>>().join("/")
    };
    let mut query: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (uri_escape(&k), uri_escape(&v)))
        .collect();
    query.sort();
    let canonical_query = query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let canonical_headers: String = all.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = all.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let payload_hash = sha256_hex(body);
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical_request.as_bytes()));
    let k_date = hmac(format!("AWS4{}", creds.secret_access_key).as_bytes(), &date);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    let k_signing = hmac(&k_service, "aws4_request");
    let signature = hex::encode(hmac(&k_signing, &string_to_sign));
    all.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key_id
        ),
    ));
    all
}

static ASSUMED: LazyLock<Mutex<HashMap<String, (Instant, Credentials)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
const ASSUMED_TTL: Duration = Duration::from_secs(300);

fn env_credentials() -> Option<Credentials> {
    Some(Credentials {
        access_key_id: std::env::var("AWS_ACCESS_KEY_ID").ok()?,
        secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").ok()?,
        session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
    })
}

fn xml_field(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].to_string())
}

/// STS AssumeRole, signed with the gateway's own (environment) credentials.
async fn assume_role(http: &reqwest::Client, role_arn: &str, external_id: &str, region: &str) -> Result<Credentials, String> {
    let key = format!("{role_arn}|{external_id}|{region}");
    if let Some((at, c)) = ASSUMED.lock().unwrap().get(&key) {
        if at.elapsed() < ASSUMED_TTL {
            return Ok(c.clone());
        }
    }
    let base = env_credentials().ok_or("no AWS credentials in the environment to assume the role with")?;
    let region = if region.is_empty() { "us-east-1" } else { region };
    let mut url = format!(
        "https://sts.{region}.amazonaws.com/?Action=AssumeRole&Version=2011-06-15&RoleArn={}&RoleSessionName=portkey-gateway",
        uri_escape(role_arn)
    );
    if !external_id.is_empty() {
        url.push_str(&format!("&ExternalId={}", uri_escape(external_id)));
    }
    let headers = sign("GET", &url, &[], b"", "sts", region, &base, chrono::Utc::now());
    let mut req = http.get(&url);
    for (k, v) in &headers {
        if k != "host" {
            req = req.header(k, v);
        }
    }
    let xml = req.send().await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?;
    let creds = Credentials {
        access_key_id: xml_field(&xml, "AccessKeyId").ok_or_else(|| format!("AssumeRole failed: {}", &xml[..xml.len().min(200)]))?,
        secret_access_key: xml_field(&xml, "SecretAccessKey").unwrap_or_default(),
        session_token: xml_field(&xml, "SessionToken"),
    };
    ASSUMED.lock().unwrap().insert(key, (Instant::now(), creds.clone()));
    Ok(creds)
}

fn opt<'a>(options: &'a Map<String, Value>, key: &str) -> &'a str {
    options.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Final headers for an AWS request per the target's auth mode.
pub async fn auth_headers(
    http: &reqwest::Client,
    options: &Map<String, Value>,
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    body: &[u8],
    service: &str,
) -> Result<Vec<(String, String)>, String> {
    let region = opt(options, "awsRegion");
    match opt(options, "awsAuthType") {
        "apiKey" => {
            let mut h = headers;
            h.push(("authorization".into(), format!("Bearer {}", opt(options, "apiKey"))));
            Ok(h)
        }
        mode => {
            let creds = match mode {
                "assumedRole" => assume_role(http, opt(options, "awsRoleArn"), opt(options, "awsExternalId"), region).await?,
                "serviceRole" => env_credentials().ok_or("no AWS credentials in the environment")?,
                _ => Credentials {
                    access_key_id: opt(options, "awsAccessKeyId").to_string(),
                    secret_access_key: opt(options, "awsSecretAccessKey").to_string(),
                    session_token: options.get("awsSessionToken").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string),
                },
            };
            Ok(sign(method, url, &headers, body, service, region, &creds, chrono::Utc::now()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// AWS's published SigV4 example (IAM ListUsers, us-east-1, 20150830).
    #[test]
    fn matches_aws_reference_signature() {
        let creds = Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let now = chrono::Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
        let headers = sign(
            "GET",
            "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
            &[("content-type".into(), "application/x-www-form-urlencoded; charset=utf-8".into())],
            b"",
            "iam",
            "us-east-1",
            &creds,
            now,
        );
        let auth = headers.iter().find(|(k, _)| k == "authorization").unwrap().1.clone();
        assert!(auth.ends_with("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"), "{auth}");
    }
}
