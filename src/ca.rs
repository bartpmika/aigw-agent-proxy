//! Local certificate authority for TLS interception. Shares its files with
//! the TypeScript gateway (RSA CA, PKCS#1 PEM), so either can create them.

use anyhow::Context;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::EncodePrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use time_shim::{days_from_now, years_from_now};

const CA_CERT_FILE: &str = "ca.cert.pem";
const CA_KEY_FILE: &str = "ca.key.pem";
const CA_BUNDLE_FILE: &str = "ca-bundle.pem";
const CA_COMMON_NAME: &str = "Portkey Forward Proxy Local CA";

pub struct LocalCa {
    pub cert_path: PathBuf,
    pub bundle_path: PathBuf,
    pub cert_pem: String,
    issuer: rcgen::Certificate,
    issuer_key: KeyPair,
    leaf_key: KeyPair,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn rsa_pkcs1_to_keypair(pem: &str) -> anyhow::Result<KeyPair> {
    let key = rsa::RsaPrivateKey::from_pkcs1_pem(pem).context("parse CA key (PKCS#1)")?;
    let pkcs8 = key.to_pkcs8_der()?;
    let der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    Ok(KeyPair::from_pkcs8_der_and_sign_algo(&der, &PKCS_RSA_SHA256)?)
}

impl LocalCa {
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        if !(cert_path.exists() && key_path.exists()) {
            create_ca(dir)?;
        }
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        let issuer_key = rsa_pkcs1_to_keypair(&key_pem)?;
        // Re-derive the issuer from the stored certificate (same subject and key).
        let issuer = CertificateParams::from_ca_cert_pem(&cert_pem)?.self_signed(&issuer_key)?;
        let bundle_path = dir.join(CA_BUNDLE_FILE);
        write_bundle(&bundle_path, &cert_pem);
        Ok(Self {
            cert_path,
            bundle_path,
            cert_pem,
            issuer,
            issuer_key,
            // One fast ECDSA key shared by all leaf certificates.
            leaf_key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?,
            configs: Mutex::new(HashMap::new()),
        })
    }

    /// TLS server config presenting a CA-signed certificate for `host`.
    pub fn server_config_for(&self, host: &str) -> anyhow::Result<Arc<ServerConfig>> {
        if let Some(c) = self.configs.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into()?),
        }];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = days_from_now(-1);
        params.not_after = days_from_now(365);
        params.use_authority_key_identifier_extension = true;
        let leaf = params.signed_by(&self.leaf_key, &self.issuer, &self.issuer_key)?;

        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der())),
        )?;
        // Keep intercepted traffic on HTTP/1.1.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.configs.lock().unwrap().insert(host.to_string(), config.clone());
        Ok(config)
    }
}

fn create_ca(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
    let key_pem = rsa_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?.to_string();
    let key = rsa_pkcs1_to_keypair(&key_pem)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "Portkey Forward Proxy");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = days_from_now(-1);
    params.not_after = years_from_now(10);
    let cert = params.self_signed(&key)?;
    write_private(&dir.join(CA_KEY_FILE), &key_pem)?;
    std::fs::write(dir.join(CA_CERT_FILE), cert.pem())?;
    Ok(())
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())
}

/// Public roots plus the local CA, for clients that replace their trust store.
fn write_bundle(path: &Path, ca_pem: &str) {
    let mut out = String::new();
    for cert in rustls_native_certs::load_native_certs().certs {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    out.push_str(ca_pem);
    let _ = std::fs::write(path, out);
}

mod time_shim {
    use time::{Duration, OffsetDateTime};
    pub fn days_from_now(days: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::days(days)
    }
    pub fn years_from_now(years: i64) -> OffsetDateTime {
        days_from_now(years * 365)
    }
}
