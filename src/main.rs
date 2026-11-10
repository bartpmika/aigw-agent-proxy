//! Portkey forward proxy, Rust edition (internal prototype).
//!
//! Drop-in for the TypeScript gateway's `--forward-proxy` mode: same
//! environment variables, `forward-proxy.json`, CA files and control-plane
//! contract.
#![recursion_limit = "256"]

mod adapter;
mod analytics;
#[cfg(feature = "gateway")]
mod api;
mod body;
mod ca;
mod config;
mod control_plane;
#[cfg(feature = "gateway")]
mod engine;
/// Proxy build: the code-only transforms, without the provider data.
#[cfg(not(feature = "gateway"))]
mod engine {
    pub mod responses;
    pub mod transforms;
}
mod gateway;
mod guardrails;
mod identity;
mod mcp;
mod policy;
mod providers;
#[cfg(feature = "gateway")]
mod mustache;
mod proxy;
mod router;
mod unified;
mod usage;
#[cfg(feature = "gateway")]
mod validate;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        // Never route our own upstream calls through HTTPS_PROXY (ourselves).
        .no_proxy()
        .connect_timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(256)
        .tcp_nodelay(true)
        .build()?)
}

fn upstream_tls() -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[cfg(not(feature = "gateway"))]
async fn health_server(host: String, port: u16) {
    use hyper::service::service_fn;
    let Ok(listener) = tokio::net::TcpListener::bind((host.as_str(), port)).await else {
        return tracing::warn!("health port {port} unavailable");
    };
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        tokio::spawn(async move {
            let svc = service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(hyper::Response::new(body::full(
                    serde_json::json!({ "status": "success", "message": "Server is healthy", "version": control_plane::GATEWAY_VERSION, "implementation": "rust-proxy" }).to_string(),
                )))
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
        });
    }
}

/// Reads `KEY=VALUE` lines from `~/.aigw-agent-proxy/proxy.env` (or
/// `$AIGW_PROXY_ENV`) into the environment. Variables already set win.
fn load_env_file() {
    let path = std::env::var("AIGW_PROXY_ENV").ok().map(std::path::PathBuf::from).or_else(|| {
        std::env::var("HOME").ok().map(|h| std::path::PathBuf::from(h).join(".aigw-agent-proxy/proxy.env"))
    });
    let Some(path) = path else { return };
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let mut value = value.trim();
        // Drop a trailing comment and surrounding quotes.
        if !value.starts_with('"') && !value.starts_with('\'') {
            value = value.split(" #").next().unwrap_or(value).trim();
        }
        let value = value.trim_matches('"').trim_matches('\'');
        let value = value.replace("$HOME", &std::env::var("HOME").unwrap_or_default());
        let value = match value.strip_prefix("~/") {
            Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
            None => value,
        };
        if !key.is_empty() && std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
    eprintln!("loaded settings from {}", path.display());
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    load_env_file();
    let settings = config::Settings::load()?;
    let ca = Arc::new(ca::LocalCa::load_or_create(&settings.ca_dir)?);
    let http = http_client()?;
    let control_plane = Arc::new(control_plane::ControlPlane::new(&settings, http.clone()));
    control_plane.spawn_sync_loop(
        settings.organisations_to_sync.clone(),
        Duration::from_millis(settings.sync_interval_ms),
    );
    let sink = analytics::Sink::new(http.clone(), settings.control_plane_basepath.clone(), settings.client_auth.clone());

    let addr: SocketAddr = format!("{}:{}", settings.listen_host, settings.port).parse()?;
    println!("{}", proxy::setup_instructions(&settings, &ca));
    let api_port = settings.health_port;
    // Usage deltas go to the control plane on a timer (budgets across machines).
    let usage = Arc::new(usage::UsageTracker::default());
    {
        let (usage, control_plane) = (usage.clone(), control_plane.clone());
        let every = Duration::from_millis(std::env::var("USAGE_RESYNC_INTERVAL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            loop {
                ticker.tick().await;
                for (org, body) in usage.take() {
                    if !control_plane.send_usage(&org, &body).await {
                        tracing::warn!("usage for {org} not reported; dropped this interval");
                    }
                }
            }
        });
    }
    let gateway = Arc::new(gateway::Gateway { settings, control_plane, sink, http, usage });
    // API mode (x-portkey-* headers) on PORT, as the TS gateway serves on 8787.
    #[cfg(feature = "gateway")]
    if let Some(port) = api_port {
        let (gateway, host) = (gateway.clone(), gateway.settings.listen_host.clone());
        tokio::spawn(async move {
            let addr: SocketAddr = match format!("{host}:{port}").parse() {
                Ok(a) => a,
                Err(e) => return tracing::warn!("bad API address: {e}"),
            };
            if let Err(e) = api::serve(gateway, addr).await {
                tracing::warn!("API server on {addr} failed: {e}");
            }
        });
    }
    // Proxy build: only a health endpoint on PORT.
    #[cfg(not(feature = "gateway"))]
    if let Some(port) = api_port {
        let host = gateway.settings.listen_host.clone();
        tokio::spawn(health_server(host, port));
    }
    let proxy = Arc::new(proxy::Proxy { gateway, ca, upstream_tls: upstream_tls() });
    proxy.serve(addr).await
}
