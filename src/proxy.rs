//! The forward proxy (what HTTPS_PROXY points at): CONNECT tunnels to LLM
//! hosts are TLS-terminated with the local CA and served by the gateway;
//! other hosts are decrypted for web inspection (see `web.rs`) unless
//! bypassed, in which case they are blind TCP tunnels.

use crate::body::{self, Body};
use crate::ca::LocalCa;
use crate::gateway::{ClientLookup, Gateway, Tunnel};
use crate::identity;
use base64::Engine;
use futures_util::FutureExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// A stream with one already-read byte put back in front.
struct Prefixed<T> {
    prefix: Option<u8>,
    inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some(b) = self.prefix.take() {
            buf.put_slice(&[b]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct Proxy {
    pub gateway: Arc<Gateway>,
    pub ca: Arc<LocalCa>,
    pub upstream_tls: tokio_rustls::TlsConnector,
}

fn text(status: StatusCode, s: impl Into<String>) -> Response<Body> {
    let mut r = Response::new(body::full(s.into()));
    *r.status_mut() = status;
    r
}

/// `Basic base64(user:<portkey-api-key>)`; the password is the key.
fn api_key_from_proxy_auth(req: &Request<Incoming>) -> Option<String> {
    let v = req.headers().get("proxy-authorization")?.to_str().ok()?;
    let encoded = v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let key = decoded.split_once(':').map(|(_, p)| p.to_string()).unwrap_or(decoded);
    (!key.is_empty()).then_some(key)
}

fn split_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port) = authority.rsplit_once(':')?;
    Some((host.trim_matches(|c| c == '[' || c == ']').to_string(), port.parse().ok()?))
}

impl Proxy {
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, peer) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let proxy = self.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| proxy.clone().route(req, peer));
                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!("proxy connection ended: {e}");
                }
            });
        }
    }

    async fn route(self: Arc<Self>, req: Request<Incoming>, peer: SocketAddr) -> Result<Response<Body>, std::convert::Infallible> {
        if req.method() == Method::CONNECT {
            return Ok(self.connect(req, peer));
        }
        if req.uri().scheme().is_some() {
            return Ok(self.forward_plain_http(req, peer).await);
        }
        Ok(match req.uri().path() {
            "/ca.pem" => {
                let mut r = text(StatusCode::OK, self.ca.cert_pem.clone());
                r.headers_mut().insert("content-type", "application/x-pem-file".parse().unwrap());
                r
            }
            _ => text(StatusCode::OK, setup_instructions(&self.gateway.settings, &self.ca)),
        })
    }

    fn connect(self: Arc<Self>, mut req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        let Some((host, port)) = req.uri().authority().and_then(|a| split_authority(a.as_str())) else {
            return text(StatusCode::BAD_REQUEST, "bad CONNECT target");
        };
        let settings = &self.gateway.settings;
        let intercept = settings.provider_for(&host).is_some() || settings.inspects_web(&host, port);
        let api_key = api_key_from_proxy_auth(&req);
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(u) => TokioIo::new(u),
                Err(e) => return tracing::debug!("CONNECT upgrade failed: {e}"),
            };
            if !intercept {
                // Blind tunnel: never decrypted.
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(mut upstream) => {
                        let mut client = upgraded;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                    Err(e) => tracing::debug!("tunnel to {host}:{port} failed: {e}"),
                }
                return;
            }
            // TLS (ClientHello starts with 0x16) is terminated with the local
            // CA; anything else is plain HTTP inside the tunnel.
            let mut client = upgraded;
            let mut first = [0u8; 1];
            match client.read(&mut first).await {
                Ok(1) => {}
                _ => return,
            }
            let client = Prefixed { prefix: Some(first[0]), inner: client };
            // Look up the calling process once per tunnel, in the background.
            let lookup: ClientLookup = identity::lookup_local_client(peer.ip(), peer.port()).boxed().shared();
            if first[0] != 0x16 {
                let tunnel = Arc::new(Tunnel { host, port, tls: false, portkey_api_key: api_key, client: lookup });
                return self.serve_tunnel(client, tunnel).await;
            }
            let config = match self.ca.server_config_for(&host) {
                Ok(c) => c,
                Err(e) => return tracing::warn!("certificate for {host} failed: {e}"),
            };
            let tls = match tokio_rustls::TlsAcceptor::from(config).accept(client).await {
                Ok(t) => t,
                Err(e) => {
                    return tracing::warn!("TLS error for {host} (is the CA trusted by the client?): {e}");
                }
            };
            let tunnel = Arc::new(Tunnel { host, port, tls: true, portkey_api_key: api_key, client: lookup });
            self.serve_tunnel(tls, tunnel).await;
        });
        Response::new(body::empty())
    }

    /// Serves HTTP/1.1 requests arriving through one tunnel.
    async fn serve_tunnel<T>(self: Arc<Self>, io: T, tunnel: Arc<Tunnel>)
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let proxy = self.clone();
        let service = service_fn(move |req: Request<Incoming>| {
            let (proxy, tunnel) = (proxy.clone(), tunnel.clone());
            async move {
                if req.headers().contains_key(hyper::header::UPGRADE) {
                    return Ok::<_, std::convert::Infallible>(proxy.upgrade_passthrough(req, &tunnel).await);
                }
                Ok(proxy.gateway.clone().handle(req, tunnel).await)
            }
        });
        if let Err(e) = http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades()
            .await
        {
            tracing::debug!("intercepted connection ended: {e}");
        }
    }

    /// Absolute-form requests (plain-HTTP proxying): inspected like
    /// decrypted web traffic, else forwarded untouched.
    async fn forward_plain_http(&self, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        let url = req.uri().to_string();
        let host = req.uri().host().unwrap_or_default().to_string();
        let port = req.uri().port_u16().unwrap_or(80);
        if !self.gateway.settings.inspects_web(&host, port) {
            return self.gateway.passthrough(req, &url).await;
        }
        let tunnel = Tunnel {
            port,
            tls: false,
            host,
            portkey_api_key: api_key_from_proxy_auth(&req),
            client: identity::lookup_local_client(peer.ip(), peer.port()).boxed().shared(),
        };
        self.gateway.clone().web(req, &tunnel, &url).await
    }

    /// WebSocket and other upgrades on intercepted hosts: raw passthrough.
    async fn upgrade_passthrough(&self, mut req: Request<Incoming>, tunnel: &Tunnel) -> Response<Body> {
        let origin = self.gateway.settings.origin_base_url(&tunnel.host, tunnel.port, tunnel.tls);
        let Ok(url) = reqwest::Url::parse(&origin) else {
            return text(StatusCode::BAD_GATEWAY, "bad origin");
        };
        let host = url.host_str().unwrap_or_default().to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let Ok(tcp) = TcpStream::connect((host.as_str(), port)).await else {
            return text(StatusCode::BAD_GATEWAY, "upstream connect failed");
        };
        let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".into());
        let mut up = Request::builder().method(req.method().clone()).uri(path);
        for (k, v) in req.headers() {
            if k != "host" && k != "proxy-authorization" {
                up = up.header(k, v);
            }
        }
        let up = up.header("host", url.authority()).body(body::empty()).unwrap();
        let client_upgrade = hyper::upgrade::on(&mut req);
        let response = if url.scheme() == "https" {
            let Ok(name) = rustls::pki_types::ServerName::try_from(host.clone()) else {
                return text(StatusCode::BAD_GATEWAY, "bad host");
            };
            let Ok(tls) = self.upstream_tls.connect(name, tcp).await else {
                return text(StatusCode::BAD_GATEWAY, "upstream TLS failed");
            };
            send_upgrade(TokioIo::new(tls), up).await
        } else {
            send_upgrade(TokioIo::new(tcp), up).await
        };
        let Ok(mut upstream_resp) = response else {
            return text(StatusCode::BAD_GATEWAY, "upstream upgrade failed");
        };
        let mut resp = Response::new(body::empty());
        *resp.status_mut() = upstream_resp.status();
        *resp.headers_mut() = upstream_resp.headers().clone();
        if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);
            tokio::spawn(async move {
                if let (Ok(c), Ok(u)) = (client_upgrade.await, upstream_upgrade.await) {
                    let (mut c, mut u) = (TokioIo::new(c), TokioIo::new(u));
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
                }
            });
        }
        resp
    }
}

async fn send_upgrade<T>(io: TokioIo<T>, req: Request<Body>) -> anyhow::Result<Response<Incoming>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender.send_request(req).await?)
}

pub fn setup_instructions(settings: &crate::config::Settings, ca: &LocalCa) -> String {
    let url = format!("http://{}:{}", settings.listen_host, settings.port);
    format!(
        "Portkey forward proxy (Rust) listening on {url}\nCA certificate: {}\n\nRoute an agent through it:\n  export HTTPS_PROXY={url}\n  export NODE_EXTRA_CA_CERTS={}   # Node agents (Claude Code, Codex, ...)\n  export SSL_CERT_FILE={}       # Python/OpenSSL agents (public roots + local CA)\n  export REQUESTS_CA_BUNDLE={}\n\n{}\n",
        ca.cert_path.display(),
        ca.cert_path.display(),
        ca.bundle_path.display(),
        ca.bundle_path.display(),
        if settings.portkey_api_key.is_some() {
            "Requests use the Portkey API key from FORWARD_PROXY_PORTKEY_API_KEY.".to_string()
        } else {
            format!("No default Portkey API key: put one in the proxy URL, e.g. http://me:<portkey-api-key>@{}:{}", settings.listen_host, settings.port)
        }
    )
}
