use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request, header};
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::task::{Context, Poll};
use tower::{Layer, Service};

use shared::config::proxy::ForwardedHeadersConfig;

pub const X_FORWARDED_FOR: &str = "x-forwarded-for";
pub const X_REAL_IP: &str = "x-real-ip";
pub(crate) const KEEP_ALIVE: &str = "keep-alive";
pub(crate) const UPGRADE: &str = "upgrade";

const REMOVABLE_CONN_HEADERS: &[header::HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    // Keep-alive not included in axum atm.
];

/// Removes hop-by-hop headers, keeping the upgrade header.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let conn_headers = extract_conn_headers(headers);
    for header_name in conn_headers {
        headers.remove(&header_name);
    }
    for header_name in REMOVABLE_CONN_HEADERS {
        headers.remove(header_name);
    }
    headers.remove(KEEP_ALIVE);
}

fn extract_conn_headers(headers: &HeaderMap) -> SmallVec<[header::HeaderName; 4]> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|header_values| {
            header_values.to_str().ok().into_iter().flat_map(|values| {
                values.split(',').filter_map(|value| {
                    let name = value.trim().parse::<header::HeaderName>().ok()?;
                    // UPGRADE is required later down the line
                    if name == header::UPGRADE {
                        return None;
                    }
                    Some(name)
                })
            })
        })
        .collect()
}

#[derive(Clone)]
pub struct ForwardedHeaders<S> {
    inner: S,
    config: ForwardedHeadersConfig,
}

#[derive(Clone, Copy)]
pub struct ForwardedHeadersLayer(ForwardedHeadersConfig);

impl ForwardedHeadersLayer {
    pub const fn new(config: ForwardedHeadersConfig) -> Self {
        Self(config)
    }
}

impl<S> Layer<S> for ForwardedHeadersLayer {
    type Service = ForwardedHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ForwardedHeaders {
            inner,
            config: self.0,
        }
    }
}

impl<S, B> Service<Request<B>> for ForwardedHeaders<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        apply_forwarded_request_headers(&mut req, self.config);
        self.inner.call(req)
    }
}

fn apply_forwarded_request_headers<B>(req: &mut Request<B>, config: ForwardedHeadersConfig) {
    let Some(ip) = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
    else {
        return;
    };

    let source = ip.to_string();

    update_xff(req.headers_mut(), &source, config.xff_strip_private);

    if !req.headers().contains_key(X_REAL_IP)
        && let Some(xff) = req.headers().get(X_FORWARDED_FOR)
        && let Ok(s) = xff.to_str()
        && let Some(forwarded) = s.rsplit(',').next().map(str::trim)
        && let Ok(new_value) = HeaderValue::from_str(forwarded)
    {
        req.headers_mut().insert(X_REAL_IP, new_value);
    }

    if config.use_remote_address {
        if let Ok(value) = HeaderValue::from_str(&source) {
            req.headers_mut().insert(X_REAL_IP, value);
        }
    }

    return;
}

/// This function mimics Anubis' behaviour:
/// 1. Strip loopback, private IPs (if `strip_private` is true), etc.
/// 2. Stop when an entry cannot be parsed
/// 3. Return the latest valid value
fn update_xff(headers: &mut HeaderMap, remote_ip: &str, strip_private: bool) {
    let original = headers
        .get(X_FORWARDED_FOR)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let combined = if original.is_empty() {
        remote_ip.to_owned()
    } else {
        format!("{original}, {remote_ip}")
    };

    let mut selected = None;
    for seg in combined.rsplit(',').map(str::trim) {
        let Ok(ip) = seg.parse::<IpAddr>() else {
            break;
        };
        if is_ignored(&ip, strip_private) {
            continue;
        }
        selected = Some(seg);
        break;
    }

    match selected {
        Some(seg) => {
            if let Ok(value) = HeaderValue::from_str(seg) {
                headers.insert(X_FORWARDED_FOR, value);
            } else {
                headers.remove(X_FORWARDED_FOR);
            }
        }
        None => {
            headers.remove(X_FORWARDED_FOR);
        }
    }
}

fn is_ignored(ip: &IpAddr, ignore_private_addrs: bool) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            addr.is_loopback()
                || addr.is_link_local()
                || (ignore_private_addrs && addr.is_private())
                || is_cgnat(addr)
        }
        IpAddr::V6(addr) => addr.is_loopback(),
    }
}

/// CGNAT range 100.64.0.0/10
fn is_cgnat(v4: &Ipv4Addr) -> bool {
    v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
}
