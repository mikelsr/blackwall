mod headers;
mod tls;
mod upgrade;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderValue, Request, Response, StatusCode, Uri,
        header::HOST,
        uri::{Authority, Scheme},
    },
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{client::legacy, rt::TokioExecutor};
use rustls;
use shared::config::{BasePrefix, PathRewriteConfig, ProxyConfig, Target};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;
use url::Url;

pub struct ProxyState {
    target_scheme: Scheme,
    target_authority: Authority,
    target_host: Option<HeaderValue>,
    base_prefix: Option<BasePrefix>,
    strip_base_prefix: bool,
    client: HttpsClient,
}

type HttpsClient = legacy::Client<HttpsConnector<legacy::connect::HttpConnector>, Body>;

pub enum RuntimeMode {
    Proxy(Box<ProxyState>), // TODO mikel: Box
    AuthOnly,
}

impl RuntimeMode {
    pub fn from_config(config: ProxyConfig) -> Result<Self, ProxyInitError> {
        let ProxyConfig {
            target,
            target_host,
            insecure_skip_verify,
            disable_keepalive,
            path_rewrite,
            .. // TODO mikel
        } = config;

        match target {
            Target::Disabled => Ok(RuntimeMode::AuthOnly),
            Target::Http(url) => Self::build_proxy_state(
                target_host,
                path_rewrite,
                insecure_skip_verify,
                disable_keepalive,
                url,
                Scheme::HTTP,
            ),
            Target::Https(url) => Self::build_proxy_state(
                target_host,
                path_rewrite,
                insecure_skip_verify,
                disable_keepalive,
                url,
                Scheme::HTTPS,
            ),
        }
    }
}

impl RuntimeMode {
    fn build_proxy_state(
        target_host: Option<String>,
        path_rewrite: Option<PathRewriteConfig>,
        insecure_skip_verify: bool,
        disable_keepalive: bool,
        url: Url,
        scheme: Scheme,
    ) -> Result<RuntimeMode, ProxyInitError> {
        let Some(host) = url.host_str() else {
            return Err(ProxyInitError::InvalidTargetUrl {
                value: url.to_string(),
                reason: "missing host",
            });
        };

        let authority = match url.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_owned(),
        };

        let Ok(authority) = authority.parse::<Authority>() else {
            return Err(ProxyInitError::InvalidTargetAuthority { value: authority });
        };

        let target_host = match target_host {
            Some(target) if !target.is_empty() => match HeaderValue::from_str(target.as_str()) {
                Ok(valid) => Some(valid),
                Err(source) => {
                    return Err(ProxyInitError::InvalidTargetHost {
                        value: target,
                        source,
                    });
                }
            },
            _ => None,
        };

        let (base_prefix, strip_base_prefix) = match path_rewrite {
            Some(path_rewrite) => (path_rewrite.base_prefix, path_rewrite.strip_base_prefix),
            _ => (None, false),
        };

        let client = build_client(insecure_skip_verify, disable_keepalive);
        Ok(RuntimeMode::Proxy(Box::new(ProxyState {
            target_scheme: scheme,
            target_authority: authority,
            target_host,
            base_prefix: base_prefix,
            strip_base_prefix: strip_base_prefix,
            client,
        })))
    }
}

pub fn build_router(mode: RuntimeMode, /*, forward_config: ForwardedHeadersConfig */) -> Router {
    match mode {
        RuntimeMode::Proxy(state) => Router::new()
            .fallback(handler_proxy)
            .with_state(Arc::new(*state)), // TODO mikel
        // .layer(forward_config),
        RuntimeMode::AuthOnly => Router::new().fallback(handler_auth_only),
    }
}

async fn handler_auth_only() -> (StatusCode, &'static str) {
    (StatusCode::OK, "you are not a bot")
}

async fn handler_proxy(
    State(state): State<Arc<ProxyState>>,
    mut req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    headers::strip_hop_by_hop(req.headers_mut());

    let uri = rewrite_uri(
        &state.target_scheme,
        &state.target_authority,
        req.uri(),
        state.base_prefix.as_ref().map(BasePrefix::as_str),
        state.strip_base_prefix,
    )
    .map_err(|_| StatusCode::BAD_GATEWAY)?;

    *req.uri_mut() = uri;

    if let Some(header_value) = state.target_host.as_ref() {
        req.headers_mut().insert(HOST, header_value.clone());
    }

    let upgrade_requested = upgrade::requests_upgrade(&req);
    let client_upgrade = if upgrade_requested {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let mut response = state
        .client
        .request(req)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    headers::strip_hop_by_hop(response.headers_mut());

    if let Some(client_upgrade) = client_upgrade {
        let target_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move { upgrade::upgrade_relay(client_upgrade, target_upgrade) });
    }

    Ok(response.map(Body::new))
}

fn rewrite_uri(
    scheme: &Scheme,
    authority: &Authority,
    source: &Uri,
    base_prefix: Option<&str>,
    strip: bool,
) -> Result<Uri, axum::http::Error> {
    let incoming_pq = source.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let owned_pq: String;

    // These gimnastics aim to allocate only if we need to prepend '/'.
    let pq = if strip {
        if let Some(prefix) = base_prefix {
            let stripped = incoming_pq.strip_prefix(prefix).unwrap_or(incoming_pq);
            if stripped.is_empty() {
                "/"
            } else if stripped.starts_with('/') {
                stripped
            } else {
                owned_pq = format!("/{stripped}");
                owned_pq.as_str()
            }
        } else {
            incoming_pq
        }
    } else {
        incoming_pq
    };

    Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(pq)
        .build()
}

fn build_client(insecure_skip_verify: bool, disable_keepalive: bool) -> HttpsClient {
    let mut http = legacy::connect::HttpConnector::new();
    http.enforce_http(false);

    // TODO mikel: apply `--target-sni` flag.
    // We're currently letting rustls handle it.

    let https = if insecure_skip_verify {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(tls::SignatureVerifier))
            .with_no_client_auth();
        HttpsConnectorBuilder::new()
            .with_tls_config(crypto)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http)
    } else {
        HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http)
    };

    let mut builder = legacy::Client::builder(TokioExecutor::new());
    if disable_keepalive {
        builder.pool_max_idle_per_host(0);
    }
    builder.build(https)
}

// Anubis allows invalid configurations and fails with 502 while proxying.
// I've opted for failing fast and not allowing those states, at least for now.
#[derive(Debug)]
pub enum ProxyInitError {
    InvalidTargetAuthority {
        value: String,
    },
    InvalidTargetUrl {
        value: String,
        reason: &'static str,
    },
    InvalidTargetHost {
        value: String,
        source: axum::http::header::InvalidHeaderValue,
    },
}

impl Display for ProxyInitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ProxyInitError::InvalidTargetAuthority { value } => {
                write!(f, "invalid target authority {:?}", value)
            }
            ProxyInitError::InvalidTargetUrl { value, reason } => {
                write!(f, "invalid target URL {:?}: {}", value, reason)
            }
            ProxyInitError::InvalidTargetHost { value, .. } => {
                write!(f, "invalid target-host {:?}", value)
            }
        }
    }
}

impl Error for ProxyInitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProxyInitError::InvalidTargetHost { source, .. } => Some(source),
            _ => None,
        }
    }
}
