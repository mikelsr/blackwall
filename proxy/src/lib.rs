mod auth;
pub mod client;
mod embed;
mod handler;
pub mod headers;
pub mod server;
mod tls;
mod upgrade;

use client::ClientAddr;
use shared::{
    challenge::{ChallengeRepository, memory::MemoryChallengeRepository},
    config::{ChallengeConfig, proxy::ForwardedHeadersConfig},
    policy::{
        PolicyEngine,
        dns::{DnsVerificationError, DnsVerifier, HickoryDnsVerifier},
    },
};
use tower_http::trace::TraceLayer;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderValue, Request, Response, StatusCode, Uri,
        header::HOST,
        uri::{Authority, Scheme},
    },
    middleware::from_fn_with_state,
    routing::get,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{client::legacy, rt::TokioExecutor};
use shared::config::{BasePrefix, PathRewriteConfig, ProxyConfig, Target};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;
use tracing::{debug, warn};
use url::Url;

use crate::auth::TokenService;

pub struct ProxyState {
    target_scheme: Scheme,
    target_authority: Authority,
    target_host: Option<HeaderValue>,
    base_prefix: Option<BasePrefix>,
    strip_base_prefix: bool,
    client: HttpsClient,
    challenge_service: ChallengeService,
    policy_engine: PolicyEngine,
    dns_verifier: Box<dyn DnsVerifier>,
}

pub struct ChallengeService {
    token_service: TokenService,
    challenge_repo: Arc<dyn ChallengeRepository + Send + Sync>,
    challenge_config: ChallengeConfig,
}

type HttpsClient = legacy::Client<HttpsConnector<legacy::connect::HttpConnector>, Body>;

pub enum RuntimeMode {
    Proxy(Box<ProxyState>), // TODO mikel: Box
    AuthOnly,
}

impl RuntimeMode {
    pub const fn name(&self) -> &'static str {
        match self {
            RuntimeMode::Proxy(_) => "proxy",
            RuntimeMode::AuthOnly => "auth-only",
        }
    }

    pub fn new(config: ProxyConfig, policy_engine: PolicyEngine) -> Result<Self, ProxyInitError> {
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
                config.challenge,
                Scheme::HTTP,
                policy_engine,
            ),
            Target::Https(url) => Self::build_proxy_state(
                target_host,
                path_rewrite,
                insecure_skip_verify,
                disable_keepalive,
                url,
                config.challenge,
                Scheme::HTTPS,
                policy_engine,
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
        challenge_config: ChallengeConfig,
        scheme: Scheme,
        policy_engine: PolicyEngine,
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
        let challenge_service = build_challenge_service(challenge_config);

        let dns_verifier = Box::new(
            HickoryDnsVerifier::new().map_err(|source| ProxyInitError::DnsError { source })?,
        );

        Ok(RuntimeMode::Proxy(Box::new(ProxyState {
            target_scheme: scheme,
            target_authority: authority,
            target_host,
            base_prefix,
            strip_base_prefix,
            client,
            challenge_service,
            policy_engine,
            dns_verifier,
        })))
    }
}

pub fn build_challenge_service(challenge_config: ChallengeConfig) -> ChallengeService {
    ChallengeService {
        token_service: TokenService::new(&challenge_config.secret)
            .expect("failed to initialize token service"),
        challenge_repo: Arc::new(MemoryChallengeRepository::new()),
        challenge_config,
    }
}

pub fn build_router(mode: RuntimeMode, forward_config: ForwardedHeadersConfig) -> Router {
    match mode {
        RuntimeMode::Proxy(state) => {
            let state = Arc::new(*state);

            // Unprotected endpoints.
            let api_routes = Router::new()
                .route("/pass-challenge", get(handler::pass_challenge))
                .route("/solver.wasm", axum::routing::get(handler::serve_wasm))
                // .layer(headers::ForwardedHeadersLayer::new(forward_config)) // TODO mikel
                .layer(TraceLayer::new_for_http())
                .with_state(state.clone());

            // Proxy routes.
            let proxy_routes = Router::new()
                .fallback(handler_proxy)
                .layer(from_fn_with_state(
                    state.clone(),
                    handler::challenge_middleware,
                ));

            Router::new()
                .nest(shared::challenge::API_PREFIX, api_routes)
                .merge(proxy_routes)
                .layer(headers::ForwardedHeadersLayer::new(forward_config))
                .with_state(state)
        }
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
    let method = req.method().clone();
    let request_uri = req.uri().clone();

    headers::strip_hop_by_hop(req.headers_mut());

    let uri = match rewrite_uri(
        &state.target_scheme,
        &state.target_authority,
        req.uri(),
        state.base_prefix.as_ref().map(BasePrefix::as_str),
        state.strip_base_prefix,
    ) {
        Ok(uri) => uri,
        Err(err) => {
            warn!(
                method = %method,
                uri = %request_uri,
                error = %err,
                "failed to rewrite request URI"
            );
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    *req.uri_mut() = uri.clone();

    if let Some(header_value) = state.target_host.as_ref() {
        req.headers_mut().insert(HOST, header_value.clone());
    }

    let upgrade_requested = upgrade::requests_upgrade(&req);
    if upgrade_requested {
        debug!(
            method = %method,
            uri = %request_uri,
            upstream_uri = %uri,
            "upgrade requested"
        );
    }

    let client_upgrade = if upgrade_requested {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let mut response = match state.client.request(req).await {
        Ok(response) => response,
        Err(err) => {
            warn!(
                method = %method,
                uri = %request_uri,
                upstream_uri = %uri,
                error = %err,
                "upstream request failed"
            );
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    headers::strip_hop_by_hop(response.headers_mut());

    if let Some(client_upgrade) = client_upgrade {
        let target_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            if let Err(status) = upgrade::upgrade_relay(client_upgrade, target_upgrade).await {
                warn!(status = %status, "upgrade relay failed");
            }
        });
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
    //It's always TCP_NODELAY: https://brooker.co.za/blog/2024/05/09/nagle.html
    http.set_nodelay(true);

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
    DnsError {
        source: DnsVerificationError,
    },
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
            Self::DnsError { source } => {
                write!(f, "failed to initialize DNS resolver: {source}")
            }
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
            Self::DnsError { source } => Some(source),
            Self::InvalidTargetHost { source, .. } => Some(source),
            _ => None,
        }
    }
}
