use crate::embed::{
    ASSET_SOLVER_WASM, ASSET_SOLVER_WASM_BROTLI, ASSET_SOLVER_WASM_GZIP, ASSET_SOLVER_WASM_ZSTD,
    CHALLENGE_DECLARATION, HTML_PREFIX, HTML_SUFFIX, WIGGLE_ROOM,
};
use crate::{ClientAddr, ProxyState, headers::X_REAL_IP};
use axum::extract::ConnectInfo;
use axum::http::header::USER_AGENT;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, Request, StatusCode, header::HOST},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use bytes::Bytes;
use compact_str::CompactString;
use flate2::Compression;
use flate2::write::GzEncoder;
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use serde_json;
use shared::challenge::verify_solution;
use shared::{
    challenge::{COOKIE_NAME, Challenge, ChallengeRecord, Solution},
    policy::compile::PolicyEvaluation,
    store::StoreError,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, warn};
use url::Url;
use uuid::{NoContext, Timestamp, Uuid};

const HTTP: &str = "http";
const HTTPS: &str = "https";
const ROOT: &str = "/";
const POW_METHOD: &str = "sha256";

const BROTLI: &str = "br";
const GZIP: &str = "gzip";
const ZSTD: &str = "zstd";

// TODO mikel these may be declared on axum already(?)

const HEADER_CACHE_CONTROL: &str = "Cache-Control";
const HEADER_CONTENT_ENCODING: &str = "Content-Encoding";
const HEADER_CONTENT_TYPE: &str = "Content-Type";
const HEADER_IP: &str = "ip";
const HEADER_URI: &str = "uri";
const HEADER_USER_AGENT: &str = "ua";
const HEADER_VARY: &str = "Vary";

use sha2::{Digest, Sha256};

struct ChallengeInfo<'a> {
    pub identity: CompactString,
    pub headers: &'a HeaderMap,
    pub uri: &'a str,
    pub difficulty_override: Option<u32>,
}

// TODO mikel: ergonomics
pub async fn challenge_middleware(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(addr): ConnectInfo<ClientAddr>,
    cookie_jar: CookieJar,
    req: Request<Body>,
    next: Next,
) -> Response {
    let request_uri = req.uri().to_string();
    let path = req.uri().path();
    let user_agent = req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok());
    let remote_ip = get_remote_ip(req.headers(), &addr);
    let policy_evaluation =
        state
            .policy_engine
            .evaluate(path, user_agent, req.headers(), remote_ip);

    match policy_evaluation {
        PolicyEvaluation::Allow { rule } => {
            debug!(rule = %rule, uri = %request_uri, "policy: ALLOW, forwarding request");
            next.run(req).await
        }

        PolicyEvaluation::Deny { rule } => {
            debug!(rule = %rule, uri = %request_uri, "policy: DENY");
            StatusCode::FORBIDDEN.into_response()
        }

        PolicyEvaluation::Challenge { rule, config } => {
            debug!(rule = %rule, uri = %request_uri, "policy: CHALLENGE");
            if check_token_cookie(&state, &cookie_jar).is_some() {
                return next.run(req).await;
            }
            let difficulty = config.as_ref().and_then(|c| c.difficulty);
            let identity = get_identity(req.headers(), &addr);
            let info = ChallengeInfo {
                identity,
                headers: req.headers(),
                uri: path,
                difficulty_override: difficulty,
            };
            serve_challenge_page(State(state), &info).await
        }

        PolicyEvaluation::DefaultAllow => {
            debug!(uri = %request_uri, "policy: no rule matched, allowing");
            next.run(req).await
        }
    }
}

fn check_token_cookie(state: &ProxyState, jar: &CookieJar) -> Option<()> {
    let cookie = jar.get(COOKIE_NAME)?;
    let val = cookie.value();
    let preview = &val[..val.len().min(30)];
    debug!(cookie_preview = %preview, "challenge_middleware: cookie found");

    if let Some(claims) = state.challenge_service.token_service.verify(val) {
        debug!(
            challenge = %claims.challenge,
            method = %claims.method,
            "challenge_middleware: valid token, forwarding request"
        );
        Some(())
    } else {
        debug!("challenge_middleware: token verification failed, re-challenging");
        None
    }
}

/// Extracts the user's identity from the request headers rather than the physical client address;
/// which could be another reverse proxy, a load balancer...
fn get_identity(headers: &HeaderMap, addr: &ClientAddr) -> CompactString {
    headers
        .get(crate::headers::X_REAL_IP)
        .and_then(|v| v.to_str().ok())
        .map(CompactString::new)
        .unwrap_or_else(|| addr.identity())
}

fn get_remote_ip(headers: &HeaderMap, addr: &ClientAddr) -> IpAddr {
    headers
        .get(X_REAL_IP)
        .and_then(|v| v.to_str().ok())
        .and_then(|ip| IpAddr::from_str(ip).ok())
        .unwrap_or_else(|| addr.ip())
}

async fn serve_challenge_page(
    State(state): State<Arc<ProxyState>>,
    challenge_info: &ChallengeInfo<'_>,
) -> Response {
    let new_challenge = match create_and_store_challenge(&state, challenge_info).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "serve_challenge_page: failed to create or store challenge");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let encoded_challenge = match serde_json::to_string(&new_challenge) {
        Ok(json) => json,
        Err(e) => {
            warn!(error = %e, "serve_challenge_page: failed to encode challenge to JSON");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut body = String::with_capacity(
        HTML_PREFIX.len()
            + CHALLENGE_DECLARATION.len()
            + encoded_challenge.len()
            + HTML_SUFFIX.len()
            + WIGGLE_ROOM,
    );
    body.push_str(HTML_PREFIX);
    body.push_str(CHALLENGE_DECLARATION);
    body.push_str(&encoded_challenge);
    body.push(';');
    body.push_str(HTML_SUFFIX);

    let accept_encoding = challenge_info
        .headers
        .get(axum::http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Try compression, fallthrough to the uncompressed version if something goes wrong.
    if accept_encoding.contains("gzip") {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());

        if let Err(e) = encoder.write_all(body.as_bytes()) {
            warn!(error = %e, "serve_challenge_page: failed to write to gzip encoder");
        } else {
            match encoder.finish() {
                Ok(compressed_data) => {
                    match Response::builder()
                        .header(axum::http::header::CONTENT_TYPE, "text/html")
                        .header(axum::http::header::CACHE_CONTROL, "no-store")
                        .header(axum::http::header::VARY, "Accept-Encoding")
                        .header(axum::http::header::CONTENT_ENCODING, "gzip")
                        .body(Body::from(compressed_data))
                    {
                        Ok(response) => return response,
                        Err(e) => {
                            warn!(error = %e, "serve_challenge_page: failed to build gzip response")
                        }
                    }
                }
                Err(e) => warn!(error = %e, "serve_challenge_page: failed to finish gzip encoder"),
            }
        }
    }

    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/html")
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header(axum::http::header::VARY, "Accept-Encoding")
        .body(Body::from(body))
        .unwrap_or_else(|e| {
            warn!(error = %e, "serve_challenge_page: failed to build final response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}

async fn create_and_store_challenge(
    state: &ProxyState,
    challenge_info: &ChallengeInfo<'_>,
) -> Result<Challenge, StoreError> {
    let now = Timestamp::now(NoContext);
    let id = Uuid::new_v7(now);
    let difficulty = challenge_info
        .difficulty_override
        .unwrap_or(state.challenge_service.challenge_config.difficulty);
    let mut raw_random_data = vec![0u8; 32];
    rng().fill_bytes(&mut raw_random_data);
    let random_data = Bytes::copy_from_slice(&raw_random_data);

    let challenge = Challenge {
        id,
        random_data: random_data.clone(),
        difficulty,
    };

    let metadata = create_metadata(challenge_info);

    let record = ChallengeRecord {
        id,
        issued_at: now.into(),
        metadata: metadata,
        method: POW_METHOD.into(),
        random_data: random_data,
        difficulty,
        spent: false,
    };

    state
        .challenge_service
        .challenge_repo
        .insert(record, state.challenge_service.challenge_config.ttl)
        .await?;

    Ok(challenge)
}

fn create_metadata(challenge_info: &ChallengeInfo<'_>) -> BTreeMap<CompactString, CompactString> {
    let mut metadata: BTreeMap<CompactString, CompactString> = BTreeMap::new();

    metadata.insert(HEADER_IP.into(), challenge_info.identity.clone());
    if let Some(ua) = challenge_info
        .headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
    {
        metadata.insert(HEADER_USER_AGENT.into(), CompactString::new(ua));
    }

    metadata.insert(HEADER_URI.into(), CompactString::new(challenge_info.uri));

    metadata
}

pub async fn serve_wasm(headers: HeaderMap) -> Response {
    let accept_encoding = headers
        .get(axum::http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let compressed_choice = if accept_encoding.contains(BROTLI) {
        Some((ASSET_SOLVER_WASM_BROTLI, BROTLI))
    } else if accept_encoding.contains(ZSTD) {
        Some((ASSET_SOLVER_WASM_ZSTD, ZSTD))
    } else if accept_encoding.contains(GZIP) {
        Some((ASSET_SOLVER_WASM_GZIP, GZIP))
    } else {
        None
    };

    // Try compression, fallthrough to the uncompressed version if something goes wrong.
    if let Some((data, encoding)) = compressed_choice {
        match Response::builder()
            .header(HEADER_CONTENT_TYPE, "application/wasm")
            .header(HEADER_CACHE_CONTROL, "public, max-age=31536000, immutable")
            .header(HEADER_VARY, "Accept-Encoding")
            .header(HEADER_CONTENT_ENCODING, encoding)
            .body(Body::from(data))
        {
            Ok(response) => return response,
            Err(e) => {
                warn!(error = %e, encoding = %encoding, "serve_wasm: failed to build compressed response")
            }
        }
    }

    Response::builder()
        .header("Content-Type", "application/wasm")
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .header("Vary", "Accept-Encoding")
        .body(Body::from(ASSET_SOLVER_WASM))
        .unwrap_or_else(|e| {
            warn!(error = %e, "serve_wasm: failed to build final response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}

#[derive(Serialize, Deserialize)]
pub struct PassParameters {
    pub id: Uuid,
    pub nonce: u64,
    pub redir: CompactString,
    pub response: Option<String>,
    #[serde(rename = "elapsedTime")]
    pub elapsed_time: Option<u64>,
}

pub async fn pass_challenge(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(_): ConnectInfo<ClientAddr>,
    Query(params): Query<PassParameters>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let solution = Solution {
        id: params.id,
        nonce: params.nonce,
    };

    // TODO mikel: return proper, readable errors?
    if verify_solution(state.challenge_service.challenge_repo.as_ref(), &solution)
        .await
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let host_header = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let final_redir = if redirect_is_safe(params.redir.as_str(), host_header) {
        params.redir.as_str()
    } else {
        ROOT
    };

    let restriction = state
        .challenge_service
        .challenge_config
        .jwt_restriction_header
        .as_deref()
        .and_then(|header_name| headers.get(header_name).and_then(|v| v.to_str().ok()))
        .map(|value| sha256_to_hex(value));
    if state
        .challenge_service
        .challenge_config
        .jwt_restriction_header
        .is_some()
        && restriction.is_none()
    {
        debug!("pass_challenge: restriction header configured but missing from request");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let token = match state.challenge_service.token_service.mint(
        params.id,
        POW_METHOD,
        restriction,
        state.challenge_service.challenge_config.ttl.as_secs(),
    ) {
        Ok(t) => t,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let token_preview = &token[..token.len().min(30)];
    debug!(
        challenge_id = %params.id,
        token_preview = %token_preview,
        redir = %final_redir,
        "pass_challenge: minted token, setting cookie, and redirecting"
    );

    let cookie = Cookie::build((COOKIE_NAME, token))
        .path(ROOT)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", final_redir)
        .body(Body::empty())
        .unwrap();

    (jar.add(cookie), response).into_response()
}

// TODO mikel: inline? Just for fun, check if the compiler inlines it automatically.
fn redirect_is_safe(redir: &str, current_host: &str) -> bool {
    // Accept local paths.
    if redir.starts_with(ROOT) {
        return !redir.starts_with("//");
    }

    // Allow absolute paths if they belong to a valid URL with the same host.
    if let Ok(url) = Url::parse(redir) {
        let scheme = url.scheme();
        return (scheme == HTTP || scheme == HTTPS) && url.host_str() == Some(current_host);
    }

    false
}

fn sha256_to_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}
