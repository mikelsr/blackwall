use crate::embed::{
    ASSET_SOLVER_WASM, CHALLENGE_DECLARATION, HTML_PREFIX, HTML_SUFFIX, WIGGLE_ROOM,
};
use crate::{ClientAddr, ProxyState};
use axum::extract::ConnectInfo;
use axum::http::header::USER_AGENT;
use axum::response::Redirect;
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
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use serde_json;
use shared::challenge::verify_solution;
use shared::{
    challenge::{COOKIE_NAME, Challenge, ChallengeRecord, Solution},
    store::StoreError,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;
use url::Url;
use uuid::{NoContext, Timestamp, Uuid};

const HTTP: &str = "http";
const HTTPS: &str = "https";
const ROOT: &str = "/";
const POW_METHOD: &str = "sha256";
const HEADER_IP: &str = "ip";
const HEADER_USER_AGENT: &str = "ua";
const HEADER_URI: &str = "uri";

type WASMHEADERS = ([(&'static str, &'static str); 2], &'static [u8]);
const WASM_RESPONSE: WASMHEADERS = (
    [
        ("Content-Type", "application/wasm"),
        ("Cache-Control", "public, max-age=31536000, immutable"),
    ],
    ASSET_SOLVER_WASM,
);

struct ChallengeInfo<'a> {
    pub identity: CompactString,
    pub headers: &'a HeaderMap,
    pub uri: &'a str,
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
    debug!(uri = %request_uri, "challenge_middleware: processing request");

    if let Some(cookie) = cookie_jar.get(COOKIE_NAME) {
        let val = cookie.value();
        let preview = &val[..val.len().min(30)];
        debug!(cookie_preview = %preview, "challenge_middleware: cookie found");

        if let Some(claims) = state.challenge_service.token_service.verify(val) {
            let identity = get_identity(req.headers(), &addr);
            debug!(
                claims_sub = %claims.sub,
                identity = %identity,
                "challenge_middleware: comparing identity"
            );
            if claims.sub == identity.as_str() {
                debug!("challenge_middleware: identity matched, forwarding request");
                return next.run(req).await;
            }
            debug!(
                claims_sub = %claims.sub,
                identity = %identity,
                "challenge_middleware: identity MISMATCH"
            );
        } else {
            debug!("challenge_middleware: token verification FAILED");
        }
    } else {
        debug!("challenge_middleware: no cookie found");
    }

    let identity = get_identity(req.headers(), &addr);
    let ctx = ChallengeInfo {
        identity,
        headers: req.headers(),
        uri: req.uri().path(),
    };

    serve_challenge_page(State(state), ctx).await
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

async fn serve_challenge_page(
    State(state): State<Arc<ProxyState>>,
    challenge_info: ChallengeInfo<'_>,
) -> Response {
    let new_challenge = match create_and_store_challenge(&state, challenge_info).await {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let encoded_challenge = match serde_json::to_string(&new_challenge) {
        Ok(json) => json,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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

    // TODO mikel: extract headers.
    let response = match Response::builder()
        .header("Content-Type", "text/html")
        .header("Cache-Control", "no-store")
        .body(Body::from(body))
    {
        Ok(response) => response,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    response
}

async fn create_and_store_challenge(
    state: &ProxyState,
    challenge_info: ChallengeInfo<'_>,
) -> Result<Challenge, StoreError> {
    let now = Timestamp::now(NoContext);
    let id = Uuid::new_v7(now);
    let difficulty = state.challenge_service.challenge_config.difficulty;
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

fn create_metadata(challenge_info: ChallengeInfo<'_>) -> BTreeMap<CompactString, CompactString> {
    let mut metadata: BTreeMap<CompactString, CompactString> = BTreeMap::new();

    metadata.insert(HEADER_IP.into(), challenge_info.identity);
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

pub async fn serve_wasm() -> Response {
    WASM_RESPONSE.into_response()
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
    ConnectInfo(addr): ConnectInfo<ClientAddr>,
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

    let identity = get_identity(&headers, &addr);
    let token = match state.challenge_service.token_service.mint(
        &identity,
        state.challenge_service.challenge_config.ttl.as_secs(),
    ) {
        Ok(t) => t,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let token_preview = &token[..token.len().min(30)];
    debug!(
        identity = %identity,
        token_preview = %token_preview,
        redir = %final_redir,
        "pass_challenge: minted token, setting cookie and redirecting"
    );

    let cookie = Cookie::build((COOKIE_NAME, token))
        .path(ROOT)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    (jar.add(cookie), Redirect::to(final_redir)).into_response()
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
