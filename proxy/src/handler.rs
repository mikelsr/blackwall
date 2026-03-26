use crate::ProxyState;
use crate::embed::{CHALLENGE_DECLARATION, HTML_PREFIX, HTML_SUFFIX, WIGGLE_ROOM};
use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use hyper::StatusCode;
use rand::{Rng, rng};
use serde_json;
use shared::{
    challenge::{COOKIE_NAME, Challenge, ChallengeRecord},
    store::StoreError,
};
use std::sync::Arc;
use std::time::SystemTime;
use uuid::{NoContext, Timestamp, Uuid};

// TODO mikel: ergonomics
pub async fn challenge_middleware(
    State(state): State<Arc<ProxyState>>,
    cookie_jar: CookieJar,
    req: Request<Body>,
    next: Next,
) -> Response {
    let mut authenticated = false;
    if let Some(cookie) = cookie_jar.get(COOKIE_NAME) {
        if let Some(claims) = state.challenge_service.token_service.verify(cookie.value()) {
            // TODO mikel: verify IP matches claims.sub
            authenticated = true;
        }
    }

    if !authenticated {
        // TODO mikel: serve challenge
    }
    next.run(req).await
}

pub async fn serve_challenge_page(State(state): State<Arc<ProxyState>>) -> Response {
    let new_challenge = create_and_store_challenge(&state).await;
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

async fn create_and_store_challenge(state: &ProxyState) -> Result<Challenge, StoreError> {
    let now = Timestamp::now(NoContext);
    let id = Uuid::new_v7(now);
    let difficulty = state.challenge_service.challenge_config.difficulty;
    let mut random_data = vec![0u8; 32];
    rng().fill_bytes(&mut random_data);

    let challenge = Challenge {
        id,
        random_data: Bytes::copy_from_slice(&random_data),
        difficulty,
    };

    let record = ChallengeRecord {
        id,
        issued_at: now.into(),
        metadata: todo!("metadata"),
        method: todo!("method"),
        random_data: Bytes::from_static(&random_data),
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
