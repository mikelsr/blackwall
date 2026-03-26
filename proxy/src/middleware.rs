use crate::ProxyState;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use shared::challenge;
use std::sync::Arc;

// TODO mikel: ergonomics
pub async fn challenge_middleware(
    State(state): State<Arc<ProxyState>>,
    cookie_jar: CookieJar,
    req: Request<Body>,
    next: Next,
) -> Response {
    let mut authenticated = false;
    if let Some(cookie) = cookie_jar.get(challenge::COOKIE_NAME) {
        if let Some(claims) = state.token_service.verify(cookie.value()) {
            // TODO mikel: verify IP matches claims.sub
            authenticated = true;
        }
    }

    if !authenticated {
        // TODO mikel: serve challenge
    }
    next.run(req).await
}
