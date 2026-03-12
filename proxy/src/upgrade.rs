use crate::headers;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use hyper::upgrade::OnUpgrade;
use tokio::io::copy_bidirectional;

pub fn requests_upgrade(req: &Request<Body>) -> bool {
    let headers = req.headers();

    if !headers.contains_key(header::UPGRADE) {
        return false;
    }

    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(headers::UPGRADE))
}

// TODO mikel: gracefully shutdown relay tasks
/// Relays data between all parties in the upgraded connection.
pub async fn upgrade_relay(
    client_upgrade: OnUpgrade,
    target_upgrade: OnUpgrade,
) -> Result<(), StatusCode> {
    let (client, target) =
        tokio::try_join!(client_upgrade, target_upgrade).map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut client = hyper_util::rt::TokioIo::new(client);
    let mut target = hyper_util::rt::TokioIo::new(target);

    let _ = copy_bidirectional(&mut client, &mut target).await;

    Ok(())
}
