use crate::headers;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use hyper::upgrade::OnUpgrade;
use tokio::io::copy_bidirectional;
use tracing::debug;

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

    debug!("upgrade relay established");

    let mut client = hyper_util::rt::TokioIo::new(client);
    let mut target = hyper_util::rt::TokioIo::new(target);

    match copy_bidirectional(&mut client, &mut target).await {
        Ok((client_to_target_bytes, target_to_client_bytes)) => {
            debug!(
                client_to_target_bytes,
                target_to_client_bytes, "upgrade relay finished"
            );
        }
        Err(err) => {
            debug!(error = %err, "upgrade relay closed with I/O error");
        }
    }

    Ok(())
}
