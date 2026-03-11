use axum::http::{HeaderMap, header};
use smallvec::SmallVec;

pub(crate) const X_FORWARDED_FOR: &str = "x-forwarded-for";
pub(crate) const X_REAL_IP: &str = "x-real-ip";
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
                        return Some(name);
                    }
                    Some(name)
                })
            })
        })
        .collect()
}
