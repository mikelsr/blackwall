use http::HeaderMap;
use std::net::IpAddr;

pub struct PolicyRequest<'a> {
    pub remote_address: IpAddr,
    pub content_length: Option<u64>,
    pub method: &'a str,
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub query: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub headers: &'a HeaderMap,
}
