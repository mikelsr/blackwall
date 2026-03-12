#[derive(Clone, Copy)]
pub struct ForwardedHeadersConfig {
    /// Whether to strip RFC1918 private IPs from XFF.
    /// Loopback, CGNAT, and link-local are always stripped.
    pub xff_strip_private: bool,
    /// Whether to override X-Real-IP with the remote address.
    pub use_remote_address: bool,
}
