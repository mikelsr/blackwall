pub(crate) fn setup() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("ring crypto provider should install once");
}
