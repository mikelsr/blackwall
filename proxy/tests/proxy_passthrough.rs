use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::any,
};
use proxy::client::ClientAddr;
use shared::config::{
    BasePrefix, ChallengeConfig, PathRewriteConfig, ProxyConfig, Target,
    proxy::ForwardedHeadersConfig,
};
use shared::policy::PolicyEngine;

use std::sync::Once;
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

static RUSTLS_PROVIDER: Once = Once::new();

const BASE_PREFIX: &str = "/app";
const HOST_OVERRIDE: &str = "example.internal";
const BODY_TEXT: &str = "hello";
const PRIVATE_IP: &str = "10.0.0.1";
const LOOPBACK_IP: &str = "127.0.0.1";
const PUBLIC_IP: &str = "198.51.100.42";

struct TestHarness {
    client: reqwest::Client,
    proxy_base: String,
}

impl TestHarness {
    async fn new(proxy_config: ProxyConfig, forwarded_config: ForwardedHeadersConfig) -> Self {
        install_rustls_provider();

        let upstream_base = spawn_server(upstream_app()).await;

        let config = ProxyConfig {
            target: Target::Http(Url::parse(&upstream_base).unwrap()),
            ..proxy_config
        };

        let policy_engine = PolicyEngine::new(Vec::new(), Vec::new(), config.challenge.difficulty);

        let app = proxy::build_router(
            proxy::RuntimeMode::new(config, policy_engine).unwrap(),
            forwarded_config,
        );
        let proxy_base = spawn_server(app).await;

        Self {
            client: reqwest::Client::new(),
            proxy_base,
        }
    }
}

fn proxy_config() -> ProxyConfig {
    ProxyConfig {
        target: Target::Disabled,
        target_host: None,
        target_sni: None,
        insecure_skip_verify: false,
        disable_keepalive: false,
        use_remote_address: false,
        xff_strip_private: true,
        path_rewrite: None,
        challenge: ChallengeConfig::parse(10, Duration::from_secs(30), None, false, None).unwrap(),
    }
}

fn forwarded_config() -> ForwardedHeadersConfig {
    ForwardedHeadersConfig {
        xff_strip_private: true,
        use_remote_address: false,
    }
}

fn upstream_app() -> Router {
    Router::new().fallback(any(echo))
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("ring crypto provider should install once");
    });
}

async fn spawn_server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientAddr>(),
        )
        .await
        .unwrap();
    });

    format!("http://{addr}")
}

async fn echo(req: Request<Body>) -> impl IntoResponse {
    let (parts, body) = req.into_parts();
    let body = to_bytes(body, usize::MAX).await.unwrap();

    let host = header_text(&parts.headers, header::HOST);
    let xff = header_text(&parts.headers, proxy::headers::X_FORWARDED_FOR);
    let xri = header_text(&parts.headers, proxy::headers::X_REAL_IP);

    (
        StatusCode::OK,
        format!(
            "method={}\npath={}\nhost={}\nxff={}\nxri={}\nbody={}",
            parts.method,
            parts.uri,
            host,
            xff,
            xri,
            String::from_utf8_lossy(&body),
        ),
    )
}

fn header_text<K>(headers: &axum::http::HeaderMap, name: K) -> String
where
    K: axum::http::header::AsHeaderName,
{
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

fn response_value<'a>(body: &'a str, key: &str) -> &'a str {
    body.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .unwrap_or("")
}

#[tokio::test]
async fn proxies_method_path_query_and_body() {
    let harness = TestHarness::new(proxy_config(), forwarded_config()).await;

    let body = harness
        .client
        .post(format!("{}/submit?x=1", harness.proxy_base))
        .body(BODY_TEXT)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(body.contains("method=POST"));
    assert!(body.contains("path=/submit?x=1"));
    assert!(body.contains(&format!("body={BODY_TEXT}")));
}

#[tokio::test]
async fn target_host_overrides_outbound_host_header() {
    let mut config = proxy_config();
    config.target_host = Some(HOST_OVERRIDE.to_owned());

    let harness = TestHarness::new(config, forwarded_config()).await;

    let body = harness
        .client
        .get(format!("{}/hello", harness.proxy_base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(response_value(&body, "host"), HOST_OVERRIDE);
}

#[tokio::test]
async fn strip_base_prefix_rewrites_path_before_forwarding() {
    let mut config = proxy_config();
    config.path_rewrite = Some(PathRewriteConfig {
        base_prefix: Some(BasePrefix::parse(BASE_PREFIX.to_owned()).unwrap().unwrap()),
        strip_base_prefix: true,
    });

    let harness = TestHarness::new(config, forwarded_config()).await;

    let body = harness
        .client
        .get(format!("{}{BASE_PREFIX}/hello?x=1", harness.proxy_base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(response_value(&body, "path"), "/hello?x=1");
}

#[tokio::test]
async fn strips_private_xff_and_uses_surviving_public_ip_for_x_real_ip() {
    let harness = TestHarness::new(proxy_config(), forwarded_config()).await;

    let body = harness
        .client
        .get(format!("{}/hello", harness.proxy_base))
        .header(
            proxy::headers::X_FORWARDED_FOR,
            format!("{PRIVATE_IP}, {PUBLIC_IP}"),
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(response_value(&body, "xff"), PUBLIC_IP);
    assert_eq!(response_value(&body, "xri"), PUBLIC_IP);
}

#[tokio::test]
async fn removes_xff_when_every_hop_is_filtered_out() {
    let harness = TestHarness::new(proxy_config(), forwarded_config()).await;

    let body = harness
        .client
        .get(format!("{}/hello", harness.proxy_base))
        .header(
            proxy::headers::X_FORWARDED_FOR,
            HeaderValue::from_str(&format!("{PRIVATE_IP}, {LOOPBACK_IP}")).unwrap(),
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(response_value(&body, "xff"), "");
    assert_eq!(response_value(&body, "xri"), "");
}
