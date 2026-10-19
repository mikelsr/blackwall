mod config;
mod health;
mod log;
mod metrics;
mod tls;

use proxy::{RuntimeMode, build_router};
use shared::config::{BindNetwork, proxy as proxy_config};
use std::process::exit;
use std::sync::Arc;
use tokio::{select, signal};
use tracing::{debug, error, info, warn};

const APP_VERSION: &str = match option_env!("B7L_VERSION") {
    Some(v) => v,
    None => "devel",
};

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let (cfg, policy_engine) = match config::load_config()? {
        config::StartupMode::Version => {
            println!("Blackwall {APP_VERSION}");
            return Ok(());
        }
        config::StartupMode::Healthcheck(health_cfg) => {
            println!("running healthcheck");
            if let Err(err) = health::check::run(&health_cfg.metrics_bind).await {
                eprintln!("{err}");
                exit(1);
            }
            return Ok(());
        }
        config::StartupMode::Run {
            config,
            policy_engine,
        } => (*config, policy_engine),
    };

    log::init();

    debug!(target = %cfg.proxy.target, "proxy target");
    debug!(
        difficulty = cfg.proxy.challenge.difficulty,
        ttl = ?cfg.proxy.challenge.ttl,
        cookie_secure = cfg.proxy.challenge.cookie_secure,
        "challenge config"
    );
    if let Some(ref rewrite) = cfg.proxy.path_rewrite {
        debug!(
            base_prefix = ?rewrite.base_prefix,
            strip = rewrite.strip_base_prefix,
            "path rewrite"
        );
    }
    debug!(
        use_remote_address = cfg.proxy.use_remote_address,
        xff_strip_private = cfg.proxy.xff_strip_private,
        "forwarded headers"
    );

    // Install the ring crypto provider as the default TLS provider,
    // it seems it needs to be invoked explicitly.
    tls::setup();

    let bind = cfg.listener.bind.clone();

    let forwarded_config = proxy_config::ForwardedHeadersConfig {
        xff_strip_private: cfg.proxy.xff_strip_private,
        use_remote_address: cfg.proxy.use_remote_address,
    };

    if cfg.proxy.insecure_skip_verify {
        warn!("target TLS verification is disabled");
    }

    if cfg.proxy.disable_keepalive {
        info!("target keep-alive is disabled");
    }

    let mode = RuntimeMode::new(cfg.proxy, policy_engine)?;
    let mode_name = mode.name();
    let app = build_router(mode, forwarded_config);

    let health_state = Arc::new(health::HealthState::new(health::HealthStatus::NotServing));
    spawn_metrics_server(&cfg.metrics, health_state.clone());

    let listener = bind_tcp_listener(&bind).await?;
    health_state.set(health::HealthStatus::Serving);

    info!(version = APP_VERSION, bind = %bind, mode = mode_name, "starting blackwall");

    proxy::server::serve(listener, app, async {
        if let Err(err) = shutdown_signal().await {
            error!(error = %err, "shutdown signal error");
        }
    })
    .await;

    info!("server stopped");

    Ok(())
}

fn spawn_metrics_server(
    cfg: &shared::config::MetricsConfig,
    health_state: Arc<health::HealthState>,
) {
    if cfg.bind.is_empty() {
        return;
    }

    let metrics_app = metrics::router(health_state);
    let metrics_bind = cfg.bind.clone();
    let metrics_network = cfg.network.clone();

    tokio::spawn(async move {
        let result = match metrics_network {
            BindNetwork::Tcp => serve_metrics_tcp(&metrics_bind, metrics_app).await,
            BindNetwork::Unix => serve_metrics_unix(metrics_bind.clone(), metrics_app).await,
        };

        if let Err(err) = result {
            error!(error = %err, bind = %metrics_bind, "metrics server exited with error");
            exit(1);
        }
    });
}

async fn bind_tcp_listener(bind: &str) -> std::io::Result<tokio::net::TcpListener> {
    let normalized = normalize_tcp_bind_addr(bind);
    tokio::net::TcpListener::bind(normalized.as_str()).await
}

async fn serve_metrics_tcp(metrics_bind: &str, metrics_app: axum::Router) -> std::io::Result<()> {
    let listener = bind_tcp_listener(metrics_bind).await?;
    axum::serve(listener, metrics_app).await
}

fn normalize_tcp_bind_addr(bind: &str) -> String {
    if let Some(port) = bind.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        bind.to_owned()
    }
}

#[cfg(unix)]
async fn serve_metrics_unix(
    metrics_bind: String,
    metrics_app: axum::Router,
) -> std::io::Result<()> {
    let listener = tokio::net::UnixListener::bind(&metrics_bind)?;
    axum::serve(listener, metrics_app).await
}

#[cfg(not(unix))]
async fn serve_metrics_unix(_: String, _: axum::Router) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unix metrics-bind-network is not supported on this platform",
    ))
}

async fn shutdown_signal() -> Result<(), Box<dyn std::error::Error>> {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        select! {
            result = ctrl_c => {
                result?;
                info!("received shutdown signal (SIGINT)");
            },
            _ = sigterm.recv() => {
                info!("received shutdown signal (SIGTERM)");
            },
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await?;
        info!("received shutdown signal");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_tcp_bind_addr;

    #[test]
    fn normalizes_port_only_bind_to_unspecified_ipv4() {
        assert_eq!(normalize_tcp_bind_addr(":9090"), "0.0.0.0:9090");
    }

    #[test]
    fn keeps_host_port_bind_as_is() {
        assert_eq!(normalize_tcp_bind_addr("127.0.0.1:9090"), "127.0.0.1:9090");
        assert_eq!(normalize_tcp_bind_addr("localhost:9090"), "localhost:9090");
        assert_eq!(normalize_tcp_bind_addr("[::1]:9090"), "[::1]:9090");
    }
}
