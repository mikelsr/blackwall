mod config;
mod log;
mod tls;

use axum::serve;
use proxy::{RuntimeMode, build_router};
use shared::config::proxy as proxy_config;
use std::net::SocketAddr;
use tokio::{select, signal};
use tracing::{error, info, warn};

const APP_VERSION: &str = match option_env!("B7L_VERSION") {
    Some(v) => v,
    None => "devel",
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = match config::load_config()? {
        config::StartupMode::Version => {
            println!("Blackwall {APP_VERSION}");
            return Ok(());
        }
        config::StartupMode::Healthcheck => {
            println!("healthcheck not implemented yet");
            return Ok(());
        }
        config::StartupMode::Run(cfg) => *cfg,
    };

    log::init();

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

    let mode = RuntimeMode::from_config(cfg.proxy)?;
    let mode_name = mode.name();
    let app = build_router(mode, forwarded_config);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();

    info!(version = APP_VERSION, bind = %bind, mode = mode_name, "starting blackwall");

    let serve_result = serve(listener, svc)
        .with_graceful_shutdown(async {
            if let Err(err) = shutdown_signal().await {
                error!(error = %err, "shutdown signal error");
            }
        })
        .await;

    if let Err(err) = &serve_result {
        error!(error = %err, "server exited with error");
    }

    serve_result?;

    info!("server stopped");

    Ok(())
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
