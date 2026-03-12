mod config;

use axum::serve;
use proxy::{RuntimeMode, build_router};
use shared::config::proxy as proxy_config;
use std::net::SocketAddr;
use tokio::{select, signal};

const APP_VERSION: &str = match option_env!("B7L_VERSION") {
    Some(v) => v,
    None => "devel",
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = match config::load_config()? {
        config::StartupMode::Version => {
            println!("Blackwall {}", APP_VERSION);
            return Ok(());
        }
        config::StartupMode::Healthcheck => {
            println!("healthcheck not implemented yet");
            return Ok(());
        }
        config::StartupMode::Run(cfg) => cfg,
    };

    let bind = cfg.listener.bind.clone();

    let forwarded_config = proxy_config::ForwardedHeadersConfig {
        xff_strip_private: cfg.proxy.xff_strip_private,
        use_remote_address: cfg.proxy.use_remote_address,
    };

    let mode = RuntimeMode::from_config(cfg.proxy)?;
    let app = build_router(mode, forwarded_config);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();

    serve(listener, svc)
        .with_graceful_shutdown(async {
            if let Err(err) = shutdown_signal().await {
                eprintln!("shutdown signal error: {err}");
            }
        })
        .await?;

    Ok(())
}

async fn shutdown_signal() -> Result<(), Box<dyn std::error::Error>> {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        select! {
            result = ctrl_c => result?,
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await?;
    }

    Ok(())
}
