mod config;

use axum::serve;
use server::build_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = match config::load_config()? {
        config::StartupMode::Version => {
            println!("Blackwall v{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        config::StartupMode::Healthcheck => {
            println!("healthcheck not implemented yet");
            return Ok(());
        }
        config::StartupMode::Serve(cfg) => cfg,
    };

    let app = build_router();

    let listener = tokio::net::TcpListener::bind(&cfg.listener.bind).await?;
    serve(listener, app).await?;

    Ok(())
}
