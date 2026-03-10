mod config;

use axum::serve;
use server::build_router;

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

    let app = build_router();

    let listener = tokio::net::TcpListener::bind(&cfg.listener.bind).await?;
    serve(listener, app).await?;

    Ok(())
}
