mod config;

use axum::serve;
use server::build_router;

#[tokio::main]
async fn main() {
    let cfg = config::load_config().unwrap();

    // build our application with a single route
    let app = build_router();

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(cfg.listener.bind)
        .await
        .unwrap();
    serve(listener, app).await.unwrap();
}
