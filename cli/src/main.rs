use axum::serve;
use server::build_router;

#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = build_router();

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(listener, app).await.unwrap();
}
