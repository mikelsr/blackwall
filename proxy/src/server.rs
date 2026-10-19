use crate::client::ClientAddr;
use axum::{Router, extract::ConnectInfo, http::Request, serve::Listener};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::pin::pin;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::ServiceExt;
use tracing::{debug, trace};

// Anubis allows 10s for headers and 2min idle; I've kept it at 2 min.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(120);

// HTTP/1 only, TCP_NODELAY enabled, attempts graceful shutdown.
pub async fn serve(mut listener: TcpListener, app: Router, shutdown: impl Future<Output = ()>) {
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(REQUEST_HEAD_TIMEOUT);

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut shutdown = pin!(shutdown);

    loop {
        let (stream, addr) = tokio::select! {
            accepted = Listener::accept(&mut listener) => accepted,
            () = &mut shutdown => break,
        };

        if let Err(err) = stream.set_nodelay(true) {
            debug!(error = %err, "failed to set TCP_NODELAY");
        }

        let client = ConnectInfo(ClientAddr::Tcp(addr));
        let service = app
            .clone()
            .map_request(move |mut request: Request<Incoming>| {
                request.extensions_mut().insert(client.clone());
                request
            });
        let connection = builder
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
            .with_upgrades();
        let mut shutdown_rx = shutdown_rx.clone();

        tokio::spawn(async move {
            let mut connection = pin!(connection);
            let result = tokio::select! {
                result = connection.as_mut() => result,
                _ = shutdown_rx.changed() => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            };
            if let Err(err) = result {
                trace!(error = %err, "connection closed with error");
            }
        });
    }

    drop(listener);
    let _ = shutdown_tx.send(());
    drop(shutdown_rx);
    shutdown_tx.closed().await;
}
