use crate::health::{HealthState, HealthStatus};
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    routing::get,
};
use std::sync::Arc;

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const HEALTH_METRIC_PREFIX: &str = "# HELP blackwall_health_status Current health status (0=unknown, 1=not_serving, 2=serving)\n# TYPE blackwall_health_status gauge\nblackwall_health_status ";

pub(crate) fn router(state: Arc<HealthState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn healthz(State(state): State<Arc<HealthState>>) -> (StatusCode, &'static str) {
    healthz_response(state.get())
}

fn healthz_response(status: HealthStatus) -> (StatusCode, &'static str) {
    match status {
        HealthStatus::NotServing => (StatusCode::INTERNAL_SERVER_ERROR, "NOT OK\n"),
        HealthStatus::Serving => (StatusCode::OK, "OK\n"),
        HealthStatus::Unknown => (StatusCode::FAILED_DEPENDENCY, "UNKNOWN\n"),
    }
}

async fn metrics(
    State(state): State<Arc<HealthState>>,
) -> (StatusCode, [(header::HeaderName, &'static str); 1], String) {
    let body = format!(
        "{}{}\n",
        HEALTH_METRIC_PREFIX,
        health_metric_value(state.get())
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)],
        body,
    )
}

const fn health_metric_value(status: HealthStatus) -> u8 {
    match status {
        HealthStatus::Unknown => 0,
        HealthStatus::NotServing => 1,
        HealthStatus::Serving => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::{METRICS_CONTENT_TYPE, healthz, metrics};
    use crate::health::{HealthState, HealthStatus};
    use axum::{body::to_bytes, extract::State, response::IntoResponse};
    use std::sync::Arc;

    #[tokio::test]
    async fn healthz_returns_expected_status_and_body() {
        let state = Arc::new(HealthState::new(HealthStatus::NotServing));
        let (status, body) = healthz(State(state.clone())).await;
        assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "NOT OK\n");

        state.set(HealthStatus::Serving);
        let (status, body) = healthz(State(state.clone())).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "OK\n");

        state.set(HealthStatus::Unknown);
        let (status, body) = healthz(State(state)).await;
        assert_eq!(status, axum::http::StatusCode::FAILED_DEPENDENCY);
        assert_eq!(body, "UNKNOWN\n");
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text_with_health_value() {
        let state = Arc::new(HealthState::new(HealthStatus::Serving));
        let response = metrics(State(state)).await.into_response();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], METRICS_CONTENT_TYPE);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("# TYPE blackwall_health_status gauge"));
        assert!(body.contains("blackwall_health_status 2"));
    }
}
