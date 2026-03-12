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

