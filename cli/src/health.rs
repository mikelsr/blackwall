use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum HealthStatus {
    Unknown = 0,
    NotServing = 1,
    Serving = 2,
}

impl HealthStatus {
    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::NotServing,
            2 => Self::Serving,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug)]
pub(crate) struct HealthState(AtomicU8);

impl HealthState {
    pub(crate) fn new(status: HealthStatus) -> Self {
        Self(AtomicU8::new(status.code()))
    }
    pub(crate) fn set(&self, status: HealthStatus) {
        self.0.store(status.code(), Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> HealthStatus {
        HealthStatus::from_code(self.0.load(Ordering::Relaxed))
    }
}

pub(crate) mod check {
    use reqwest::StatusCode;
    use std::io;

    pub async fn run(metrics_bind: &str) -> io::Result<()> {
        let url = healthcheck_url(metrics_bind);
        let resp = reqwest::get(&url)
            .await
            .map_err(|error| io::Error::other(format_fetch_error(&url, &error)))?;

        if resp.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "unexpected status code: {}",
                resp.status().as_u16()
            )));
        }

        Ok(())
    }

    fn healthcheck_url(metrics_bind: &str) -> String {
        format!("http://localhost{metrics_bind}/healthz")
    }

    fn format_fetch_error(url: &str, error: &reqwest::Error) -> String {
        format!(r#"failed to fetch metrics: Get "{url}": {error}"#)
    }
}
