use async_trait::async_trait;
use regex::Regex;
use std::{error::Error, fmt, net::IpAddr};

#[async_trait]
pub trait DnsVerifier: Send + Sync {
    async fn verify_fcrdns(
        &self,
        address: IpAddr,
        hostname_pattern: &Regex,
    ) -> Result<bool, DnsVerificationError>;
}

#[derive(Debug)]
pub struct DnsVerificationError {
    source: Box<dyn Error + Send + Sync>,
}

impl DnsVerificationError {
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for DnsVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS verification failed: {}", self.source)
    }
}

impl Error for DnsVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
