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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct AlwaysVerified;

    #[async_trait]
    impl DnsVerifier for AlwaysVerified {
        async fn verify_fcrdns(
            &self,
            _address: IpAddr,
            _hostname_pattern: &Regex,
        ) -> Result<bool, DnsVerificationError> {
            // TODO mikel: actually verify it
            Ok(true)
        }
    }

    #[tokio::test]
    async fn verifier_is_async_and_object_safe() {
        let verifier: Box<dyn DnsVerifier> = Box::new(AlwaysVerified);
        let pattern = Regex::new(r"^crawler\.example$").unwrap();

        assert!(
            verifier
                .verify_fcrdns(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), &pattern,)
                .await
                .unwrap()
        );
    }
}
