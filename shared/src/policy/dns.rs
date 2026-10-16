use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    proto::rr::{Name, RData},
};
use regex::Regex;
use std::{error::Error, fmt, net::IpAddr};

const DOT: &str = ".";

#[async_trait]
pub trait DnsVerifier: Send + Sync {
    async fn verify_fcrdns(&self, address: IpAddr, hostname_pattern: &Regex) -> bool;
}

#[derive(Clone)]
pub struct HickoryDnsVerifier {
    resolver: TokioResolver,
}

impl HickoryDnsVerifier {
    pub fn new() -> Result<Self, DnsVerificationError> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(DnsVerificationError::new)?
            .build()
            .map_err(DnsVerificationError::new)?;

        Ok(Self { resolver })
    }
}

#[async_trait]
impl DnsVerifier for HickoryDnsVerifier {
    async fn verify_fcrdns(&self, address: IpAddr, hostname_pattern: &Regex) -> bool {
        let ptr_records = match self.resolver.reverse_lookup(Name::from(address)).await {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%address, %error, "reverse DNS lookup failed");
                return false;
            }
        };

        for record in ptr_records.answers() {
            let RData::PTR(name) = &record.data else {
                continue;
            };

            let hostname = name.to_string();
            let hostname = hostname.strip_suffix(DOT).unwrap_or(&hostname);

            if !hostname_pattern.is_match(hostname) {
                continue;
            }

            let forward_records = match self.resolver.lookup_ip(format!("{hostname}.")).await {
                Ok(records) => records,
                Err(error) => {
                    tracing::warn!(
                        %hostname,
                        %error,
                        "DNS lookup failed"
                    );
                    continue;
                }
            };

            if forward_records.iter().any(|candidate| candidate == address) {
                return true;
            }
        }

        false
    }
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
