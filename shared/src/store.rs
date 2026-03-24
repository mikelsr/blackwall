use bytes::Bytes;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[async_trait::async_trait]
pub trait KvStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Bytes, StoreError>;
    async fn set(&self, key: &str, val: Bytes, ttl: std::time::Duration) -> Result<(), StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
    fn is_persistent(&self) -> bool;

    async fn compare_and_swap(
        &self,
        _key: &str,
        _old: &[u8],
        _new: Bytes,
        _ttl: std::time::Duration,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }
}

#[derive(Debug)]
pub enum StoreError {
    NotFound,
    InvalidData,
    BackendUnavailable,
    Timeout,
    Other(String),
}

impl Display for StoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => write!(f, "store key not found"),
            StoreError::InvalidData => write!(f, "store returned invalid data"),
            StoreError::BackendUnavailable => write!(f, "store backend unavailable"),
            StoreError::Timeout => write!(f, "store operation timed out"),
            StoreError::Other(msg) => f.write_str(msg),
        }
    }
}

impl Error for StoreError {}
