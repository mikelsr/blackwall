use crate::store::StoreError;
use challenge::PowHashAlgorithm;
use std::{collections::BTreeMap, time::SystemTime};
use uuid::Uuid;

use bytes::Bytes;
use compact_str::CompactString;
use serde;

pub const STATIC_PREFIX: &str = "/.within.website/x/cmd/anubis/";
pub const API_PREFIX: &str = "/.within.website/x/cmd/anubis/api/";
pub const PASS_CHALLENGE_PATH: &str = "/.within.website/x/cmd/anubis/api/pass-challenge";
pub const CHECK_PATH: &str = "/.within.website/x/cmd/anubis/api/check";
pub const COOKIE_NAME: &str = "b7l.net";
pub const TEST_COOKIE_NAME: &str = "b7l.net-anubis-cookie-verification";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    #[serde(rename = "randomData")]
    pub random_data: Bytes,
    pub difficulty: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Solution {
    pub id: Uuid,
    #[serde(rename = "randomData")]
    pub nonce: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChallengeRecord {
    #[serde(rename = "issuedAt")]
    pub issued_at: SystemTime,
    pub metadata: BTreeMap<CompactString, CompactString>,
    pub id: Uuid,
    pub method: CompactString, // I expect them to always fit in a CompactString
    #[serde(rename = "randomData")]
    pub random_data: Bytes,
    pub difficulty: u32,
    pub spent: bool,
}

#[derive(Debug)]
pub enum ConsumeError {
    NotFound,
    AlreadyConsumed,
    Store(StoreError),
}

#[async_trait::async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn insert(
        &self,
        record: ChallengeRecord,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError>;
    async fn consume_once(&self, id: &Uuid) -> Result<ChallengeRecord, ConsumeError>;
}

pub async fn verify_solution(
    repo: &dyn ChallengeRepository,
    solution: &Solution,
) -> Result<(), VerificationError> {
    let record = repo
        .consume_once(&solution.id)
        .await
        .map_err(VerificationError::Consume)?;

    let hash = challenge::Sha256Pow::digest(&record.random_data, solution.nonce);

    if !challenge::check_difficulty(&hash, record.difficulty) {
        return Err(VerificationError::InvalidSolution);
    }

    Ok(())
}

pub enum VerificationError {
    InvalidSolution,
    Consume(ConsumeError),
}

pub mod memory {

    use crate::challenge::{ChallengeRecord, ChallengeRepository, ConsumeError};
    use crate::store::StoreError;
    use async_trait::async_trait;
    use dashmap::DashMap;
    use rustc_hash::FxHasher;
    use std::collections::VecDeque;
    use std::default::Default;
    use std::hash::BuildHasherDefault;
    use std::sync::{Arc, Weak};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::Instant;
    use uuid::Uuid;

    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

    // A DashMap with FxHasher for fast key lookups.
    // The idea is to have a scaling concurrent map with non-cryptographic hashing.
    type DashFxMap<K, V> = DashMap<K, V, BuildHasherDefault<FxHasher>>;

    pub struct MemoryChallengeRepository {
        inner: Arc<Inner>,
        cleanup_tx: mpsc::UnboundedSender<Expiry>,
    }

    struct Inner {
        map: DashFxMap<Uuid, Entry>,
    }

    pub struct Entry {
        record: ChallengeRecord,
        expires_at: Instant,
    }

    struct Expiry {
        challenge_id: Uuid,
        expires_at: Instant,
    }

    impl MemoryChallengeRepository {
        pub fn new() -> Self {
            let (tx, rx) = mpsc::unbounded_channel();
            let inner = Arc::new(Inner {
                map: DashFxMap::default(),
            });

            Self::start_expiration(Arc::downgrade(&inner), rx, CLEANUP_INTERVAL);

            Self {
                inner,
                cleanup_tx: tx,
            }
        }

        /// Spawns a background task that periodically checks the
        /// cleanup queue and removes expired entries.
        fn start_expiration(
            weak_state: Weak<Inner>,
            mut rx: mpsc::UnboundedReceiver<Expiry>,
            interval: Duration,
        ) {
            tokio::spawn(async move {
                let mut local_queue: VecDeque<Expiry> = VecDeque::new();
                let mut cleanup_timer = tokio::time::interval(interval);

                loop {
                    tokio::select! {
                        // Receive new cleanup tasks.
                        Some(item) = rx.recv() => {
                            local_queue.push_back(item);
                        }
                        // Periodically cleanup expired items.
                        _ = cleanup_timer.tick() => {
                            let Some(state) = weak_state.upgrade() else {
                                break;
                            };

                            let now = Instant::now();
                            while let Some(expiry) = local_queue.front() {
                                if expiry.expires_at <= now {
                                    let id = expiry.challenge_id;
                                    local_queue.pop_front();
                                    state.map.remove(&id);
                                } else {
                                    break;
                                }
                            }
                        }
                        else => break,
                    }
                }
            });
        }
    }

    impl Default for MemoryChallengeRepository {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl ChallengeRepository for MemoryChallengeRepository {
        async fn insert(&self, record: ChallengeRecord, ttl: Duration) -> Result<(), StoreError> {
            let expires_at = Instant::now() + ttl;
            let id = record.id;
            // Insert into the sharded map.
            self.inner.map.insert(id, Entry { record, expires_at });
            // Register for cleanup.
            let _ = self.cleanup_tx.send(Expiry {
                challenge_id: id,
                expires_at: expires_at,
            });
            Ok(())
        }

        async fn consume_once(&self, id: &Uuid) -> Result<ChallengeRecord, ConsumeError> {
            match self.inner.map.remove(id) {
                Some((_, entry)) => {
                    if entry.expires_at > Instant::now() {
                        Ok(entry.record)
                    } else {
                        Err(ConsumeError::NotFound)
                    }
                }
                None => Err(ConsumeError::NotFound),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use bytes::Bytes;
        use std::collections::BTreeMap;
        use std::time::SystemTime;
        use tokio::time::{advance, pause, sleep};

        fn mock_record(id: Uuid) -> ChallengeRecord {
            ChallengeRecord {
                issued_at: SystemTime::now(),
                metadata: BTreeMap::new(),
                id,
                method: "sha256".into(),
                random_data: Bytes::from_static(b"test_data"),
                difficulty: 1,
                spent: false,
            }
        }

        #[tokio::test]
        async fn test_memory_repo_insert_and_consume() {
            let repo = MemoryChallengeRepository::new();
            let id = Uuid::now_v7();
            let record = mock_record(id);

            repo.insert(record, Duration::from_secs(60))
                .await
                .expect("insert failed");

            let consumed = repo.consume_once(&id).await.expect("consume failed");

            assert_eq!(consumed.id, id);
            assert_eq!(consumed.random_data, Bytes::from_static(b"test_data"));
        }

        #[tokio::test]
        async fn test_memory_repo_consume_is_atomic() {
            let repo = MemoryChallengeRepository::new();
            let id = Uuid::now_v7();
            let record = mock_record(id);

            repo.insert(record, Duration::from_secs(60)).await.unwrap();

            // First consumption succeeds
            assert!(repo.consume_once(&id).await.is_ok());

            // Second consumption fails (it was removed)
            let second = repo.consume_once(&id).await;
            assert!(matches!(second, Err(ConsumeError::NotFound)));
        }

        #[tokio::test]
        async fn test_memory_repo_expiration_logic() {
            pause(); // Control time
            let repo = MemoryChallengeRepository::new();
            let id = Uuid::now_v7();
            let record = mock_record(id);

            // Insert with 1s TTL
            repo.insert(record, Duration::from_secs(1)).await.unwrap();

            // Advance time by 2s
            advance(Duration::from_secs(2)).await;

            // Should be expired
            let result = repo.consume_once(&id).await;
            assert!(matches!(result, Err(ConsumeError::NotFound)));
        }

        #[tokio::test]
        async fn test_expiration_task() {
            pause();
            let repo = MemoryChallengeRepository::new();
            let id = Uuid::now_v7();
            let record = mock_record(id);

            // Insert with very short TTL
            repo.insert(record, Duration::from_millis(100))
                .await
                .unwrap();

            // Advance time past the CLEANUP_INTERVAL (10s)
            for _ in 0..11 {
                advance(Duration::from_secs(1)).await;
                // yield_now is not always enough to trigger background task in mock time
                // sometimes we need to sleep for a tiny bit of mock time
                sleep(Duration::from_millis(1)).await;
            }

            // The janitor should have run.
            // We verify by checking that the map no longer contains the ID.
            assert!(repo.inner.map.is_empty());
        }

        #[tokio::test]
        async fn test_concurrent_access_safety() {
            let repo = Arc::new(MemoryChallengeRepository::new());
            let mut handles = Vec::new();

            for _i in 0..100 {
                let r = repo.clone();
                handles.push(tokio::spawn(async move {
                    let id = Uuid::now_v7();
                    let record = mock_record(id);
                    r.insert(record, Duration::from_secs(60)).await.unwrap();
                    let _ = r.consume_once(&id).await.unwrap();
                }));
            }

            for h in handles {
                h.await.unwrap();
            }

            assert!(repo.inner.map.is_empty());
        }
    }
}
