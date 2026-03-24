use crate::store::StoreError;
use std::{collections::BTreeMap, time::SystemTime};
use uuid::Uuid;

use compact_str::CompactString;
use serde;

pub const STATIC_PREFIX: &str = "/.within.website/x/cmd/anubis/";
pub const API_PREFIX: &str = "/.within.website/x/cmd/anubis/api/";
pub const PASS_CHALLENGE_PATH: &str = "/.within.website/x/cmd/anubis/api/pass-challenge";
pub const CHECK_PATH: &str = "/.within.website/x/cmd/anubis/api/check";
pub const COOKIE_NAME: &str = "techaro.lol-anubis";
pub const TEST_COOKIE_NAME: &str = "techaro.lol-anubis-cookie-verification";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChallengeRecord {
    #[serde(rename = "issuedAt")]
    pub issued_at: SystemTime,
    pub metadata: BTreeMap<CompactString, CompactString>,
    pub id: Uuid,
    pub method: CompactString, // I expect them to always fit in a CompactString
    #[serde(rename = "randomData")]
    pub random_data: String,
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
pub trait ChallengeRepository {
    async fn insert(
        &self,
        record: &ChallengeRecord,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError>;
    async fn consume_once(&self, id: &Uuid) -> Result<ChallengeRecord, ConsumeError>;
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
    use std::sync::{Arc, Mutex, Weak};
    use std::time::{Duration, Instant};
    use tokio::time::sleep;
    use uuid::Uuid;

    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

    // A DashMap with FxHasher for fast key lookups.
    type DashFxMap<K, V> = DashMap<K, V, BuildHasherDefault<FxHasher>>;

    pub struct MemoryChallengeRepository {
        inner: Arc<Inner>,
    }

    struct Inner {
        map: DashFxMap<Uuid, Entry>,
        cleanup_queue: Mutex<VecDeque<(Instant, Uuid)>>,
    }

    pub struct Entry {
        record: ChallengeRecord,
        expires_at: Instant,
    }

    impl MemoryChallengeRepository {
        pub fn new() -> Self {
            let inner = Arc::new(Inner {
                map: DashFxMap::default(),
                cleanup_queue: Mutex::new(VecDeque::new()),
            });

            Self::start_expiration(Arc::downgrade(&inner), CLEANUP_INTERVAL);

            Self { inner }
        }

        /// Spawns a background task that periodically checks the
        /// cleanup queue and removes expired entries.
        fn start_expiration(weak_state: Weak<Inner>, interval: Duration) {
            tokio::spawn(async move {
                while let Some(state) = weak_state.upgrade() {
                    sleep(interval).await;

                    let now = Instant::now();
                    let mut expired_ids = Vec::new();

                    {
                        let mut queue = state.cleanup_queue.lock().unwrap();
                        while let Some((expiry, id)) = queue.front() {
                            if *expiry <= now {
                                expired_ids.push(*id);
                                queue.pop_front();
                            } else {
                                break;
                            }
                        }
                    }

                    for id in expired_ids {
                        state.map.remove(&id);
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
        async fn insert(&self, record: &ChallengeRecord, ttl: Duration) -> Result<(), StoreError> {
            let expires_at = Instant::now() + ttl;
            // Insert into the sharded map.
            self.inner.map.insert(
                record.id,
                Entry {
                    record: record.clone(),
                    expires_at,
                },
            );
            // Register for cleanup.
            self.inner
                .cleanup_queue
                .lock()
                .unwrap()
                .push_back((expires_at, record.id));
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
}
