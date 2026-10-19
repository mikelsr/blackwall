use crate::store::StoreError;
use challenge::PowHashAlgorithm;
use uuid::Uuid;

use serde;

pub const STATIC_PREFIX: &str = "/.within.website/x/cmd/anubis/";
pub const API_PREFIX: &str = "/.within.website/x/cmd/anubis/api/";
pub const PASS_CHALLENGE_PATH: &str = "/.within.website/x/cmd/anubis/api/pass-challenge";
pub const CHECK_PATH: &str = "/.within.website/x/cmd/anubis/api/check";
pub const COOKIE_NAME: &str = "b7l.net";
pub const TEST_COOKIE_NAME: &str = "b7l.net-anubis-cookie-verification";

pub const RANDOM_DATA_LEN: usize = 32;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    #[serde(rename = "randomData")]
    pub random_data: [u8; RANDOM_DATA_LEN],
    pub difficulty: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Solution {
    pub id: Uuid,
    pub nonce: u64,
}

/// What the server keeps to verify a solution. The challenge id is the store key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeRecord {
    pub random_data: [u8; RANDOM_DATA_LEN],
    pub difficulty: u32,
    pub rule_hash: u64,
}

#[derive(Debug)]
pub enum ConsumeError {
    NotFound,
    AlreadyConsumed,
    Store(StoreError),
}

#[async_trait::async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn insert(&self, id: Uuid, record: ChallengeRecord) -> Result<(), StoreError>;
    async fn consume_once(&self, id: &Uuid) -> Result<ChallengeRecord, ConsumeError>;
}

/// Consumes the challenge and checks the solution, returning what the challenge was issued for.
pub async fn verify_solution(
    repo: &dyn ChallengeRepository,
    solution: &Solution,
) -> Result<ChallengeRecord, VerificationError> {
    let record = repo
        .consume_once(&solution.id)
        .await
        .map_err(VerificationError::Consume)?;

    let hash = challenge::Sha256Pow::digest(&record.random_data, solution.nonce);

    if !challenge::check_difficulty(&hash, record.difficulty) {
        return Err(VerificationError::InvalidSolution);
    }

    Ok(record)
}

pub enum VerificationError {
    InvalidSolution,
    Consume(ConsumeError),
}

pub mod memory {
    use crate::challenge::{ChallengeRecord, ChallengeRepository, ConsumeError};
    use crate::store::StoreError;
    use async_trait::async_trait;
    use rustc_hash::FxHashMap;
    use std::collections::VecDeque;
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;
    use tokio::time::Instant;
    use uuid::Uuid;

    /// How long a client has to solve a challenge. Same as Anubis.
    pub const CHALLENGE_EXPIRY: Duration = Duration::from_secs(30 * 60);

    /// Most pending challenges kept, the oldest is dropped when full.
    pub const CHALLENGE_CAPACITY: usize = 100_000;

    pub struct MemoryChallengeRepository {
        expiry: Duration,
        capacity: usize,
        state: Mutex<State>,
    }

    #[derive(Default)]
    struct State {
        entries: FxHashMap<Uuid, Entry>,
        order: VecDeque<Uuid>, // In insertion order.
    }

    struct Entry {
        record: ChallengeRecord,
        expires_at: Instant,
    }

    impl MemoryChallengeRepository {
        pub fn new() -> Self {
            Self::with_limits(CHALLENGE_EXPIRY, CHALLENGE_CAPACITY)
        }

        fn with_limits(expiry: Duration, capacity: usize) -> Self {
            Self {
                expiry,
                capacity,
                state: Mutex::default(),
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl State {
        fn remove_expired(&mut self, now: Instant) {
            while let Some(id) = self.order.front() {
                if self
                    .entries
                    .get(id)
                    .is_some_and(|entry| entry.expires_at > now)
                {
                    break;
                }
                self.remove_oldest();
            }
        }

        fn remove_oldest(&mut self) {
            if let Some(id) = self.order.pop_front() {
                self.entries.remove(&id);
            }
        }
    }

    impl Default for MemoryChallengeRepository {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl ChallengeRepository for MemoryChallengeRepository {
        async fn insert(&self, id: Uuid, record: ChallengeRecord) -> Result<(), StoreError> {
            let now = Instant::now();
            let mut state = self.state();
            state.remove_expired(now);
            if state.order.len() >= self.capacity {
                state.remove_oldest();
            }
            let expires_at = now + self.expiry;
            state.entries.insert(id, Entry { record, expires_at });
            state.order.push_back(id);
            Ok(())
        }

        async fn consume_once(&self, id: &Uuid) -> Result<ChallengeRecord, ConsumeError> {
            match self.state().entries.remove(id) {
                Some(entry) if entry.expires_at > Instant::now() => Ok(entry.record),
                _ => Err(ConsumeError::NotFound),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use tokio::time::{advance, pause};

        fn record(difficulty: u32) -> ChallengeRecord {
            ChallengeRecord {
                random_data: [7; crate::challenge::RANDOM_DATA_LEN],
                difficulty,
                rule_hash: 1,
            }
        }

        #[tokio::test]
        async fn insert_and_consume() {
            let repo = MemoryChallengeRepository::new();
            let id = Uuid::now_v7();

            repo.insert(id, record(4)).await.unwrap();

            assert_eq!(repo.consume_once(&id).await.unwrap(), record(4));
        }

        #[tokio::test]
        async fn consumes_only_once() {
            let repo = MemoryChallengeRepository::new();
            let id = Uuid::now_v7();
            repo.insert(id, record(4)).await.unwrap();

            assert!(repo.consume_once(&id).await.is_ok());
            let second = repo.consume_once(&id).await;
            assert!(matches!(second, Err(ConsumeError::NotFound)));
        }

        #[tokio::test]
        async fn expired_challenges_are_rejected() {
            pause();
            let repo = MemoryChallengeRepository::with_limits(Duration::from_secs(1), 10);
            let id = Uuid::now_v7();
            repo.insert(id, record(4)).await.unwrap();

            advance(Duration::from_secs(2)).await;

            let result = repo.consume_once(&id).await;
            assert!(matches!(result, Err(ConsumeError::NotFound)));
        }

        #[tokio::test]
        async fn inserts_remove_expired_challenges() {
            pause();
            let repo = MemoryChallengeRepository::with_limits(Duration::from_secs(1), 10);
            repo.insert(Uuid::now_v7(), record(4)).await.unwrap();
            repo.insert(Uuid::now_v7(), record(4)).await.unwrap();

            advance(Duration::from_secs(2)).await;
            repo.insert(Uuid::now_v7(), record(4)).await.unwrap();

            let state = repo.state();
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.order.len(), 1);
        }

        #[tokio::test]
        async fn full_store_drops_the_oldest() {
            let repo = MemoryChallengeRepository::with_limits(CHALLENGE_EXPIRY, 2);
            let ids = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
            for id in ids {
                repo.insert(id, record(4)).await.unwrap();
            }

            let oldest = repo.consume_once(&ids[0]).await;
            assert!(matches!(oldest, Err(ConsumeError::NotFound)));
            assert!(repo.consume_once(&ids[1]).await.is_ok());
            assert!(repo.consume_once(&ids[2]).await.is_ok());
        }

        #[tokio::test]
        async fn consumed_ids_count_toward_capacity_until_dropped() {
            let repo = MemoryChallengeRepository::with_limits(CHALLENGE_EXPIRY, 2);
            for _ in 0..5 {
                let id = Uuid::now_v7();
                repo.insert(id, record(4)).await.unwrap();
                repo.consume_once(&id).await.unwrap();
            }

            assert!(repo.state().order.len() <= 2);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn concurrent_insert_and_consume() {
            let repo = Arc::new(MemoryChallengeRepository::new());
            let handles: Vec<_> = (0..100)
                .map(|_| {
                    let repo = repo.clone();
                    tokio::spawn(async move {
                        let id = Uuid::now_v7();
                        repo.insert(id, record(4)).await.unwrap();
                        repo.consume_once(&id).await.unwrap();
                    })
                })
                .collect();

            for handle in handles {
                handle.await.unwrap();
            }

            assert!(repo.state().entries.is_empty());
        }
    }
}
