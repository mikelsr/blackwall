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
