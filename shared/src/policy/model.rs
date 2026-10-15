use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;

const CEL_AND: &str = " && ";
const CEL_OR: &str = " || ";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Allow,
    Deny,
    Challenge,
    Weigh,
    DebugBenchmark,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ChallengeRules {
    pub algorithm: Option<String>,
    pub difficulty: Option<u32>,
    pub report_as: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Weight {
    #[serde(default)]
    pub adjust: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expression {
    Simple(String),
    All { all: Vec<String> },
    Any { any: Vec<String> },
}

impl Expression {
    pub fn as_cel(&self) -> Cow<'_, str> {
        match self {
            Self::Simple(expr) => Cow::Borrowed(expr),
            Self::All { all } => Cow::Owned(
                all.iter()
                    .map(|expr| format!("({expr})"))
                    .collect::<Vec<_>>()
                    .join(CEL_AND),
            ),
            Self::Any { any } => Cow::Owned(
                any.iter()
                    .map(|expr| format!("({expr})"))
                    .collect::<Vec<_>>()
                    .join(CEL_OR),
            ),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoIp {
    #[serde(default)]
    pub countries: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Asns {
    #[serde(default, rename = "match")]
    pub matches: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: CompactString,
    pub action: Action,
    #[serde(default)]
    pub user_agent_regex: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub headers_regex: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "remote_addresses")]
    pub remote_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub expression: Option<Expression>,
    #[serde(default)]
    pub challenge: Option<ChallengeRules>,
    #[serde(default)]
    pub weight: Option<Weight>,
    #[serde(default, rename = "geoip")]
    pub geo_ip: Option<GeoIp>,
    #[serde(default)]
    pub asns: Option<Asns>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Threshold {
    pub(crate) name: CompactString,
    pub(crate) expression: Expression,
    pub(crate) action: Action,
    #[serde(default)]
    pub(crate) challenge: Option<ChallengeRules>,
}
