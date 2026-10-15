use cel::{Context, Program, Value};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;

const CEL_AND: &str = " && ";
const CEL_OR: &str = " || ";

const CEL_REMOTE_ADDRESS: &str = "remoteAddress";
const CEL_CONTENT_LENGTH: &str = "contentLength";
const CEL_USER_AGENT: &str = "userAgent";
const CEL_HOST: &str = "host";
const CEL_METHOD: &str = "method";
const CEL_PATH: &str = "path";
const CEL_QUERY: &str = "query";
const CEL_HEADERS: &str = "headers";
const CEL_LOAD_1M: &str = "load_1m";
const CEL_LOAD_5M: &str = "load_5m";
const CEL_LOAD_15M: &str = "load_15m";

const CEL_REMOTE_ADDRESS_DEFAULT: &str = "127.0.0.1";
const CEL_CONTENT_LENGTH_DEFAULT: i64 = 0;
const CEL_USER_AGENT_DEFAULT: &str = "Mozilla/5.0";
const CEL_HOST_DEFAULT: &str = "example.test";
const CEL_METHOD_DEFAULT: &str = "GET";
const CEL_PATH_DEFAULT: &str = "/";
const CEL_LOAD_1M_DEFAULT: f64 = 0.0;
const CEL_LOAD_5M_DEFAULT: f64 = 0.0;
const CEL_LOAD_15M_DEFAULT: f64 = 0.0;

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

    pub(crate) fn validate_cel(&self) -> Result<(), CelValidationError> {
        let source = self.as_cel();
        let program = Program::compile(source.as_ref()).map_err(CelValidationError::Parse)?;
        let mut context = Context::default();

        context
            .add_variable(CEL_REMOTE_ADDRESS, CEL_REMOTE_ADDRESS_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_CONTENT_LENGTH, CEL_CONTENT_LENGTH_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_USER_AGENT, CEL_USER_AGENT_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_HOST, CEL_HOST_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_METHOD, CEL_METHOD_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_PATH, CEL_PATH_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_QUERY, HashMap::<String, String>::new())
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_HEADERS, HashMap::<String, String>::new())
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_LOAD_1M, CEL_LOAD_1M_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_LOAD_5M, CEL_LOAD_5M_DEFAULT)
            .map_err(CelValidationError::Binding)?;
        context
            .add_variable(CEL_LOAD_15M, CEL_LOAD_15M_DEFAULT)
            .map_err(CelValidationError::Binding)?;

        match program
            .execute(&context)
            .map_err(CelValidationError::Evaluation)?
        {
            Value::Bool(_) => Ok(()),
            _ => Err(CelValidationError::NonBooleanResult),
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

#[derive(Debug)]
pub enum CelValidationError {
    Parse(cel::ParseErrors),
    Binding(cel::SerializationError),
    Evaluation(cel::ExecutionError),
    NonBooleanResult,
}

impl fmt::Display for CelValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(source) => write!(f, "invalid CEL syntax: {source}"),
            Self::Binding(source) => write!(f, "failed to bind CEL validation value: {source}"),
            Self::Evaluation(source) => write!(f, "invalid CEL expression: {source}"),
            Self::NonBooleanResult => write!(f, "CEL expression must return a boolean"),
        }
    }
}

impl std::error::Error for CelValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(source) => Some(source),
            Self::Binding(source) => Some(source),
            Self::Evaluation(source) => Some(source),
            Self::NonBooleanResult => None,
        }
    }
}
