use cel::Program;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

const CEL_AND: &str = " && ";
const CEL_OR: &str = " || ";

pub(crate) const CEL_REMOTE_ADDRESS: &str = "remoteAddress";
pub(crate) const CEL_CONTENT_LENGTH: &str = "contentLength";
pub(crate) const CEL_USER_AGENT: &str = "userAgent";
pub(crate) const CEL_HOST: &str = "host";
pub(crate) const CEL_METHOD: &str = "method";
pub(crate) const CEL_PATH: &str = "path";
pub(crate) const CEL_QUERY: &str = "query";
pub(crate) const CEL_HEADERS: &str = "headers";

pub(crate) const RULE_CEL_VARIABLES: &[&str] = &[
    CEL_REMOTE_ADDRESS,
    CEL_CONTENT_LENGTH,
    CEL_USER_AGENT,
    CEL_HOST,
    CEL_METHOD,
    CEL_PATH,
    CEL_QUERY,
    CEL_HEADERS,
    "load_1m",
    "load_5m",
    "load_15m",
];

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

        if let Some(variable) = program
            .references()
            .variables()
            .into_iter()
            .find(|variable| !RULE_CEL_VARIABLES.contains(variable))
        {
            return Err(CelValidationError::UnknownVariable {
                variable: variable.to_owned(),
            });
        }

        Ok(())
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
    UnknownVariable { variable: String },
}

impl fmt::Display for CelValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(source) => write!(f, "invalid CEL syntax: {source}"),
            Self::UnknownVariable { variable } => {
                write!(f, "unknown CEL policy variable: {variable}")
            }
        }
    }
}

impl std::error::Error for CelValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(source) => Some(source),
            Self::UnknownVariable { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn rule_cel_validation_accepts_known_rule_variables() {
        let expression = Expression::Simple(
            r#"remoteAddress == "127.0.0.1"
                && contentLength >= 0
                && userAgent.contains("Mozilla")
                && host == "example.test"
                && method == "GET"
                && path.startsWith("/")
                && query["go-get"] == "1"
                && "Accept" in headers
                && load_1m >= 0.0
                && load_5m >= 0.0
                && load_15m >= 0.0"#
                .into(),
        );

        expression
            .validate_cel()
            .expect("known Anubis rule variables must validate");
    }

    #[test]
    fn rule_cel_validation_rejects_unknown_rule_variables() {
        let expression = Expression::Simple(r#"userAgnet == "Mozilla/5.0""#.into());

        assert!(matches!(
            expression.validate_cel(),
            Err(CelValidationError::UnknownVariable { variable })
                if variable == "userAgnet"
        ));
    }
}
