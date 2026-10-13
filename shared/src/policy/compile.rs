use compact_str::CompactString;
use http::{HeaderMap, HeaderName};
use ipnet::IpNet;
use regex::{self, Regex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

const PATH_REGEX: &str = "path_regex";
const USER_AGENT_REGEX: &str = "user_agent_regex";
const HEADERS_REGEX: &str = "headers_regex";
// The name is kept to keep behaviour as close as possible to the Anubis...
const LEGACY_ANUBIS_NAME: &str = "legacy-anubis-behaviour";
const DEFAULT_ALGORITHM: &str = "fast";

// Policy definitions.

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

/// Rule definition, for initialization.
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

// Policy compilation.

/// Rules kept at runtime and used for actual evaluation.
#[derive(Debug)]
pub struct CompiledRule {
    pub name: CompactString,
    pub action: Action,
    path_regex: Option<Regex>,
    user_agent_regex: Option<Regex>,
    headers_regex: Option<Vec<(CompactString, Regex)>>,
    expression: Option<CompiledRuleExpression>,
    remote_addresses: Option<Vec<IpNet>>,
    challenge: Option<ChallengeRules>,
    weight: Option<Weight>,
}

impl CompiledRule {
    pub fn compile(rule: &Rule) -> Result<Self, PolicyCompileError> {
        if rule.user_agent_regex.is_some() && rule.path_regex.is_some() {
            return Err(PolicyCompileError::BothUserAgentAndPath {
                name: rule.name.clone(),
            });
        }

        let path_regex = rule
            .path_regex
            .as_deref()
            .map(|r| compile_regex(r, &rule.name, PATH_REGEX))
            .transpose()?;

        let user_agent_regex = rule
            .user_agent_regex
            .as_deref()
            .map(|r| compile_regex(r, &rule.name, USER_AGENT_REGEX))
            .transpose()?;

        let headers_regex = rule
            .headers_regex
            .as_ref()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        compile_regex(v, &rule.name, HEADERS_REGEX)
                            .map(|r| (CompactString::new(k), r))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let expression = rule
            .expression
            .as_ref()
            .map(|e| compile_rule_expr(e, &rule.name))
            .transpose()?;

        let remote_addresses = rule
            .remote_addresses
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|s| {
                        s.parse::<IpNet>()
                            .map_err(|source| PolicyCompileError::InvalidCidr {
                                name: rule.name.clone(),
                                value: s.clone(),
                                source,
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let has_matcher = path_regex.is_some()
            || user_agent_regex.is_some()
            || headers_regex.is_some()
            || remote_addresses.is_some()
            || expression.is_some()
            || rule.geo_ip.is_some()
            || rule.asns.is_some();

        if !has_matcher {
            return Err(PolicyCompileError::NoMatchers {
                name: rule.name.clone(),
            });
        }

        // Weight defaults to 5.
        let weight = match (&rule.action, &rule.weight) {
            (Action::Weigh, None) => Some(Weight { adjust: 5 }),
            (_, w) => w.clone(),
        };

        Ok(Self {
            name: rule.name.clone(),
            action: rule.action.clone(),
            path_regex,
            user_agent_regex,
            headers_regex,
            expression,
            remote_addresses,
            challenge: rule.challenge.clone(),
            weight,
        })
    }

    pub fn matches(
        &self,
        path: &str,
        user_agent: Option<&str>,
        headers: &HeaderMap,
        remote_ip: IpAddr,
    ) -> bool {
        if let Some(re) = &self.path_regex {
            if !re.is_match(path) {
                return false;
            }
        }

        if let Some(re) = &self.user_agent_regex {
            if !re.is_match(user_agent.unwrap_or("")) {
                return false;
            }
        }

        if let Some(header_regexes) = &self.headers_regex {
            for (name, re) in header_regexes {
                let value = headers
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !re.is_match(value) {
                    return false;
                }
            }
        }

        if let Some(CompiledRuleExpression::HasHeader(name)) = &self.expression {
            if !headers.contains_key(name.as_str()) {
                return false;
            }
        }

        if let Some(nets) = &self.remote_addresses {
            if !nets.iter().any(|net| net.contains(&remote_ip)) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug)]
enum CompiledRuleExpression {
    HasHeader(HeaderName),
}

fn compile_regex(
    pattern: &str,
    rule_name: &CompactString,
    field: &'static str,
) -> Result<Regex, PolicyCompileError> {
    // Anubis rejects newlines.
    if pattern.ends_with('\n') {
        return Err(PolicyCompileError::TrailingNewline {
            name: rule_name.clone(),
            field,
        });
    }
    Regex::new(pattern).map_err(|source| PolicyCompileError::InvalidRegex {
        name: rule_name.clone(),
        field,
        source,
    })
}

fn compile_rule_expr(
    expression: &Expression,
    rule_name: &CompactString,
) -> Result<CompiledRuleExpression, PolicyCompileError> {
    let Expression::Simple(src) = expression else {
        return Err(PolicyCompileError::UnsupportedRuleExpression {
            name: rule_name.clone(),
            expression: format!("{expression:?}"),
        });
    };

    let unsupported_expr = || PolicyCompileError::UnsupportedRuleExpression {
        name: rule_name.clone(),
        expression: src.clone(),
    };

    let header_name = src
        .trim()
        .strip_suffix(" in headers")
        .map(str::trim_end)
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty())
        .ok_or_else(unsupported_expr)?;

    let header_name =
        HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| unsupported_expr())?;

    Ok(CompiledRuleExpression::HasHeader(header_name))
}

#[derive(Debug, Deserialize)]
pub(crate) struct Threshold {
    name: CompactString,
    expression: Expression,
    action: Action,

    #[serde(default)]
    challenge: Option<ChallengeRules>,
}

#[derive(Debug, Clone, Copy)]
pub enum ThresholdLogic {
    All,
    Any,
}

// Weight thresholds.
#[derive(Debug)]
pub struct CompiledThreshold {
    pub name: CompactString,
    pub predicates: Vec<WeightPredicate>,
    pub logic: ThresholdLogic,
    pub action: Action,
    pub challenge: Option<ChallengeRules>,
}

impl CompiledThreshold {
    pub fn matches(&self, weight: i32) -> bool {
        match self.logic {
            ThresholdLogic::All => self.predicates.iter().all(|pred| pred.evaluate(weight)),
            ThresholdLogic::Any => self.predicates.iter().any(|pred| pred.evaluate(weight)),
        }
    }

    pub(crate) fn compile(threshold: Threshold) -> Result<Self, PolicyCompileError> {
        let (logic, expr) = match threshold.expression {
            Expression::Simple(expr) => (ThresholdLogic::All, vec![expr]),
            Expression::All { all } => (ThresholdLogic::All, all),
            Expression::Any { any } => (ThresholdLogic::Any, any),
        };

        let predicates = expr
            .iter()
            .map(|expr| WeightPredicate::parse(&expr))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|cause| PolicyCompileError::InvalidThresholdExpression {
                name: threshold.name.clone(),
                cause,
            })?;

        Ok(Self {
            name: threshold.name,
            predicates: predicates,
            logic,
            action: threshold.action,
            challenge: threshold.challenge,
        })
    }
}

#[derive(Debug, Clone)]
pub enum WeightPredicate {
    Gt(i32),
    Gte(i32),
    Lt(i32),
    Lte(i32),
    Eq(i32),
}

impl WeightPredicate {
    pub fn parse(expression: &str) -> Result<Self, String> {
        let rest = expression
            .trim()
            .strip_prefix("weight")
            .ok_or_else(|| format!("expression must start with 'weight': {expression:?}"))?
            .trim_start();

        // Two-char operators before single-char.
        if let Some(n) = rest.strip_prefix(">=") {
            return Ok(Self::Gte(parse_i32(n)?));
        }
        if let Some(n) = rest.strip_prefix(">") {
            return Ok(Self::Gt(parse_i32(n)?));
        }
        if let Some(n) = rest.strip_prefix("<=") {
            return Ok(Self::Lte(parse_i32(n)?));
        }
        if let Some(n) = rest.strip_prefix("<") {
            return Ok(Self::Lt(parse_i32(n)?));
        }
        if let Some(n) = rest.strip_prefix("==") {
            return Ok(Self::Eq(parse_i32(n)?));
        }

        Err(format!("unknown operator in expression: {expression:?}"))
    }

    #[inline]
    pub fn evaluate(&self, weight: i32) -> bool {
        match self {
            Self::Gt(n) => weight > *n,
            Self::Gte(n) => weight >= *n,
            Self::Lt(n) => weight < *n,
            Self::Lte(n) => weight <= *n,
            Self::Eq(n) => weight == *n,
        }
    }
}

fn parse_i32(s: &str) -> Result<i32, String> {
    s.trim().parse().map_err(|e| format!("invalid number: {e}"))
}

// Policy engine.
#[derive(Debug)]
pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    thresholds: Vec<CompiledThreshold>,
    default_difficulty: u32,
}

pub enum PolicyEvaluation {
    Allow {
        rule: CompactString,
    },
    Deny {
        rule: CompactString,
    },
    Challenge {
        rule: CompactString,
        config: Option<ChallengeRules>,
    },
    DefaultAllow,
}

impl PolicyEngine {
    pub fn new(
        rules: Vec<CompiledRule>,
        thresholds: Vec<CompiledThreshold>,
        default_difficulty: u32,
    ) -> Self {
        let thresholds = if thresholds.is_empty() {
            vec![CompiledThreshold {
                name: CompactString::from(LEGACY_ANUBIS_NAME),
                logic: ThresholdLogic::All,
                predicates: vec![WeightPredicate::Gt(0)],
                action: Action::Challenge,
                challenge: Some(ChallengeRules {
                    algorithm: Some(DEFAULT_ALGORITHM.into()),
                    difficulty: Some(default_difficulty),
                    report_as: None,
                }),
            }]
        } else {
            thresholds
        };
        Self {
            rules,
            thresholds,
            default_difficulty,
        }
    }

    pub fn default(default_difficulty: u32) -> Self {
        // TODO mikel: load from YAML
        let browser_rule = CompiledRule::compile(&Rule {
            name: "generic-browser".into(),
            action: Action::Weigh,
            user_agent_regex: Some("Mozilla|Opera".into()),
            path_regex: None,
            headers_regex: None,
            remote_addresses: None,
            expression: None,
            challenge: None,
            weight: Some(Weight { adjust: 10 }),
            geo_ip: None,
            asns: None,
        })
        .expect("built-in rule must compile");

        let thresholds = vec![
            CompiledThreshold {
                name: "minimal-suspicion".into(),
                logic: ThresholdLogic::All,
                predicates: vec![WeightPredicate::Lte(0)],
                action: Action::Allow,
                challenge: None,
            },
            CompiledThreshold {
                name: "moderate-suspicion".into(),
                logic: ThresholdLogic::All,
                predicates: vec![WeightPredicate::Gt(0)],
                action: Action::Challenge,
                challenge: Some(ChallengeRules {
                    algorithm: Some("fast".into()),
                    difficulty: Some(default_difficulty),
                    report_as: None,
                }),
            },
        ];

        Self {
            rules: vec![browser_rule],
            thresholds,
            default_difficulty,
        }
    }

    pub fn default_difficulty(&self) -> u32 {
        self.default_difficulty
    }

    pub fn evaluate(
        &self,
        path: &str,
        user_agent: Option<&str>,
        headers: &HeaderMap,
        remote_ip: IpAddr,
    ) -> PolicyEvaluation {
        let mut weight: i32 = 0;

        for rule in &self.rules {
            if !rule.matches(path, user_agent, headers, remote_ip) {
                continue;
            }

            match &rule.action {
                Action::Allow => {
                    return PolicyEvaluation::Allow {
                        rule: rule.name.clone(),
                    };
                }
                Action::Deny => {
                    return PolicyEvaluation::Deny {
                        rule: rule.name.clone(),
                    };
                }
                Action::Challenge => {
                    return PolicyEvaluation::Challenge {
                        rule: rule.name.clone(),
                        config: rule.challenge.clone(),
                    };
                }
                Action::DebugBenchmark => {
                    todo!("debug benchmark");
                }
                Action::Weigh => {
                    let adjust = rule.weight.as_ref().map_or(5, |w| w.adjust);
                    weight = weight.saturating_add(adjust);
                }
            }
        }

        for threshold in &self.thresholds {
            if !threshold.matches(weight) {
                continue;
            }

            // theshold evaluation cannot lead to weight or debug.
            return match &threshold.action {
                Action::Allow => PolicyEvaluation::Allow {
                    rule: threshold.name.clone(),
                },
                Action::Deny => PolicyEvaluation::Deny {
                    rule: threshold.name.clone(),
                },
                Action::Challenge => PolicyEvaluation::Challenge {
                    rule: threshold.name.clone(),
                    config: threshold.challenge.clone(),
                },
                _ => continue,
            };
        }

        PolicyEvaluation::DefaultAllow
    }
}

// Policy compilation errors.

#[derive(Debug)]
pub enum PolicyCompileError {
    BothUserAgentAndPath {
        name: CompactString,
    },
    InvalidCidr {
        name: CompactString,
        value: String,
        source: ipnet::AddrParseError,
    },
    InvalidRegex {
        name: CompactString,
        field: &'static str,
        source: regex::Error,
    },
    InvalidThresholdExpression {
        name: CompactString,
        cause: String,
    },
    NoMatchers {
        name: CompactString,
    },
    TrailingNewline {
        name: CompactString,
        field: &'static str,
    },
    UnsupportedRuleExpression {
        name: CompactString,
        expression: String,
    },
}

impl fmt::Display for PolicyCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothUserAgentAndPath { name } => {
                write!(
                    f,
                    "rule {name:?}: must set either user_agent_regex or path_regex, not both"
                )
            }
            Self::InvalidCidr {
                name,
                value,
                source,
            } => {
                write!(f, "rule {name:?}: invalid CIDR {value:?}: {source}")
            }
            Self::InvalidRegex {
                name,
                field,
                source,
            } => {
                write!(f, "rule {name:?}: invalid {field}: {source}")
            }
            Self::InvalidThresholdExpression { name, cause } => {
                write!(f, "rule {name:?}: invalid threshold expression: {cause}")
            }

            // TODO mikel: Thoth support?
            Self::NoMatchers { name } => {
                write!(
                    f,
                    "rule {name:?}: must set one of user_agent_regex,\
                    path_regex, headers_regex, remote_addresses, expression, or Thoth keyword"
                )
            }
            Self::TrailingNewline { name, field } => {
                write!(
                    f,
                    "rule {name:?}: {field} ends with newline (try >- instead of > in yaml)"
                )
            }
            Self::UnsupportedRuleExpression { name, expression } => {
                write!(
                    f,
                    "rule {name:?}: unsupported rule expression: {expression}"
                )
            }
        }
    }
}

impl std::error::Error for PolicyCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRegex { source, .. } => Some(source),
            Self::InvalidCidr { source, .. } => Some(source),
            _ => None,
        }
    }
}

// Tests, generated by the LLM intern.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }
    fn external_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    }
    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn rule(name: &str, action: Action) -> Rule {
        Rule {
            name: name.into(),
            action,
            path_regex: None,
            user_agent_regex: None,
            headers_regex: None,
            remote_addresses: None,
            expression: None,
            challenge: None,
            weight: None,
            geo_ip: None,
            asns: None,
        }
    }

    // ── CompiledRule ──

    #[test]
    fn compile_rejects_no_matchers() {
        let r = rule("empty", Action::Allow);
        assert!(matches!(
            CompiledRule::compile(&r),
            Err(PolicyCompileError::NoMatchers { .. })
        ));
    }

    #[test]
    fn compile_rejects_both_ua_and_path() {
        let mut r = rule("both", Action::Allow);
        r.user_agent_regex = Some("Mozilla".into());
        r.path_regex = Some("/api".into());
        assert!(matches!(
            CompiledRule::compile(&r),
            Err(PolicyCompileError::BothUserAgentAndPath { .. })
        ));
    }

    #[test]
    fn compile_rejects_trailing_newline() {
        let mut r = rule("bad", Action::Allow);
        r.path_regex = Some("/foo\n".into());
        assert!(matches!(
            CompiledRule::compile(&r),
            Err(PolicyCompileError::TrailingNewline { .. })
        ));
    }

    #[test]
    fn compile_rejects_invalid_regex() {
        let mut r = rule("bad", Action::Allow);
        r.user_agent_regex = Some("[unclosed".into());
        assert!(matches!(
            CompiledRule::compile(&r),
            Err(PolicyCompileError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn compile_rejects_invalid_cidr() {
        let mut r = rule("bad", Action::Allow);
        r.remote_addresses = Some(vec!["not-a-cidr".into()]);
        assert!(matches!(
            CompiledRule::compile(&r),
            Err(PolicyCompileError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn compile_defaults_weigh_to_5() {
        let mut r = rule("w", Action::Weigh);
        r.user_agent_regex = Some(".*".into());
        let compiled = CompiledRule::compile(&r).unwrap();
        assert_eq!(compiled.weight.as_ref().unwrap().adjust, 5);
    }

    #[test]
    fn compile_accepts_expr_as_sole_matcher() {
        let mut r = rule("expr", Action::Allow);
        r.expression = Some(Expression::Simple(r#""X-Firefox-Ai" in headers"#.into()));
        assert!(CompiledRule::compile(&r).is_ok());
    }

    #[test]
    fn compile_accepts_geoip_as_sole_matcher() {
        let mut r = rule("geo", Action::Weigh);
        r.geo_ip = Some(GeoIp {
            countries: vec!["BR".into()],
        });
        assert!(CompiledRule::compile(&r).is_ok());
    }

    #[test]
    fn compile_accepts_asns_as_sole_matcher() {
        let mut r = rule("asn", Action::Weigh);
        r.asns = Some(Asns {
            matches: vec![13335],
        });
        assert!(CompiledRule::compile(&r).is_ok());
    }

    #[test]
    fn matches_path_regex() {
        let mut r = rule("p", Action::Allow);
        r.path_regex = Some("^/api/".into());
        let c = CompiledRule::compile(&r).unwrap();
        assert!(c.matches("/api/users", None, &empty_headers(), localhost()));
        assert!(!c.matches("/home", None, &empty_headers(), localhost()));
    }

    #[test]
    fn matches_header_present_expression() {
        let mut rule = rule("firefox-ai", Action::Weigh);
        rule.expression = Some(Expression::Simple(r#""X-Firefox-Ai" in headers"#.into()));

        let compiled = CompiledRule::compile(&rule).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("X-Firefox-Ai", "1".parse().unwrap());

        assert!(compiled.matches("/", None, &headers, localhost()));
        assert!(!compiled.matches("/", None, &empty_headers(), localhost()));
    }

    #[test]
    fn rejects_unsupported_rule_expression() {
        let mut rule = rule("unsupported", Action::Allow);
        rule.expression = Some(Expression::Simple("method == 'POST'".into()));

        assert!(matches!(
            CompiledRule::compile(&rule),
            Err(PolicyCompileError::UnsupportedRuleExpression { .. })
        ));
    }

    #[test]
    fn matches_user_agent() {
        let mut r = rule("ua", Action::Deny);
        r.user_agent_regex = Some("BadBot".into());
        let c = CompiledRule::compile(&r).unwrap();
        assert!(c.matches("/", Some("BadBot/1.0"), &empty_headers(), localhost()));
        assert!(!c.matches("/", Some("Mozilla/5.0"), &empty_headers(), localhost()));
        assert!(!c.matches("/", None, &empty_headers(), localhost()));
    }

    #[test]
    fn matches_cidr() {
        let mut r = rule("local", Action::Allow);
        r.remote_addresses = Some(vec!["127.0.0.0/8".into()]);
        let c = CompiledRule::compile(&r).unwrap();
        assert!(c.matches("/", None, &empty_headers(), localhost()));
        assert!(!c.matches("/", None, &empty_headers(), external_ip()));
    }

    #[test]
    fn matches_requires_all_matchers_and() {
        let mut r = rule("both", Action::Allow);
        // Can't use both ua + path, so use ua + remote_addresses
        r.user_agent_regex = Some("Mozilla".into());
        r.remote_addresses = Some(vec!["127.0.0.0/8".into()]);
        let c = CompiledRule::compile(&r).unwrap();
        assert!(c.matches("/", Some("Mozilla/5.0"), &empty_headers(), localhost()));
        assert!(!c.matches("/", Some("curl/7"), &empty_headers(), localhost()));
        assert!(!c.matches("/", Some("Mozilla/5.0"), &empty_headers(), external_ip()));
    }

    // ── WeightPredicate ──

    #[test]
    fn predicate_gt() {
        let p = WeightPredicate::parse("weight > 0").unwrap();
        assert!(!p.evaluate(0));
        assert!(p.evaluate(1));
    }

    #[test]
    fn predicate_gte() {
        let p = WeightPredicate::parse("weight >= 0").unwrap();
        assert!(p.evaluate(0));
        assert!(!p.evaluate(-1));
    }

    #[test]
    fn predicate_lt() {
        let p = WeightPredicate::parse("weight < 5").unwrap();
        assert!(p.evaluate(4));
        assert!(!p.evaluate(5));
    }

    #[test]
    fn predicate_eq() {
        let p = WeightPredicate::parse("weight == 10").unwrap();
        assert!(p.evaluate(10));
        assert!(!p.evaluate(11));
    }

    #[test]
    fn predicate_rejects_bad_input() {
        assert!(WeightPredicate::parse("foo > 0").is_err());
        assert!(WeightPredicate::parse("weight ~ 0").is_err());
        assert!(WeightPredicate::parse("weight > abc").is_err());
    }

    // ── PolicyEngine ──

    #[test]
    fn allow_short_circuits() {
        let mut r = rule("allow-all", Action::Allow);
        r.path_regex = Some(".*".into());
        let engine = PolicyEngine::new(vec![CompiledRule::compile(&r).unwrap()], vec![], 4);
        assert!(matches!(
            engine.evaluate("/foo", None, &empty_headers(), localhost()),
            PolicyEvaluation::Allow { .. }
        ));
    }

    #[test]
    fn deny_short_circuits() {
        let mut r = rule("deny-bots", Action::Deny);
        r.user_agent_regex = Some("BadBot".into());
        let engine = PolicyEngine::new(vec![CompiledRule::compile(&r).unwrap()], vec![], 4);
        assert!(matches!(
            engine.evaluate("/", Some("BadBot/1.0"), &empty_headers(), localhost()),
            PolicyEvaluation::Deny { .. }
        ));
    }

    #[test]
    fn weigh_accumulates_then_threshold_fires() {
        let mut r1 = rule("browser", Action::Weigh);
        r1.user_agent_regex = Some("Mozilla".into());
        r1.weight = Some(Weight { adjust: 10 });

        let mut r2 = rule("api-path", Action::Weigh);
        r2.path_regex = Some("^/api/".into());
        r2.weight = Some(Weight { adjust: 5 });

        let thresholds = vec![CompiledThreshold {
            name: "high-suspicion".into(),
            logic: ThresholdLogic::All,
            predicates: vec![WeightPredicate::Gt(12)],
            action: Action::Challenge,
            challenge: Some(ChallengeRules {
                difficulty: Some(6),
                algorithm: None,
                report_as: None,
            }),
        }];

        let engine = PolicyEngine::new(
            vec![
                CompiledRule::compile(&r1).unwrap(),
                CompiledRule::compile(&r2).unwrap(),
            ],
            thresholds,
            4,
        );

        // Both match: weight = 15 > 12 → Challenge
        assert!(matches!(
            engine.evaluate(
                "/api/data",
                Some("Mozilla/5.0"),
                &empty_headers(),
                localhost()
            ),
            PolicyEvaluation::Challenge { .. }
        ));
        // Only r1: weight = 10, not > 12 → DefaultChallenge
        assert!(matches!(
            engine.evaluate("/home", Some("Mozilla/5.0"), &empty_headers(), localhost()),
            PolicyEvaluation::DefaultAllow
        ));
    }

    #[test]
    fn default_policy_allows_zero_weight_requests() {
        let engine = PolicyEngine::default(4);

        assert!(matches!(
            engine.evaluate("/", None, &empty_headers(), localhost()),
            PolicyEvaluation::Allow { rule } if rule == "minimal-suspicion" // TODO mikel: const?
        ));
    }

    #[test]
    fn empty_thresholds_get_legacy_default() {
        let mut r = rule("browser", Action::Weigh);
        r.user_agent_regex = Some("Mozilla".into());
        r.weight = Some(Weight { adjust: 1 });
        let engine = PolicyEngine::new(vec![CompiledRule::compile(&r).unwrap()], vec![], 4);
        // weight=1 > 0 → legacy threshold fires
        assert!(matches!(
            engine.evaluate("/", Some("Mozilla/5.0"), &empty_headers(), localhost()),
            PolicyEvaluation::Challenge { .. }
        ));
    }

    #[test]
    fn allow_before_weigh_short_circuits() {
        let mut allow = rule("search-engine", Action::Allow);
        allow.user_agent_regex = Some("Googlebot".into());
        let mut weigh = rule("generic", Action::Weigh);
        weigh.user_agent_regex = Some(".*".into());
        weigh.weight = Some(Weight { adjust: 10 });

        let engine = PolicyEngine::new(
            vec![
                CompiledRule::compile(&allow).unwrap(),
                CompiledRule::compile(&weigh).unwrap(),
            ],
            vec![CompiledThreshold {
                name: "t".into(),
                logic: ThresholdLogic::All,
                predicates: vec![WeightPredicate::Gt(0)],
                action: Action::Deny,
                challenge: None,
            }],
            4,
        );
        assert!(matches!(
            engine.evaluate("/", Some("Googlebot/2.1"), &empty_headers(), localhost()),
            PolicyEvaluation::Allow { .. }
        ));
    }
}
