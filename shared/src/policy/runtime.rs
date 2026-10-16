use compact_str::CompactString;

use super::compile::{
    CompiledRule, CompiledThreshold, PolicyMatchError, ThresholdLogic, WeightPredicate, cel_context,
};
use super::dns::DnsVerifier;
use super::model::{Action, ChallengeRules, Rule, Weight};
use super::request::PolicyRequest;

const LEGACY_ANUBIS_NAME: &str = "legacy-anubis-behaviour";
const DEFAULT_ALGORITHM: &str = "fast";

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
                    algorithm: Some(DEFAULT_ALGORITHM.into()),
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

    pub async fn evaluate(
        &self,
        request: &PolicyRequest<'_>,
        dns_verifier: &dyn DnsVerifier,
    ) -> Result<PolicyEvaluation, PolicyMatchError> {
        let context = cel_context(request).map_err(PolicyMatchError::Context)?;
        let mut weight = 0_i32;

        for rule in &self.rules {
            if !rule.matches(&context, request, dns_verifier).await? {
                continue;
            }

            match &rule.action {
                Action::Allow => {
                    return Ok(PolicyEvaluation::Allow {
                        rule: rule.name.clone(),
                    });
                }
                Action::Deny => {
                    return Ok(PolicyEvaluation::Deny {
                        rule: rule.name.clone(),
                    });
                }
                Action::Challenge => {
                    return Ok(PolicyEvaluation::Challenge {
                        rule: rule.name.clone(),
                        config: rule.challenge.clone(),
                    });
                }
                Action::DebugBenchmark => todo!("debug benchmark"),
                Action::Weigh => {
                    let adjust = rule.weight.as_ref().map_or(5, |weight| weight.adjust);
                    weight = weight.saturating_add(adjust);
                }
            }
        }

        for threshold in &self.thresholds {
            if !threshold.matches(weight) {
                continue;
            }
            return match &threshold.action {
                Action::Allow => Ok(PolicyEvaluation::Allow {
                    rule: threshold.name.clone(),
                }),
                Action::Deny => Ok(PolicyEvaluation::Deny {
                    rule: threshold.name.clone(),
                }),
                Action::Challenge => Ok(PolicyEvaluation::Challenge {
                    rule: threshold.name.clone(),
                    config: threshold.challenge.clone(),
                }),
                _ => continue,
            };
        }

        Ok(PolicyEvaluation::DefaultAllow)
    }
}
