use compact_str::CompactString;
use sha2::{Digest, Sha256};

use super::compile::{
    CompiledRule, CompiledThreshold, PolicyMatchError, ThresholdLogic, WeightPredicate, cel_context,
};
use super::dns::DnsVerifier;
use super::model::{Action, ChallengeRules, RULE_CEL_VARIABLES, Rule, Weight};
use super::request::PolicyRequest;

const LEGACY_ANUBIS_NAME: &str = "legacy-anubis-behaviour";
const DEFAULT_ALGORITHM: &str = "fast";

fn cel_variables(rules: &[CompiledRule]) -> Vec<&'static str> {
    RULE_CEL_VARIABLES
        .iter()
        .copied()
        .filter(|variable| rules.iter().any(|rule| rule.reads_cel_variable(variable)))
        .collect()
}

#[derive(Debug)]
pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    rule_challenges: Vec<ChallengeSpec>,
    cel_variables: Vec<&'static str>,
    thresholds: Vec<CompiledThreshold>,
    threshold_challenges: Vec<ChallengeSpec>,
    default_difficulty: u32,
}

/// Identifies a challenge *type* by rule and difficulty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeSpec {
    pub difficulty: u32,
    pub rule_hash: u64,
}

impl ChallengeSpec {
    fn new(name: &str, challenge: Option<&ChallengeRules>, default_difficulty: u32) -> Self {
        let difficulty = challenge
            .and_then(|challenge| challenge.difficulty)
            .unwrap_or(default_difficulty);
        let digest = Sha256::new()
            .chain_update(name)
            .chain_update([0])
            .chain_update(difficulty.to_be_bytes())
            .finalize();
        let rule_hash = u64::from_be_bytes(digest[..8].try_into().expect("digest has 32 bytes"));
        Self {
            difficulty,
            rule_hash,
        }
    }
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
        challenge: ChallengeSpec,
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

        let rule_challenges = rules
            .iter()
            .map(|rule| ChallengeSpec::new(&rule.name, rule.challenge.as_ref(), default_difficulty))
            .collect();
        let threshold_challenges = thresholds
            .iter()
            .map(|threshold| {
                ChallengeSpec::new(
                    &threshold.name,
                    threshold.challenge.as_ref(),
                    default_difficulty,
                )
            })
            .collect();

        Self {
            cel_variables: cel_variables(&rules),
            rules,
            rule_challenges,
            thresholds,
            threshold_challenges,
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

        Self::new(vec![browser_rule], thresholds, default_difficulty)
    }

    pub fn default_difficulty(&self) -> u32 {
        self.default_difficulty
    }

    pub async fn evaluate(
        &self,
        request: &PolicyRequest<'_>,
        dns_verifier: &dyn DnsVerifier,
    ) -> Result<PolicyEvaluation, PolicyMatchError> {
        let context =
            cel_context(request, &self.cel_variables).map_err(PolicyMatchError::Context)?;
        let mut weight: i32 = 0;

        for (rule, challenge) in self.rules.iter().zip(&self.rule_challenges) {
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
                        challenge: *challenge,
                    });
                }
                Action::DebugBenchmark => todo!("debug benchmark"),
                Action::Weigh => {
                    let adjust = rule.weight.as_ref().map_or(5, |weight| weight.adjust);
                    weight = weight.saturating_add(adjust);
                }
            }
        }

        for (threshold, challenge) in self.thresholds.iter().zip(&self.threshold_challenges) {
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
                    challenge: *challenge,
                }),
                _ => continue,
            };
        }

        Ok(PolicyEvaluation::DefaultAllow)
    }
}
