use std::{
    borrow::Cow,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::compile::*;
use super::embed;

const YAML_IMPORT_PREFIX: &str = "(data)/";

#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    bots: Vec<BotEntry>,

    #[serde(default)]
    thresholds: Vec<Threshold>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BotEntry {
    Import { import: String },
    Rule(Rule),
}

pub fn load_policy_file(
    path: &Path,
    default_difficulty: u32,
) -> Result<PolicyEngine, PolicyLoadError> {
    let as_str = fs::read_to_string(path).map_err(|source| PolicyLoadError::ReadFile {
        path: path.to_owned(),
        source,
    })?;

    load_policy_str(
        &as_str,
        PolicySource::File(path.to_owned()),
        default_difficulty,
    )
}

fn load_policy_str(
    as_str: &str,
    source: PolicySource,
    default_difficulty: u32,
) -> Result<PolicyEngine, PolicyLoadError> {
    let policy: PolicyFile =
        serde_yaml::from_str(as_str).map_err(|e| PolicyLoadError::ParseYaml {
            source_file: source,
            source: e,
        })?;

    let mut rules = Vec::new();
    expand_bot_entries(policy.bots, &mut rules)?;

    let thresholds = policy
        .thresholds
        .into_iter()
        .map(CompiledThreshold::compile)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PolicyLoadError::CompilationError { err: e })?;

    Ok(PolicyEngine::new(rules, thresholds, default_difficulty))
}

fn expand_bot_entries(
    entries: Vec<BotEntry>,
    rules: &mut Vec<CompiledRule>,
) -> Result<(), PolicyLoadError> {
    for entry in entries {
        match entry {
            BotEntry::Import { import } => {
                let entries = load_import_entries(&import)?;
                expand_bot_entries(entries, rules)?;
            }
            BotEntry::Rule(rule) => {
                let compiled = CompiledRule::compile(&rule)
                    .map_err(|err| PolicyLoadError::CompilationError { err })?;
                rules.push(compiled);
            }
        }
    }
    Ok(())
}

// Loads entries from an import path, relative to the process' working directory.
fn load_import_entries(import: &str) -> Result<Vec<BotEntry>, PolicyLoadError> {
    let (yaml, source_file): (Cow<'static, str>, PolicySource) =
        if let Some(embedded_path) = import.strip_prefix(YAML_IMPORT_PREFIX) {
            let yaml =
                embed::get(embedded_path).ok_or_else(|| PolicyLoadError::EmbeddedFileMissing {
                    file: embedded_path.to_owned(),
                })?;

            (
                Cow::Borrowed(yaml),
                PolicySource::Embedded(embedded_path.to_owned()),
            )
        } else {
            let path = PathBuf::from(import);
            let yaml = fs::read_to_string(&path).map_err(|source| PolicyLoadError::ReadFile {
                path: path.clone(),
                source,
            })?;

            (Cow::Owned(yaml), PolicySource::File(path))
        };

    serde_yaml::from_str(yaml.as_ref()).map_err(|source| PolicyLoadError::ParseYaml {
        source_file,
        source,
    })
}

#[derive(Debug, Clone)]
pub enum PolicySource {
    File(PathBuf),
    Embedded(String),
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Embedded(path) => write!(f, "{YAML_IMPORT_PREFIX}{path}"),
        }
    }
}

#[derive(Debug)]
pub enum PolicyLoadError {
    CompilationError {
        err: PolicyCompileError,
    },
    EmbeddedFileMissing {
        file: String,
    },
    ImportCycle {
        file: String,
    },
    ParseYaml {
        source_file: PolicySource,
        source: serde_yaml::Error,
    },
    ReadFile {
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompilationError { err } => write!(f, "{err}"),
            Self::EmbeddedFileMissing { file } => {
                write!(f, "missing embedded policy file: {file}")
            }
            Self::ImportCycle { file } => write!(f, "import cycle: {file}"),
            Self::ParseYaml {
                source_file,
                source,
            } => write!(f, "failed to parse YAML from {source_file}: {source}"),
            Self::ReadFile { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for PolicyLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CompilationError { err } => Some(err),
            Self::ParseYaml { source, .. } => Some(source),
            Self::ReadFile { source, .. } => Some(source),
            Self::EmbeddedFileMissing { .. } | Self::ImportCycle { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_default_policy_loads() {
        let yaml = embed::get("botPolicies.yaml").expect("bundled root policy must exist");

        let engine = load_policy_str(
            yaml,
            PolicySource::Embedded("botPolicies.yaml".to_owned()),
            4,
        )
        .expect("bundled default policy must load");

        assert_eq!(engine.default_difficulty(), 4);
    }
}
