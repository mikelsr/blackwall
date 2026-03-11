use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub listener: ListenerConfig,
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListenerConfig {
    pub bind: String,
    pub network: BindNetwork,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProxyConfig {
    pub target: Target,
    pub target_host: Option<String>,
    pub target_sni: Option<String>,
    pub insecure_skip_verify: bool,
    pub disable_keepalive: bool,
    pub use_remote_address: bool,
    pub xff_strip_private: bool,
    pub path_rewrite: Option<PathRewriteConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindNetwork {
    Tcp,
    Unix,
}

impl BindNetwork {
    pub fn parse(value: String) -> Result<Self, ConfigError> {
        match value.as_str() {
            "tcp" => Ok(BindNetwork::Tcp),
            "unix" => Ok(BindNetwork::Unix),
            _ => Err(ConfigError::InvalidBindNetwork(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Disabled,
    Http(Url),
    Https(Url),
    // Unix(Url),
}

impl Target {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        if value.trim().is_empty() {
            return Ok(Target::Disabled);
        }
        let url = Url::parse(value).map_err(|source| ConfigError::InvalidTarget {
            value: value.to_owned(),
            source,
        })?;
        match url.scheme() {
            "http" => Ok(Target::Http(url)),
            "https" => Ok(Target::Https(url)),
            "unix" => Err(ConfigError::UnixTargetNotYetImplemented),
            _ => Err(ConfigError::UnsupportedTargetScheme(
                url.scheme().to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathRewriteConfig {
    pub base_prefix: Option<BasePrefix>,
    pub strip_base_prefix: bool,
}

impl PathRewriteConfig {
    pub fn parse(
        base_prefix: String,
        strip_base_prefix: bool,
    ) -> Result<Option<Self>, ConfigError> {
        let base_prefix = BasePrefix::parse(base_prefix)?;

        if strip_base_prefix && base_prefix.is_none() {
            return Err(ConfigError::StripBasePrefixRequiresBasePrefix);
        }

        if base_prefix.is_some() || strip_base_prefix {
            Ok(Some(Self {
                base_prefix,
                strip_base_prefix,
            }))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasePrefix(String);

impl BasePrefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl BasePrefix {
    pub fn parse(value: String) -> Result<Option<Self>, ConfigError> {
        if value.is_empty() {
            return Ok(None);
        }
        if !value.starts_with('/') {
            return Err(ConfigError::InvalidBasePrefix {
                value,
                reason: "base prefix must start with '/'",
            });
        }
        if value.ends_with('/') {
            return Err(ConfigError::InvalidBasePrefix {
                value,
                reason: "base prefix must not end with '/'",
            });
        }
        Ok(Some(Self(value)))
    }
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidBindNetwork(String),
    InvalidTarget {
        value: String,
        source: url::ParseError,
    },
    UnsupportedTargetScheme(String),
    UnixTargetNotYetImplemented,
    InvalidBasePrefix {
        value: String,
        reason: &'static str,
    },
    StripBasePrefixRequiresBasePrefix,
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ConfigError::InvalidBindNetwork(value) => {
                write!(
                    f,
                    "invalid bind-network {:?}, expected \"tcp\" or \"unix\"",
                    value
                )
            }
            ConfigError::InvalidTarget { value, .. } => {
                write!(f, "invalid target {:?}", value)
            }
            ConfigError::UnsupportedTargetScheme(value) => {
                write!(f, "unsupported target scheme {:?}", value)
            }
            ConfigError::UnixTargetNotYetImplemented => {
                write!(
                    f,
                    "unix targets are recognized but not implemented in the MVP"
                )
            }
            ConfigError::InvalidBasePrefix { value, reason } => {
                write!(f, "invalid base-prefix {:?}: {}", value, reason)
            }
            ConfigError::StripBasePrefixRequiresBasePrefix => {
                write!(f, "strip-base-prefix=true requires a non-empty base-prefix")
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfigError::InvalidTarget { source, .. } => Some(source),
            _ => None,
        }
    }
}
