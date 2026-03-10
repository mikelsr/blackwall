use clap::Parser;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use url::Url;

pub(crate) fn load_config() -> Result<StartupMode, ConfigError> {
    let _ = dotenvy::dotenv();
    let args = RawArgs::parse();
    StartupMode::parse(args)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum StartupMode {
    Run(Config),
    Version,
    Healthcheck,
}

impl StartupMode {
    fn parse(args: RawArgs) -> Result<StartupMode, ConfigError> {
        if args.version {
            return Ok(StartupMode::Version);
        }
        if args.health {
            return Ok(StartupMode::Healthcheck);
        }

        Ok(StartupMode::Run(Config::try_from(args)?))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Config {
    pub listener: ListenerConfig,
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ListenerConfig {
    pub bind: String,
    pub network: BindNetwork,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProxyConfig {
    pub target: UpstreamTarget,
    pub target_host: Option<String>,
    pub insecure_skip_verify: bool,
    pub disable_keepalive: bool,
    pub path_rewrite: Option<PathRewriteConfig>,
}

impl TryFrom<RawArgs> for Config {
    type Error = ConfigError;

    fn try_from(args: RawArgs) -> Result<Self, Self::Error> {
        let target_host = if args.target_host.is_empty() {
            None
        } else {
            Some(args.target_host)
        };
        let path_rewrite = PathRewriteConfig::parse(args.base_prefix, args.strip_base_prefix)?;

        Ok(Self {
            listener: ListenerConfig {
                bind: args.bind,
                network: BindNetwork::parse(args.bind_network)?,
            },
            proxy: ProxyConfig {
                target: UpstreamTarget::parse(args.target.as_str())?,
                target_host: target_host,
                insecure_skip_verify: args.target_insecure_skip_verify,
                disable_keepalive: args.target_disable_keepalive,
                path_rewrite: path_rewrite,
            },
        })
    }
}

// TODO mikel: lots of pubs. Check what actually needs to be pub.

#[derive(Parser)]
#[command(name = "b7l")]
struct RawArgs {
    /// Base prefix (root URL) the application is served under e.g. /myapp
    #[arg(long = "base-prefix", env = "BASE_PREFIX", default_value = "")]
    pub(super) base_prefix: String,

    /// Network address to bind HTTP to
    #[arg(long, env = "BIND", default_value = ":8923")]
    pub(super) bind: String,

    /// Network family to bind HTTP to, e.g. unix, tcp
    #[arg(long = "bind-network", env = "BIND_NETWORK", default_value = "tcp")]
    pub(super) bind_network: String,

    /// If true, strips the base prefix from requests forwarded to the target server
    #[arg(
        long = "strip-base-prefix",
        env = "STRIP_BASE_PREFIX",
        default_value_t = false
    )]
    pub(super) strip_base_prefix: bool,

    /// Target to reverse proxy to, set to an empty string to disable proxying when only using auth request
    #[arg(
        long = "target",
        env = "TARGET",
        default_value = "http://localhost:3923"
    )]
    pub(super) target: String,

    /// If set, the value of the Host header when forwarding requests to the target
    #[arg(long = "target-host", env = "TARGET_HOST", default_value = "")]
    pub(super) target_host: String,

    /// If true, disables HTTP keep-alive for the backend
    #[arg(
        long = "target-disable-keepalive",
        env = "TARGET_DISABLE_KEEPALIVE",
        default_value_t = false
    )]
    pub(super) target_disable_keepalive: bool,

    /// If true, skips TLS validation for the backend
    #[arg(
        long = "target-insecure-skip-verify",
        env = "TARGET_INSECURE_SKIP_VERIFY",
        default_value_t = false
    )]
    pub(super) target_insecure_skip_verify: bool,

    // Startup modes
    /// Run a health check against Blackwall
    #[arg(long = "healthcheck", env = "HEALTHCHECK", default_value_t = false)]
    pub(super) health: bool,

    /// Print Blackwall version
    #[arg(long = "version", env = "VERSION", default_value_t = false)]
    pub(super) version: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindNetwork {
    Tcp,
    Unix,
}

impl BindNetwork {
    fn parse(value: String) -> Result<Self, ConfigError> {
        match value.as_str() {
            "tcp" => Ok(BindNetwork::Tcp),
            "unix" => Ok(BindNetwork::Unix),
            _ => Err(ConfigError::InvalidBindNetwork(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum UpstreamTarget {
    Disabled,
    Http(Url),
    Https(Url),
}

impl UpstreamTarget {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        if value.trim().is_empty() {
            return Ok(UpstreamTarget::Disabled);
        }
        let url = Url::parse(value).map_err(|source| ConfigError::InvalidTarget {
            value: value.to_owned(),
            source,
        })?;
        match url.scheme() {
            "http" => Ok(UpstreamTarget::Http(url)),
            "https" => Ok(UpstreamTarget::Https(url)),
            "unix" => Err(ConfigError::UnixTargetNotYetImplemented),
            _ => Err(ConfigError::UnsupportedTargetScheme(
                url.scheme().to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PathRewriteConfig {
    pub base_prefix: Option<BasePrefix>,
    pub strip_base_prefix: bool,
}

impl PathRewriteConfig {
    fn parse(base_prefix: String, strip_base_prefix: bool) -> Result<Option<Self>, ConfigError> {
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
pub(crate) struct BasePrefix(String);

impl BasePrefix {
    fn parse(value: String) -> Result<Option<Self>, ConfigError> {
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
pub(crate) enum ConfigError {
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
