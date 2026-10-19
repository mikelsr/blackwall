use std::{error::Error, fmt, path::Path, time::Duration};

use shared::{
    config::{
        BindNetwork, ChallengeConfig, Config, ConfigError, ListenerConfig, MetricsConfig,
        PathRewriteConfig, ProxyConfig, Target,
    },
    policy::{
        PolicyEngine,
        file::{self as policy_file, PolicyLoadError},
    },
};

use clap::Parser;
use humantime::parse_duration;

pub(crate) fn load_config() -> Result<StartupMode, StartupError> {
    let env_config = dotenvy::dotenv();
    match env_config {
        Ok(path) => eprintln!("loaded env from {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {} // No `.env` file.
        Err(e) => eprintln!("warning: failed to load env file: {e}"),
    }
    let args = RawArgs::parse();
    StartupMode::parse(args)
}

#[derive(Debug)]
pub(crate) enum StartupMode {
    Run {
        config: Box<Config>,
        policy_engine: PolicyEngine,
    },
    Version,
    Healthcheck(HealthcheckConfig),
}

impl StartupMode {
    fn parse(args: RawArgs) -> Result<StartupMode, StartupError> {
        if args.version {
            return Ok(StartupMode::Version);
        }
        if args.health {
            return Ok(StartupMode::Healthcheck(HealthcheckConfig {
                metrics_bind: args.metrics_bind.clone(),
            }));
        }

        let policy_fname = args.policy_fname.clone();
        let config = args.into_config()?;
        let default_difficulty = config.proxy.challenge.difficulty;

        let policy_engine = match non_empty(policy_fname) {
            Some(path) => policy_file::load_policy_file(Path::new(&path), default_difficulty)?,
            None => policy_file::default(default_difficulty)?,
        };

        Ok(StartupMode::Run {
            config: Box::new(config),
            policy_engine,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthcheckConfig {
    pub metrics_bind: String,
}

impl RawArgs {
    fn into_config(self) -> Result<Config, ConfigError> {
        let target_host = non_empty(self.target_host);
        let target_sni = non_empty(self.target_sni);
        let path_rewrite = PathRewriteConfig::parse(self.base_prefix, self.strip_base_prefix)?;
        let challenge_config = ChallengeConfig::parse(
            self.challenge_difficulty,
            self.cookie_expiration,
            self.challenge_secret,
            self.cookie_secure,
            self.jwt_restriction_header,
        )?;

        Ok(Config {
            listener: ListenerConfig {
                bind: self.bind,
                network: BindNetwork::parse(self.bind_network)?,
            },
            metrics: MetricsConfig {
                bind: self.metrics_bind,
                network: BindNetwork::parse(self.metrics_bind_network)?,
            },
            proxy: ProxyConfig {
                target: Target::parse(self.target.as_str())?,
                target_host,
                target_sni,
                insecure_skip_verify: self.target_insecure_skip_verify,
                disable_keepalive: self.target_disable_keepalive,
                use_remote_address: self.use_remote_address,
                xff_strip_private: self.xff_strip_private,
                path_rewrite,
                challenge: challenge_config,
            },
        })
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

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

    #[arg(long = "metrics-bind", env = "METRICS_BIND", default_value = ":9090")]
    pub(super) metrics_bind: String,

    #[arg(
        long = "metrics-bind-network",
        env = "METRICS_BIND_NETWORK",
        default_value = "tcp"
    )]
    pub(super) metrics_bind_network: String,

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

    /// TLS SNI hostname for the backend (use "auto" to derive from Host header)
    #[arg(long = "target-sni", env = "TARGET_SNI", default_value = "")]
    pub(super) target_sni: String,

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

    /// If true, read client IP from the network socket instead of X-Real-IP
    #[arg(
        long = "use-remote-address",
        env = "USE_REMOTE_ADDRESS",
        default_value_t = false
    )]
    pub(super) use_remote_address: bool,

    /// If true, strip RFC1918 private IPs from X-Forwarded-For (loopback/CGNAT/link-local always stripped)
    #[arg(
        long = "xff-strip-private",
        env = "XFF_STRIP_PRIVATE",
        default_value_t = true
    )]
    pub(super) xff_strip_private: bool,

    /// Challenge difficulty (number of leading 0 hex digits)
    #[arg(long = "difficulty", env = "DIFFICULTY", default_value_t = 4)]
    pub(super) challenge_difficulty: u32,

    /// How long the cookie for a solved challenge stays valid (e.g. 168h, 1h)
    #[arg(
        long = "cookie-expiration-time",
        env = "COOKIE_EXPIRATION_TIME",
        default_value = "168h",
        value_parser = parse_duration
    )]
    pub(super) cookie_expiration: Duration,

    // TODO mikel: HS512
    /// ED25519 private key seed for signing JWTs. 32 bytes, base64 encoded.
    #[arg(long = "challenge-secret", env = "CHALLENGE_SECRET")]
    pub(super) challenge_secret: Option<String>,

    /// If true, the session cookie will only be sent over HTTPS
    #[arg(long = "cookie-secure", env = "COOKIE_SECURE", default_value_t = false)]
    pub(super) cookie_secure: bool,

    /// Path to policy YAML file. If empty, all requests are challenged at the default difficulty.
    #[arg(long = "policy-fname", env = "POLICY_FNAME", default_value = "")]
    pub(super) policy_fname: String,

    // Startup modes
    /// Run a health check against Blackwall
    #[arg(long = "healthcheck", env = "HEALTHCHECK", default_value_t = false)]
    pub(super) health: bool,

    /// Print Blackwall version
    #[arg(long = "version", env = "VERSION", default_value_t = false)]
    pub(super) version: bool,

    /// If set, the JWT is only valid if the current value of this header matches the value when the JWT was created.
    /// You can use it e.g. to restrict a JWT to the source IP of the user using `X-Real-IP`
    #[arg(
        long = "jwt-restriction-header",
        env = "JWT_RESTRICTION_HEADER",
        default_value = "X-Real-IP"
    )]
    pub(super) jwt_restriction_header: Option<String>,
}

#[derive(Debug)]
pub(crate) enum StartupError {
    Config(ConfigError),
    Policy(PolicyLoadError),
}

impl From<ConfigError> for StartupError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<PolicyLoadError> for StartupError {
    fn from(error: PolicyLoadError) -> Self {
        Self::Policy(error)
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Policy(error) => write!(f, "failed to load policy: {error}"),
        }
    }
}

impl Error for StartupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Policy(error) => Some(error),
        }
    }
}
