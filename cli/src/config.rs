use clap::Parser;
use shared::config::{
    BindNetwork, Config, ConfigError, ListenerConfig, PathRewriteConfig, ProxyConfig, Target,
};

pub(crate) fn load_config() -> Result<StartupMode, ConfigError> {
    let _ = dotenvy::dotenv();
    let args = RawArgs::parse();
    StartupMode::parse(args)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum StartupMode {
    Run(Box<Config>),
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

        Ok(StartupMode::Run(Box::new(args.into_config()?)))
    }
}

impl RawArgs {
    fn into_config(self) -> Result<Config, ConfigError> {
        let target_host = if self.target_host.is_empty() {
            None
        } else {
            Some(self.target_host)
        };
        let target_sni = if self.target_sni.is_empty() {
            None
        } else {
            Some(self.target_sni)
        };
        let path_rewrite = PathRewriteConfig::parse(self.base_prefix, self.strip_base_prefix)?;

        Ok(Config {
            listener: ListenerConfig {
                bind: self.bind,
                network: BindNetwork::parse(self.bind_network)?,
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
            },
        })
    }
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

    // Startup modes
    /// Run a health check against Blackwall
    #[arg(long = "healthcheck", env = "HEALTHCHECK", default_value_t = false)]
    pub(super) health: bool,

    /// Print Blackwall version
    #[arg(long = "version", env = "VERSION", default_value_t = false)]
    pub(super) version: bool,
}
