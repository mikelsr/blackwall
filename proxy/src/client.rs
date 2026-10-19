use compact_str::{CompactString, ToCompactString};

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(unix)]
use tokio::net::unix::SocketAddr as UnixSocketAddr;

const UNIX_PREFIX: &str = "unix:";
const UNAMED_UNIX_SOCKET: &str = "unix:<unnamed>";

/// Represents a client address, either TCP or Unix socket.
#[derive(Clone)]
pub enum ClientAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(UnixSocketAddr),
}

impl ClientAddr {
    /// IP address or Unix socket path.
    pub fn identity(&self) -> CompactString {
        self.to_compact_string()
    }

    fn to_compact_string(&self) -> CompactString {
        match self {
            Self::Tcp(addr) => addr.ip().to_compact_string(),
            #[cfg(unix)]
            Self::Unix(addr) => {
                if let Some(path) = addr.as_pathname() {
                    let mut s = CompactString::new(UNIX_PREFIX);
                    s.push_str(&path.to_string_lossy());
                    s
                } else {
                    CompactString::new(UNAMED_UNIX_SOCKET)
                }
            }
        }
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Tcp(addr) => addr.ip(),
            #[cfg(unix)]
            Self::Unix(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}

impl Display for ClientAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ClientAddr::Tcp(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            ClientAddr::Unix(addr) => {
                write!(
                    f,
                    "unix:{}",
                    if let Some(path) = addr.as_pathname() {
                        path.to_string_lossy()
                    } else {
                        UNAMED_UNIX_SOCKET.into()
                    }
                )
            }
        }
    }
}
