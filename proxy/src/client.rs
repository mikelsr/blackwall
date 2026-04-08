use compact_str::{CompactString, ToCompactString};

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem::zeroed;
use std::net::SocketAddr;
use tokio::net::{
    TcpListener, TcpStream, UnixListener, UnixStream, unix::SocketAddr as UnixSocketAddr,
};

const UNIX_PREFIX: &str = "unix:";
const UNAMED_UNIX_SOCKET: &str = "unix:<unnamed>";
const CLIENT_STR_CAPACITY: usize = 40; // Should fit IPv4 and IPv6 addresses, may fit Unix paths.

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
                let mut s = CompactString::with_capacity(CLIENT_STR_CAPACITY);
                if let Some(path) = addr.as_pathname() {
                    s.push_str(UNIX_PREFIX);
                    s.push_str(&path.to_string_lossy());
                } else {
                    s.push_str(UNAMED_UNIX_SOCKET);
                }
                s
            }
        }
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for ClientAddr {
    fn connect_info(target: IncomingStream<'_, TcpListener>) -> Self {
        Self::Tcp(*target.remote_addr())
    }
}

impl Connected<TcpStream> for ClientAddr {
    fn connect_info(target: TcpStream) -> Self {
        target
            .peer_addr()
            .map(Self::Tcp)
            .unwrap_or_else(|_| Self::Tcp(SocketAddr::from(([0, 0, 0, 0], 0))))
    }
}

#[cfg(unix)]
impl Connected<IncomingStream<'_, UnixListener>> for ClientAddr {
    fn connect_info(target: IncomingStream<'_, UnixListener>) -> Self {
        Self::Unix(target.remote_addr().clone())
    }
}

#[cfg(unix)]
impl Connected<UnixStream> for ClientAddr {
    fn connect_info(target: UnixStream) -> Self {
        Self::Unix(target.peer_addr().unwrap_or_else(|_| unsafe { zeroed() }))
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
