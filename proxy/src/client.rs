use compact_str::{CompactString, ToCompactString};

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io;
use std::mem::zeroed;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::{
    TcpListener, TcpStream, UnixListener, UnixStream, unix::SocketAddr as UnixSocketAddr,
};
use tracing::debug;

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

impl Connected<IncomingStream<'_, TcpListener>> for ClientAddr {
    fn connect_info(target: IncomingStream<'_, TcpListener>) -> Self {
        Self::Tcp(*target.remote_addr())
    }
}

pub struct NoDelayTcpListener(TcpListener);

impl NoDelayTcpListener {
    pub fn new(listener: TcpListener) -> Self {
        Self(listener)
    }
}

impl Listener for NoDelayTcpListener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (TcpStream, SocketAddr) {
        let (stream, addr) = Listener::accept(&mut self.0).await;
        if let Err(err) = stream.set_nodelay(true) {
            debug!(error = %err, "failed to set TCP_NODELAY");
        }
        (stream, addr)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl Connected<IncomingStream<'_, NoDelayTcpListener>> for ClientAddr {
    fn connect_info(target: IncomingStream<'_, NoDelayTcpListener>) -> Self {
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
