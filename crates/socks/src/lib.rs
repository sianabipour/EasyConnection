//! Local SOCKS4/4a/5 and HTTP CONNECT proxy.

mod error;
mod http_connect;
mod nodelay;
mod server;
mod socks4;
mod socks5;
mod upstream;

pub use error::SocksError;
pub use nodelay::set_nodelay;
pub use server::{ProxyHandles, ProxyServer, ProxyStats};
pub use socks5::Socks5Auth;
pub use upstream::{UpstreamConnector, UpstreamIo};

pub type Result<T> = std::result::Result<T, SocksError>;
