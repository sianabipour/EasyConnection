use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("invalid TUN name `{0}` — helper will only manage `{expected}`", expected = crate::TUN_NAME)]
    InvalidName(String),
    #[error("helper IPC error: {0}")]
    Ipc(String),
    #[error("privileged helper is not running (socket {0})")]
    HelperUnavailable(String),
    #[error("helper rejected request: {0}")]
    HelperRejected(String),
    #[error("{0}")]
    Other(String),
}

impl TunError {
    pub fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }

    pub fn is_disconnect(&self) -> bool {
        match self {
            Self::Io { source, .. } => matches!(
                source.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
            ),
            _ => false,
        }
    }
}

impl From<serde_json::Error> for TunError {
    fn from(e: serde_json::Error) -> Self {
        Self::Ipc(e.to_string())
    }
}
