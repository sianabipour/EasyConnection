use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("SSH protocol error: {0}")]
    Protocol(String),

    #[error(
        "SSH authentication failed.\n\n\
         The server accepted the TCP connection, but rejected the supplied credentials.\n\n\
         Possible causes:\n\
         • incorrect username\n\
         • incorrect password\n\
         • public-key authentication required\n\
         • account disabled"
    )]
    AuthenticationFailed,

    #[error(
        "SSH host key verification failed.\n\n\
         The server's host key does not match known_hosts (or is unknown under Strict policy).\n\n\
         This can indicate a misconfiguration or a man-in-the-middle attack.\n\n\
         Host: {host}:{port}"
    )]
    HostKeyMismatch { host: String, port: u16 },

    #[error("SSH host key changed for {host}:{port} (known_hosts line {line})")]
    HostKeyChanged {
        host: String,
        port: u16,
        line: usize,
    },

    #[error("connection timed out after {0}s")]
    Timeout(u64),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("secrets error: {0}")]
    Secrets(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Russh(String),
}

impl From<russh::Error> for SshError {
    fn from(value: russh::Error) -> Self {
        Self::Russh(value.to_string())
    }
}

impl From<russh::keys::Error> for SshError {
    fn from(value: russh::keys::Error) -> Self {
        match value {
            russh::keys::Error::KeyChanged { line } => Self::HostKeyChanged {
                host: String::new(),
                port: 0,
                line,
            },
            other => Self::Russh(other.to_string()),
        }
    }
}

impl From<russh::AgentAuthError> for SshError {
    fn from(value: russh::AgentAuthError) -> Self {
        Self::Russh(value.to_string())
    }
}
