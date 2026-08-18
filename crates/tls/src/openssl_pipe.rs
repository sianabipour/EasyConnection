//! TLS via system `openssl s_client` (Ubuntu 26.04 ships OpenSSL).

use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::{alpn_for_profile, warn_insecure, DialRequest, Result, TransportError};

pub struct OpensslStream {
    stdin: ChildStdin,
    stdout: ChildStdout,
    _child: Child,
}

pub async fn connect(req: &DialRequest) -> Result<OpensslStream> {
    warn_insecure(req);
    let sni = req.sni();
    let alpn = alpn_for_profile(req.tls.fingerprint, &req.tls.alpn, req.transport);
    let mut cmd = Command::new("openssl");
    cmd.arg("s_client")
        .arg("-connect")
        .arg(format!("{}:{}", req.host, req.port))
        .arg("-servername")
        .arg(&sni)
        .arg("-quiet")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if req.tls.verify {
        cmd.arg("-verify_return_error");
    }
    if !alpn.is_empty() {
        cmd.arg("-alpn").arg(alpn.join(","));
    }
    let mut child = cmd.spawn().map_err(|e| {
        TransportError::Tls(format!(
            "failed to spawn openssl s_client ({e}). Install openssl."
        ))
    })?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| TransportError::Tls("openssl stdin missing".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| TransportError::Tls("openssl stdout missing".into()))?;
    Ok(OpensslStream {
        stdin,
        stdout,
        _child: child,
    })
}

impl AsyncRead for OpensslStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for OpensslStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}
