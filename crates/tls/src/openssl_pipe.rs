//! TLS via the system OpenSSL library (`libssl`), in-process.
//!
//! Spawning `openssl s_client` for every tunneled TCP flow was both slow (process
//! + handshake on the first request) and unstable (zombie/fd exhaustion, app crash).

use std::pin::Pin;
use std::time::Duration;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::fingerprint::encode_alpn_wire;
use crate::tcp::connect_tcp;
use crate::{alpn_for_profile, warn_insecure, DialRequest, Result, TransportError};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);

pub async fn connect(req: &DialRequest) -> Result<SslStream<TcpStream>> {
    warn_insecure(req);
    let tcp = connect_tcp(&req.host, req.port).await?;
    let sni = req.sni();
    let alpn = alpn_for_profile(req.tls.fingerprint, &req.tls.alpn, req.transport);

    let mut builder = SslConnector::builder(SslMethod::tls_client()).map_err(tls_err)?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(tls_err)?;
    if !req.tls.verify {
        builder.set_verify(SslVerifyMode::NONE);
    }
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(&encode_alpn_wire(&alpn))
            .map_err(tls_err)?;
    }

    let connector = builder.build();
    let ssl = connector
        .configure()
        .map_err(tls_err)?
        .into_ssl(&sni)
        .map_err(tls_err)?;
    let mut stream = SslStream::new(ssl, tcp).map_err(tls_err)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, Pin::new(&mut stream).connect())
        .await
        .map_err(|_| {
            TransportError::Tls(format!(
                "TLS handshake to {}:{} timed out",
                req.host, req.port
            ))
        })?
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    Ok(stream)
}

fn tls_err(err: openssl::error::ErrorStack) -> TransportError {
    TransportError::Tls(err.to_string())
}
