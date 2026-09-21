use rt_config::{TlsFingerprintProfile, Transport};

/// Wire-format ALPN for OpenSSL `SSL_CTX_set_alpn_protos`.
pub fn encode_alpn_wire(protos: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in protos {
        let b = p.as_bytes();
        if b.is_empty() || b.len() > 255 {
            continue;
        }
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out
}

/// ALPN list for a fingerprint profile.
///
/// rustls cannot reproduce a browser JA3. These profiles only pick conventional
/// ALPN when the user did not set any. SSH-over-TLS keeps ALPN empty unless the
/// user set it — h2 would break SSH.
pub fn alpn_for_profile(
    profile: TlsFingerprintProfile,
    user: &[String],
    transport: Transport,
) -> Vec<String> {
    if !user.is_empty() {
        return user.to_vec();
    }
    match (profile, transport) {
        (TlsFingerprintProfile::Default | TlsFingerprintProfile::Custom, _) => Vec::new(),
        (
            TlsFingerprintProfile::Chrome
            | TlsFingerprintProfile::Firefox
            | TlsFingerprintProfile::Safari,
            Transport::Wss | Transport::HttpUpgrade,
        ) => vec!["http/1.1".into()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_alpn_wins() {
        let v = alpn_for_profile(
            TlsFingerprintProfile::Chrome,
            &["h2".into()],
            Transport::Wss,
        );
        assert_eq!(v, vec!["h2"]);
    }

    #[test]
    fn ssh_tls_stays_empty() {
        let v = alpn_for_profile(TlsFingerprintProfile::Chrome, &[], Transport::Tls);
        assert!(v.is_empty());
    }

    #[test]
    fn wss_chrome_gets_http11() {
        let v = alpn_for_profile(TlsFingerprintProfile::Chrome, &[], Transport::Wss);
        assert_eq!(v, vec!["http/1.1"]);
    }

    #[test]
    fn alpn_wire_length_prefixed() {
        let w = encode_alpn_wire(&["h2".into(), "http/1.1".into()]);
        assert_eq!(w[0], 2);
        assert_eq!(&w[1..3], b"h2");
        assert_eq!(w[3], 8);
        assert_eq!(&w[4..], b"http/1.1");
    }
}
