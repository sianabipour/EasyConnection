use std::net::IpAddr;

use ipnet::IpNet;

/// RFC1918 / link-local / ULA networks used by "bypass private networks".
pub fn private_cidrs() -> Vec<IpNet> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .map(|s| s.parse().expect("static CIDR"))
    .collect()
}

pub fn split_default_v4() -> [IpNet; 2] {
    ["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()]
}

pub fn split_default_v6() -> [IpNet; 2] {
    ["::/1".parse().unwrap(), "8000::/1".parse().unwrap()]
}

pub fn is_private(addr: IpAddr) -> bool {
    private_cidrs().iter().any(|n| n.contains(&addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rfc1918_is_private() {
        assert!(is_private(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!is_private(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
