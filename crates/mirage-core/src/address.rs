//! Universal address type used across the engine. Supports IPv4, IPv6, and FQDN
//! targets so the proxy can lazily resolve domains where appropriate (e.g. when
//! the outbound is a remote proxy that prefers to resolve on its side).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Kind of address. Mirrors the VLESS/Trojan/SOCKS5 address-type byte semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKind {
    /// 4-byte IPv4 address.
    V4,
    /// 16-byte IPv6 address.
    V6,
    /// Length-prefixed UTF-8 domain name (max 255 bytes).
    Domain,
}

/// An address consisting of a host (IP or domain) and a port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    /// The host part — either a resolved IP or an unresolved domain.
    pub host: Host,
    /// The destination port in host-byte order.
    pub port: u16,
}

/// The host part of an [`Address`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Host {
    /// Resolved IP address (v4 or v6).
    Ip(IpAddr),
    /// Unresolved domain name.
    Domain(String),
}

impl Address {
    /// Build a new IPv4 address.
    #[must_use]
    pub fn v4(addr: Ipv4Addr, port: u16) -> Self {
        Self {
            host: Host::Ip(IpAddr::V4(addr)),
            port,
        }
    }

    /// Build a new IPv6 address.
    #[must_use]
    pub fn v6(addr: Ipv6Addr, port: u16) -> Self {
        Self {
            host: Host::Ip(IpAddr::V6(addr)),
            port,
        }
    }

    /// Build a new domain-based address.
    #[must_use]
    pub fn domain<S: Into<String>>(domain: S, port: u16) -> Self {
        Self {
            host: Host::Domain(domain.into()),
            port,
        }
    }

    /// Returns the [`AddressKind`].
    #[must_use]
    pub fn kind(&self) -> AddressKind {
        match &self.host {
            Host::Ip(IpAddr::V4(_)) => AddressKind::V4,
            Host::Ip(IpAddr::V6(_)) => AddressKind::V6,
            Host::Domain(_) => AddressKind::Domain,
        }
    }

    /// Returns `Some(SocketAddr)` if the address is already an IP, else `None`.
    #[must_use]
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match &self.host {
            Host::Ip(ip) => Some(SocketAddr::new(*ip, self.port)),
            Host::Domain(_) => None,
        }
    }

    /// Returns the textual representation of the host.
    #[must_use]
    pub fn host_string(&self) -> String {
        match &self.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.clone(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
            Host::Ip(IpAddr::V4(v4)) => write!(f, "{v4}:{}", self.port),
            Host::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // IPv6 form: [::1]:443
        if let Some(rest) = s.strip_prefix('[') {
            let (addr, port) = rest
                .split_once("]:")
                .ok_or_else(|| Error::InvalidAddress(s.to_string()))?;
            let ip: Ipv6Addr = addr
                .parse()
                .map_err(|_| Error::InvalidAddress(s.to_string()))?;
            let port: u16 = port
                .parse()
                .map_err(|_| Error::InvalidAddress(s.to_string()))?;
            return Ok(Self::v6(ip, port));
        }
        let (host, port_s) = s
            .rsplit_once(':')
            .ok_or_else(|| Error::InvalidAddress(s.to_string()))?;
        let port: u16 = port_s
            .parse()
            .map_err(|_| Error::InvalidAddress(s.to_string()))?;
        if let Ok(v4) = host.parse::<Ipv4Addr>() {
            Ok(Self::v4(v4, port))
        } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
            Ok(Self::v6(v6, port))
        } else {
            // Validate as RFC1035-ish domain: non-empty, no control chars, max 255 bytes.
            if host.is_empty() || host.len() > 255 || host.contains(char::is_whitespace) {
                return Err(Error::InvalidAddress(s.to_string()));
            }
            Ok(Self::domain(host, port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        let a: Address = "1.2.3.4:443".parse().unwrap();
        assert_eq!(a.kind(), AddressKind::V4);
        assert_eq!(a.port, 443);
        assert_eq!(a.to_string(), "1.2.3.4:443");
    }

    #[test]
    fn parse_ipv6() {
        let a: Address = "[2001:db8::1]:8443".parse().unwrap();
        assert_eq!(a.kind(), AddressKind::V6);
        assert_eq!(a.port, 8443);
    }

    #[test]
    fn parse_domain() {
        let a: Address = "example.com:443".parse().unwrap();
        assert_eq!(a.kind(), AddressKind::Domain);
        assert_eq!(a.host_string(), "example.com");
    }

    #[test]
    fn parse_invalid() {
        assert!("no-port".parse::<Address>().is_err());
        assert!("[bad-v6]:443".parse::<Address>().is_err());
        assert!(":443".parse::<Address>().is_err());
    }
}
