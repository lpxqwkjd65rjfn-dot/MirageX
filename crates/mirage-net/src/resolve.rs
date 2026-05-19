//! Address resolution + family ordering.
//!
//! We don't ship our own resolver yet — the OS resolver is fine on every
//! platform except Android (where TUN inbounds need an in-process resolver
//! to avoid loops). Caching + TTL handling will land alongside the Android
//! TUN inbound.
//!
//! What this module *does* do, however, is *order* the resolved addresses
//! so the happy-eyeballs dialer races them sensibly:
//!
//! * [`FamilyOrder::Ipv6First`] (default) — RFC 8305 §4: try v6 then v4.
//! * [`FamilyOrder::Ipv4First`] — useful on networks where v6 is
//!   misconfigured (carrier-grade NATs sometimes leak v6 with no working
//!   default route).
//! * [`FamilyOrder::Native`] — keep the resolver's order untouched.
//! * [`FamilyOrder::Interleaved`] — alternate families. Reduces tail latency
//!   when one family is much slower but still functional.

use std::io;
use std::net::SocketAddr;

use mirage_core::address::{Address, Host};
use tokio::net::lookup_host;

/// Preferred address-family order for the happy-eyeballs dialer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FamilyOrder {
    /// IPv6 first, IPv4 after. RFC 8305 default.
    #[default]
    Ipv6First,
    /// IPv4 first.
    Ipv4First,
    /// Use whatever order the resolver returned.
    Native,
    /// Interleave families round-robin.
    Interleaved,
}

/// Resolve `addr` to a vector of `SocketAddr` candidates, sorted IPv6-first.
pub async fn resolve(addr: &Address) -> io::Result<Vec<SocketAddr>> {
    resolve_with_family_order(addr, FamilyOrder::default()).await
}

/// Resolve `addr` with a specific family ordering.
pub async fn resolve_with_family_order(
    addr: &Address,
    order: FamilyOrder,
) -> io::Result<Vec<SocketAddr>> {
    let raw = match &addr.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, addr.port)],
        Host::Domain(d) => lookup_host((d.as_str(), addr.port)).await?.collect(),
    };
    Ok(reorder(raw, order))
}

fn reorder(mut addrs: Vec<SocketAddr>, order: FamilyOrder) -> Vec<SocketAddr> {
    match order {
        FamilyOrder::Native => addrs,
        FamilyOrder::Ipv6First => {
            addrs.sort_by_key(|a| u8::from(a.is_ipv4()));
            addrs
        }
        FamilyOrder::Ipv4First => {
            addrs.sort_by_key(|a| u8::from(a.is_ipv6()));
            addrs
        }
        FamilyOrder::Interleaved => {
            let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
            let mut out = Vec::with_capacity(v6.len() + v4.len());
            let mut v6 = v6.into_iter();
            let mut v4 = v4.into_iter();
            loop {
                match (v6.next(), v4.next()) {
                    (None, None) => break,
                    (Some(a), Some(b)) => {
                        out.push(a);
                        out.push(b);
                    }
                    (Some(a), None) => out.push(a),
                    (None, Some(b)) => out.push(b),
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn sa4(b: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, b)), 443)
    }
    fn sa6(b: u8) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(b))),
            443,
        )
    }

    #[test]
    fn v6_first_keeps_v6_before_v4() {
        let r = reorder(vec![sa4(1), sa6(1), sa4(2), sa6(2)], FamilyOrder::Ipv6First);
        assert!(r[0].is_ipv6() && r[1].is_ipv6());
        assert!(r[2].is_ipv4() && r[3].is_ipv4());
    }

    #[test]
    fn v4_first_keeps_v4_before_v6() {
        let r = reorder(vec![sa6(1), sa4(1), sa6(2), sa4(2)], FamilyOrder::Ipv4First);
        assert!(r[0].is_ipv4() && r[1].is_ipv4());
        assert!(r[2].is_ipv6() && r[3].is_ipv6());
    }

    #[test]
    fn interleaved_alternates_families() {
        let r = reorder(
            vec![sa6(1), sa6(2), sa4(1), sa4(2)],
            FamilyOrder::Interleaved,
        );
        assert!(r[0].is_ipv6());
        assert!(r[1].is_ipv4());
        assert!(r[2].is_ipv6());
        assert!(r[3].is_ipv4());
    }

    #[tokio::test]
    async fn resolve_ip_literal_is_synthesised() {
        let addr: Address = "127.0.0.1:1080".parse().unwrap();
        let r = resolve(&addr).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].port(), 1080);
    }
}
