//! Inbound (ingress) configurations.

use serde::{Deserialize, Serialize};

/// A single inbound entry-point.
//
// NOTE: this struct cannot use `deny_unknown_fields` because it `flatten`s a
// tagged enum (`InboundKind`). serde explicitly documents that the two are
// mutually exclusive — combining them makes the outer struct reject the
// flattened tag field. See <https://serde.rs/container-attrs.html>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    /// Stable tag (used by routing rules).
    pub tag: String,
    /// Bind address (e.g. `127.0.0.1:1080`).
    pub listen: String,
    /// Kind-specific configuration.
    #[serde(flatten)]
    pub kind: InboundKind,
    /// Enable the `sniffing` feature: peek at the first bytes of every connection
    /// to detect TLS SNI / HTTP Host and use that as the routing host. Highly
    /// recommended for selective routing.
    #[serde(default = "crate::default_true")]
    pub sniffing: bool,
}

impl Default for InboundConfig {
    fn default() -> Self {
        Self {
            tag: "socks-in".into(),
            listen: "127.0.0.1:1080".into(),
            kind: InboundKind::Socks(SocksInbound::default()),
            sniffing: true,
        }
    }
}

/// Discriminated union of inbound kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundKind {
    /// SOCKS5 (with optional username/password).
    Socks(SocksInbound),
    /// Plain HTTP(S) CONNECT proxy.
    Http(HttpInbound),
    /// Transparent / TUN inbound — receives raw IP packets from the OS routing
    /// table. Available where supported by the host platform.
    Tun(TunInbound),
}

/// SOCKS5 inbound settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SocksInbound {
    /// Allow CONNECT.
    pub allow_tcp: bool,
    /// Allow ASSOCIATE (UDP).
    pub allow_udp: bool,
    /// Optional user/password pairs. When empty, no authentication is required.
    pub users: Vec<UserPass>,
}

/// Plain HTTP CONNECT inbound settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct HttpInbound {
    /// Optional user/password pairs (HTTP Basic).
    pub users: Vec<UserPass>,
    /// Forward non-CONNECT requests as plain HTTP through the chosen outbound.
    pub allow_plain_http: bool,
}

/// TUN inbound settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TunInbound {
    /// Name of the TUN device to create.
    pub name: String,
    /// IPv4 CIDR assigned to the device.
    pub ipv4: String,
    /// IPv6 CIDR assigned to the device.
    pub ipv6: Option<String>,
    /// MTU. Defaults to 1500.
    pub mtu: u16,
    /// Auto-route: install OS routes that direct all traffic into the tunnel.
    pub auto_route: bool,
    /// Strict route: only allow traffic into the tunnel from inside the device's
    /// configured CIDR.
    pub strict_route: bool,
}

impl Default for TunInbound {
    fn default() -> Self {
        Self {
            name: "miragex0".into(),
            ipv4: "198.18.0.1/30".into(),
            ipv6: None,
            mtu: 1500,
            auto_route: true,
            strict_route: false,
        }
    }
}

/// Basic username + password tuple.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPass {
    /// Username.
    pub user: String,
    /// Password.
    pub pass: String,
}
