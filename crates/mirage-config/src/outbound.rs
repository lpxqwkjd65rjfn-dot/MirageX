//! Outbound (egress) configurations. Mirrors the Xray outbound protocol set.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::transport::TransportSettings;

/// A single outbound.
//
// NOTE: this struct cannot use `deny_unknown_fields` because it `flatten`s a
// tagged enum (`OutboundKind`). serde explicitly documents that the two are
// mutually exclusive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// Stable tag referenced by routing rules.
    pub tag: String,
    /// Kind-specific settings.
    #[serde(flatten)]
    pub kind: OutboundKind,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            tag: "direct".into(),
            kind: OutboundKind::Direct(DirectOutbound::default()),
        }
    }
}

/// Outbound protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutboundKind {
    /// Direct egress (no encryption / forwarding).
    Direct(DirectOutbound),
    /// Block — drops the traffic immediately.
    Block,
    /// DNS — answers DNS queries locally instead of forwarding.
    Dns,
    /// VLESS — supports Reality / XTLS-Vision / XHTTP / WebSocket / gRPC / Raw.
    Vless(VlessOutbound),
    /// VMess (legacy, for compatibility).
    Vmess(VmessOutbound),
    /// Trojan.
    Trojan(TrojanOutbound),
    /// Shadowsocks.
    Shadowsocks(ShadowsocksOutbound),
    /// SOCKS5 forwarding (chain).
    Socks(SocksOutbound),
    /// HTTP CONNECT forwarding (chain).
    Http(HttpOutbound),
}

/// Direct outbound settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DirectOutbound {
    /// How freedom-style direct resolves domains.
    pub domain_strategy: FreedomDomainStrategy,
    /// Optional local interface or source address to bind to.
    pub bind: Option<String>,
}

/// Freedom-style direct outbound domain strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FreedomDomainStrategy {
    /// Use the OS resolver as-is.
    #[default]
    AsIs,
    /// Prefer IPv4 (IPv4 first, IPv6 fallback).
    UseIp,
    /// Prefer IPv4 only.
    UseIpv4,
    /// Prefer IPv6 only.
    UseIpv6,
}

/// VLESS outbound configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessOutbound {
    /// Remote server `host:port`.
    pub server: String,
    /// User identifier (UUID, in canonical text form).
    pub uuid: Uuid,
    /// Encryption mode. For VLESS this is always `none`, but is configurable so
    /// experimental ciphers (e.g. post-quantum hybrids) can be slotted in later.
    #[serde(default = "default_vless_encryption")]
    pub encryption: String,
    /// Flow control marker. The most relevant values are:
    /// * empty / `none`        — plain VLESS
    /// * `xtls-rprx-vision`    — XTLS-Vision (recommended with Reality + Raw TCP)
    #[serde(default)]
    pub flow: String,
    /// TLS settings — including SNI, ALPN, fingerprint, certificate pinning.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Reality TLS settings — only used when `tls` is empty or `security = "reality"`.
    #[serde(default)]
    pub reality: Option<RealityConfig>,
    /// Transport settings (Raw / WebSocket / gRPC / HTTPUpgrade / XHTTP).
    #[serde(default)]
    pub transport: TransportSettings,
}

fn default_vless_encryption() -> String {
    "none".into()
}

/// VMess outbound configuration (kept for backward compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessOutbound {
    /// Remote server `host:port`.
    pub server: String,
    /// User identifier (UUID).
    pub uuid: Uuid,
    /// AlterID. Must be `0` for AEAD (recommended).
    #[serde(default)]
    pub alter_id: u16,
    /// Stream cipher (e.g. `aes-128-gcm`, `chacha20-poly1305`, `auto`, `none`).
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// TLS settings.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Transport settings.
    #[serde(default)]
    pub transport: TransportSettings,
}

fn default_vmess_security() -> String {
    "auto".into()
}

/// Trojan outbound configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanOutbound {
    /// Remote server `host:port`.
    pub server: String,
    /// Pre-shared password.
    pub password: String,
    /// TLS settings (Trojan mandates TLS).
    pub tls: TlsConfig,
    /// Optional Reality settings (overrides plain TLS).
    #[serde(default)]
    pub reality: Option<RealityConfig>,
    /// Transport settings.
    #[serde(default)]
    pub transport: TransportSettings,
}

/// Shadowsocks outbound configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksOutbound {
    /// Remote server `host:port`.
    pub server: String,
    /// Cipher selection.
    pub method: ShadowsocksCipher,
    /// Password.
    pub password: String,
    /// AEAD2022 extra `psk`s for multi-user mode.
    #[serde(default)]
    pub psks: Vec<String>,
    /// UoT (UDP over TCP) — wraps UDP datagrams in the TCP relay stream.
    #[serde(default)]
    pub uot: bool,
}

/// Shadowsocks cipher.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowsocksCipher {
    /// `aes-128-gcm`
    Aes128Gcm,
    /// `aes-256-gcm`
    Aes256Gcm,
    /// `chacha20-ietf-poly1305`
    Chacha20Ietf,
    /// `xchacha20-ietf-poly1305`
    XChacha20Ietf,
    /// `2022-blake3-aes-128-gcm`
    Aead2022Blake3Aes128,
    /// `2022-blake3-aes-256-gcm`
    Aead2022Blake3Aes256,
    /// `2022-blake3-chacha20-poly1305`
    Aead2022Blake3Chacha20,
    /// Plain (no encryption — for chaining purposes only).
    None,
}

/// SOCKS5 outbound (chain).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SocksOutbound {
    /// `host:port` of the upstream SOCKS5 proxy.
    pub server: String,
    /// Optional username.
    pub user: Option<String>,
    /// Optional password.
    pub pass: Option<String>,
}

/// HTTP CONNECT outbound (chain).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct HttpOutbound {
    /// `host:port` of the upstream HTTP proxy.
    pub server: String,
    /// Optional username.
    pub user: Option<String>,
    /// Optional password.
    pub pass: Option<String>,
    /// Use TLS to talk to the upstream proxy (HTTPS proxy).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Generic TLS configuration block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// SNI to send. When empty, the server hostname is used.
    pub server_name: Option<String>,
    /// ALPN protocol preferences (e.g. `["h2", "http/1.1"]`).
    pub alpn: Vec<String>,
    /// JA3 / utls fingerprint to emulate, e.g. `chrome`, `firefox`, `safari`,
    /// `random`, `ios`. When empty, rustls' native fingerprint is used.
    pub fingerprint: Option<String>,
    /// Skip certificate verification (NEVER recommended outside of testing).
    pub insecure: bool,
    /// PEM-encoded CA bundle. When empty, system roots are used.
    pub ca: Option<String>,
    /// Certificate pinning: SHA-256 of the leaf cert's SPKI in lower-case hex.
    pub pin_sha256: Vec<String>,
    /// Enable TLS 1.3 0-RTT early data.
    pub enable_early_data: bool,
}

/// Reality TLS configuration block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    /// SNI / target hostname to forge in the ClientHello.
    pub server_name: String,
    /// Server's Reality public key (X25519, hex).
    pub public_key: String,
    /// Optional short id (hex). Empty when not set by the server.
    #[serde(default)]
    pub short_id: String,
    /// Optional spider X session — used by the Vision flow to match server-side
    /// expectations (the "uTLS spider" path).
    #[serde(default)]
    pub spider_x: String,
    /// Fingerprint to forge in the outer ClientHello (e.g. `chrome`, `firefox`).
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    /// ALPN preference for the outer hello.
    #[serde(default)]
    pub alpn: Vec<String>,
}

fn default_fingerprint() -> String {
    "chrome".into()
}
