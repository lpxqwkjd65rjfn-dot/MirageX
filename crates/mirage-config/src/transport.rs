//! Transport settings — XHTTP, gRPC, WebSocket, Raw, HTTPUpgrade. These are the
//! protocols that sit between the outer TLS / Reality layer and the inner VLESS
//! / Trojan / VMess payload.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Top-level transport selector. Defaults to raw TCP because it is the
/// recommended pairing with VLESS + Reality + Vision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum TransportSettings {
    /// Raw TCP — no transport framing.
    Raw(RawSettings),
    /// XHTTP — bidirectional HTTP/2 (or HTTP/3) tunnel; the modern replacement
    /// for the older `splithttp` / `gun` transports.
    Xhttp(XHttpSettings),
    /// HTTP Upgrade — `Upgrade: websocket` style switch but without WS framing
    /// overhead. Useful behind some CDNs.
    HttpUpgrade(HttpUpgradeSettings),
    /// WebSocket — RFC 6455 framed.
    Websocket(WebsocketSettings),
    /// gRPC.
    Grpc(GrpcSettings),
}

impl Default for TransportSettings {
    fn default() -> Self {
        Self::Raw(RawSettings::default())
    }
}

/// Raw TCP transport settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RawSettings {
    /// Enable TCP Fast Open (where supported by the OS).
    pub tcp_fast_open: bool,
    /// Header obfuscation profile (e.g. `none`, `http`).
    pub header: Option<RawHeader>,
}

/// Optional raw-transport header obfuscation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RawHeader {
    /// No header obfuscation.
    None,
    /// HTTP/1.1 GET/POST request-style header. Configurable host / path.
    Http {
        /// Host header value.
        host: String,
        /// Request path.
        path: String,
        /// Method override (`GET`, `POST`, …). Defaults to `GET`.
        #[serde(default = "default_get")]
        method: String,
    },
}

fn default_get() -> String {
    "GET".into()
}

/// XHTTP transport settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct XHttpSettings {
    /// Server-side path (`/your/secret/path`).
    pub path: String,
    /// Override `:authority` (HTTP/2) / `Host` (HTTP/1.x). When empty the TLS
    /// SNI is used.
    pub host: Option<String>,
    /// XHTTP operating mode: full-duplex `stream`, or upload+download split
    /// `packet`, or `auto` (negotiated on first request).
    pub mode: XHttpMode,
    /// Maximum concurrent streams over a single HTTP/2 connection.
    pub max_streams: u32,
    /// Initial HTTP/2 window size hint.
    pub initial_window_kb: u32,
    /// Custom headers sent on every request.
    pub headers: BTreeMap<String, String>,
    /// Force HTTP/3 (QUIC). Falls back to HTTP/2 when the network blocks UDP.
    pub force_h3: bool,
    /// Force HTTP/2. Mutually exclusive with `force_h3`.
    pub force_h2: bool,
    /// Optional X-Padding strategy (`auto`, `100-1000`, `none`).
    pub padding: Option<String>,
}

impl Default for XHttpSettings {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host: None,
            mode: XHttpMode::Auto,
            max_streams: 64,
            initial_window_kb: 4 * 1024,
            headers: BTreeMap::new(),
            force_h3: false,
            force_h2: false,
            padding: Some("100-1000".into()),
        }
    }
}

/// XHTTP operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum XHttpMode {
    /// Auto-negotiate on first request.
    #[default]
    Auto,
    /// Full-duplex single stream — best on stable links.
    Stream,
    /// Upload + download split into separate streams — better on lossy mobile
    /// links since a stalled upload doesn't pause the download.
    Packet,
}

/// HTTPUpgrade transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct HttpUpgradeSettings {
    /// Path on the upstream HTTP server.
    pub path: String,
    /// `Host:` header override.
    pub host: Option<String>,
    /// Custom additional headers.
    pub headers: BTreeMap<String, String>,
}

/// WebSocket transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebsocketSettings {
    /// Path on the upstream HTTP server.
    pub path: String,
    /// `Host:` header override.
    pub host: Option<String>,
    /// Send early-data bytes inline in the `Sec-WebSocket-Protocol` header to
    /// shave one RTT off the handshake. Default: `true`.
    pub early_data: bool,
    /// Maximum early-data bytes to inline.
    pub max_early_data: u32,
    /// Custom additional headers.
    pub headers: BTreeMap<String, String>,
}

impl Default for WebsocketSettings {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host: None,
            early_data: true,
            max_early_data: 2048,
            headers: BTreeMap::new(),
        }
    }
}

/// gRPC transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct GrpcSettings {
    /// `service` name registered on the upstream proxy.
    pub service_name: String,
    /// Whether to multiplex multiple substreams on one gRPC connection.
    pub multi_mode: bool,
    /// Override `:authority`. Empty = use SNI.
    pub authority: Option<String>,
    /// Healthcheck timeout in seconds. Zero disables.
    pub idle_timeout_secs: u32,
    /// HTTP/2 ping interval in seconds.
    pub ping_interval_secs: u32,
}
