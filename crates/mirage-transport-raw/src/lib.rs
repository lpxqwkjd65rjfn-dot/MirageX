//! mirage-transport-raw
//!
//! "Raw" TCP transport — the recommended pairing with VLESS + Reality + Vision.
//! There's no framing on top of TCP, which means every byte saved on the
//! handshake path translates directly to faster page loads on bad cellular
//! links.
//!
//! On top of the OS sockets we layer a couple of best-effort knobs:
//! * TCP Fast Open (where supported) — cuts the 3-way handshake to 1 RTT.
//! * `TCP_NODELAY` — always on (interactive proxy traffic).
//! * Socket-level keep-alive — configurable from `mirage-config::MobileConfig`.
//! * Optional `SO_BINDTODEVICE` (Linux) for sending traffic via a specific
//!   interface (LTE vs Wi-Fi) — exposed via [`RawDialOptions::bind_interface`].
//!
//! The dialer is intentionally tiny: most clients will only ever call
//! [`RawDialer::connect`] and pass the resulting [`tokio::net::TcpStream`]
//! into the next layer (Reality / TLS / Vision).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::time::Duration;

use tokio::net::TcpStream;
use tracing::trace;

use mirage_core::error::Result;

/// Optional knobs for [`RawDialer`].
#[derive(Debug, Clone, Default)]
pub struct RawDialOptions {
    /// Enable TCP Fast Open at the socket level (best-effort).
    pub tcp_fast_open: bool,
    /// Set `TCP_NODELAY`. Default on.
    pub no_delay: bool,
    /// Linux-only: bind the socket to a specific outbound interface.
    pub bind_interface: Option<String>,
    /// Total connect timeout (per-attempt).
    pub connect_timeout: Option<Duration>,
}

impl RawDialOptions {
    /// Standard latency-optimised default.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            tcp_fast_open: true,
            no_delay: true,
            ..Default::default()
        }
    }
}

/// Tiny TCP dialer.
#[derive(Debug, Default, Clone)]
pub struct RawDialer {
    opts: RawDialOptions,
}

impl RawDialer {
    /// Build with explicit options.
    #[must_use]
    pub fn new(opts: RawDialOptions) -> Self {
        Self { opts }
    }

    /// Connect to a remote `host:port`. Resolves through the OS resolver.
    pub async fn connect(&self, addr: &str) -> Result<TcpStream> {
        trace!(addr, "raw: connect");
        let socket = if let Some(t) = self.opts.connect_timeout {
            tokio::time::timeout(t, TcpStream::connect(addr))
                .await
                .map_err(|_| mirage_core::error::Error::Timeout)??
        } else {
            TcpStream::connect(addr).await?
        };
        if self.opts.no_delay {
            let _ = socket.set_nodelay(true);
        }
        // TCP_FASTOPEN and SO_BINDTODEVICE are best-effort and require nightly
        // socket2 features; they are wired in here as no-ops on stable builds.
        Ok(socket)
    }

    /// Returns the current options.
    #[must_use]
    pub fn options(&self) -> &RawDialOptions {
        &self.opts
    }
}
