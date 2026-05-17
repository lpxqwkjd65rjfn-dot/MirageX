//! mirage-transport-xhttp
//!
//! XHTTP is Xray's modern HTTP-tunnelled transport. It supports three operating
//! modes:
//!
//! * `stream`  — a single full-duplex HTTP/2 (or HTTP/3) stream.
//! * `packet`  — uplink and downlink are split into two unidirectional streams.
//!   On weak cellular signal this measurably improves goodput because a stalled
//!   ACK on the uplink can't pause the downlink stream's data delivery.
//! * `auto`    — the client probes once on connect and picks whichever
//!   mode the server accepts.
//!
//! Compared to the older `splithttp` and `gun` transports, XHTTP:
//!
//! * always speaks HTTP/2 (or H/3) — no HTTP/1.1 fallback chunk dance.
//! * carries the framing as plain `:method POST / :path …` requests with a
//!   single chunked body; nothing about the request shape gives away that
//!   it carries proxy traffic.
//! * supports an `X-Padding` extension to defeat fingerprinting based on
//!   payload-size distributions.
//!
//! This crate currently exposes the public dialer/connector API plus the
//! framing types; the HTTP/2 stream plumbing is wired up against `hyper`
//! and gated behind a feature flag for cross-compilation targets where
//! `hyper-util` cannot be linked (e.g. some `no_std` mobile builds).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use mirage_config::transport::{XHttpMode, XHttpSettings};

/// Materialised XHTTP dial parameters.
#[derive(Debug, Clone)]
pub struct XHttpDial {
    /// Path on the server.
    pub path: String,
    /// Host header / `:authority` override.
    pub host: Option<String>,
    /// Operating mode.
    pub mode: XHttpMode,
    /// Maximum concurrent streams to open against a single H2 connection.
    pub max_streams: u32,
    /// Initial H2 window size (KiB).
    pub initial_window_kb: u32,
    /// Custom request headers.
    pub headers: BTreeMap<String, String>,
    /// `true` when the dialer should attempt HTTP/3 (QUIC) first.
    pub prefer_h3: bool,
    /// `true` when HTTP/2 should be forced (no H/3 attempt).
    pub force_h2: bool,
    /// Optional padding policy (`auto`, `100-1000`, `none`).
    pub padding: Option<String>,
}

impl From<&XHttpSettings> for XHttpDial {
    fn from(s: &XHttpSettings) -> Self {
        Self {
            path: s.path.clone(),
            host: s.host.clone(),
            mode: s.mode,
            max_streams: s.max_streams,
            initial_window_kb: s.initial_window_kb,
            headers: s.headers.clone(),
            prefer_h3: s.force_h3 && !s.force_h2,
            force_h2: s.force_h2,
            padding: s.padding.clone(),
        }
    }
}

/// Compute an X-Padding header value from the configured policy.
///
/// Supported syntax:
/// * `none` / `0` → returns `None`.
/// * `N` → exactly N bytes of padding.
/// * `MIN-MAX` → a uniformly random length in `[MIN, MAX]`.
/// * `auto` (default) → equivalent to `100-1000`.
#[must_use]
pub fn compute_padding(policy: Option<&str>) -> Option<String> {
    use rand::Rng;
    let value = policy.unwrap_or("auto").trim();
    let (lo, hi) = match value {
        "" | "none" | "0" | "off" => return None,
        "auto" => (100u32, 1000u32),
        other if other.contains('-') => {
            let (l, r) = other.split_once('-')?;
            (l.trim().parse().ok()?, r.trim().parse().ok()?)
        }
        other => {
            let n: u32 = other.parse().ok()?;
            (n, n)
        }
    };
    let n = if lo == hi {
        lo
    } else {
        rand::thread_rng().gen_range(lo..=hi)
    };
    Some("X".repeat(n as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_none_is_empty() {
        assert!(compute_padding(Some("none")).is_none());
        assert!(compute_padding(Some("0")).is_none());
    }

    #[test]
    fn padding_fixed_size() {
        assert_eq!(compute_padding(Some("32")).map(|s| s.len()), Some(32));
    }

    #[test]
    fn padding_range_in_bounds() {
        let p = compute_padding(Some("10-20")).expect("padding produced");
        assert!((10..=20).contains(&p.len()));
    }

    #[test]
    fn padding_auto_in_default_range() {
        let p = compute_padding(Some("auto")).expect("padding produced");
        assert!((100..=1000).contains(&p.len()));
    }
}
