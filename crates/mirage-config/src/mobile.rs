//! Mobile-network adaptation knobs. This block tells the engine how aggressively
//! to fight packet loss, reordering, and jitter — the three things that
//! dominate the experience on weak cellular signal.

use serde::{Deserialize, Serialize};

/// Mobile-network adaptation block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MobileConfig {
    /// Whether the adaptation layer is enabled at all.
    pub enabled: bool,
    /// Congestion-control algorithm to advise at the kernel level (where the OS
    /// supports `TCP_CONGESTION`). Best-effort — silently ignored on platforms
    /// that don't expose the knob.
    pub congestion: CongestionControl,
    /// Pacing configuration (smoothes bursts that trigger cellular shaping).
    pub pacing: PacingConfig,
    /// Connection keep-alive configuration.
    pub keep_alive: KeepAliveConfig,
    /// Retransmit profile (controls the engine's retry / dup-ACK behaviour for
    /// transports that perform retries above the OS, e.g. QUIC).
    pub retransmit: RetransmitProfile,
    /// Whether to enable Multipath QUIC / Multipath TCP for outbound flows
    /// where the OS exposes it (Wi-Fi + LTE handover, etc.).
    pub multipath: MultipathMode,
    /// 0-RTT TLS resumption — saves 1 RTT on every reconnect.
    pub zero_rtt: bool,
    /// Pre-warm pool size (number of pre-established outbound connections kept
    /// hot for instant first-byte delivery).
    pub prewarm: u8,
    /// Adaptive MTU probing. Useful behind LTE/5G access points that fragment
    /// large packets aggressively.
    pub adaptive_mtu: bool,
    /// Smooth roaming: detect interface flaps and migrate live flows without
    /// breaking them (works for QUIC/MASQUE; best-effort for TCP).
    pub smooth_roaming: bool,
    /// Optional forward-error-correction layer (datagram transports only).
    /// `redundancy` is the number of FEC packets sent per N data packets
    /// (`group`). When `group` is `0`, FEC is disabled.
    pub fec_group: u8,
    /// Number of FEC redundancy packets per group.
    pub fec_redundancy: u8,
    /// Number of parallel TCP / QUIC streams per outbound (cellular schedulers
    /// often allocate per-flow bandwidth, so 2–4 parallel streams measurably
    /// beat a single one on lossy links).
    pub parallel_streams: u8,
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            congestion: CongestionControl::Bbr,
            pacing: PacingConfig::default(),
            keep_alive: KeepAliveConfig::default(),
            retransmit: RetransmitProfile::Aggressive,
            multipath: MultipathMode::Auto,
            zero_rtt: true,
            prewarm: 2,
            adaptive_mtu: true,
            smooth_roaming: true,
            fec_group: 0,
            fec_redundancy: 0,
            parallel_streams: 2,
        }
    }
}

/// Congestion-control selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// Whatever the kernel default is — `cubic` on most systems.
    Default,
    /// BBR (v1). Best fit for lossy mobile links.
    #[default]
    Bbr,
    /// BBRv2 (where available).
    Bbr2,
    /// CUBIC. Sensitive to loss; not recommended for mobile.
    Cubic,
    /// Reno.
    Reno,
    /// `prague` (TCP Prague / L4S). Experimental.
    Prague,
}

/// Pacing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PacingConfig {
    /// Master enable.
    pub enabled: bool,
    /// Minimum interval between two writes, in microseconds. Useful when the
    /// remote carrier rate-limits aggressively on burst.
    pub min_inter_packet_us: u32,
    /// Maximum burst size in bytes. Defaults to ~64 KiB (one window).
    pub burst_bytes: u32,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_inter_packet_us: 0,
            burst_bytes: 64 * 1024,
        }
    }
}

/// Keep-alive configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeepAliveConfig {
    /// Master enable.
    pub enabled: bool,
    /// Initial idle time before the first probe, in seconds.
    pub idle_secs: u32,
    /// Interval between subsequent probes, in seconds.
    pub interval_secs: u32,
    /// Number of probes before the connection is declared dead.
    pub probes: u32,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_secs: 30,
            interval_secs: 10,
            probes: 3,
        }
    }
}

/// Retransmit profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RetransmitProfile {
    /// Conservative — close to the QUIC RFC defaults.
    Conservative,
    /// Balanced — sensible defaults for most mobile networks.
    #[default]
    Balanced,
    /// Aggressive — much higher `max_idle_timeout`, faster PTO back-off,
    /// duplicate first packets. Trades wire efficiency for latency.
    Aggressive,
}

/// Multipath operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MultipathMode {
    /// Always single-path.
    Off,
    /// Use multipath when the OS exposes more than one default-route interface.
    #[default]
    Auto,
    /// Force multipath; fail if the OS doesn't expose enough interfaces.
    Force,
}
