//! mirage-mobile
//!
//! Adaptive helpers tuned for cellular networks. The defining property of
//! a cellular link is *non-stationary loss + bursty jitter*: the link can be
//! healthy for several seconds, then suffer a 500ms outage, then immediately
//! recover. Anything that hard-fails on a single missed ACK falls apart.
//!
//! This crate provides:
//!
//! * [`RttEstimator`] — a smoothed RTT/RTT-variance estimator with the same
//!   shape RFC 6298 uses for TCP, but exposed as a free-standing struct so
//!   transports that don't rely on the kernel (QUIC, MASQUE, XHTTP) can use it.
//! * [`Pacer`] — a token-bucket pacer that smooths bursts of writes.
//! * [`HappyEyeballs`] — a happy-eyeballs-style parallel dialer that races
//!   IPv6 + IPv4 + multiple resolved addresses; returns the first to connect.
//! * [`Prewarmer`] — a cheap pre-warm pool of outbound connections that
//!   absorbs the latency cost of TLS handshakes for the first user request.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unchecked_time_subtraction,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

pub mod happy_eyeballs;
pub mod pacer;
pub mod prewarm;
pub mod rtt;

pub use happy_eyeballs::HappyEyeballs;
pub use pacer::Pacer;
pub use prewarm::Prewarmer;
pub use rtt::RttEstimator;
