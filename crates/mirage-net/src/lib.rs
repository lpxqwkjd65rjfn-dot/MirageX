//! mirage-net
//!
//! The "narrow waist" between Tokio and every other crate in the engine:
//! a single dial path, a single listen path, and a single place where TCP
//! socket-options (TCP_NODELAY, TCP_FASTOPEN, TCP_USER_TIMEOUT, SO_SNDBUF /
//! RCVBUF, SO_REUSEPORT, IP_BIND_ADDRESS_NO_PORT, DSCP, …) are applied.
//!
//! Why "single place"? Because the wrong default on any one of these knobs
//! costs latency in ways that are hard to see in flame graphs: e.g. the
//! default Linux SNDBUF is too small for a >50ms RTT path and silently
//! pins throughput. By going through this crate we get to set the right
//! defaults *for a mobile-optimised proxy client* — which is a very
//! different set of defaults than the kernel ships with.
//!
//! The dial path additionally:
//!
//! 1. Resolves the target name to a list of `SocketAddr`s (IPv6 + IPv4).
//! 2. Races the addresses with a happy-eyeballs scheduler — first to
//!    connect wins, the rest are dropped. This is a real latency win on
//!    cellular networks where v6 is often slower than v4 (and vice-versa).
//! 3. Applies the configured socket options to the winning socket.
//! 4. Returns a [`tokio::net::TcpStream`] ready for the upper transport.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unnecessary_wraps,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

pub mod dial;
pub mod listen;
pub mod options;
pub mod resolve;

pub use dial::{dial, dial_with};
pub use listen::{listen, listen_with};
pub use options::{SocketOptions, SocketOptionsBuilder};
pub use resolve::{resolve, resolve_with_family_order, FamilyOrder};
