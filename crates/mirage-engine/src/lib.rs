//! mirage-engine
//!
//! Glues the rest of the workspace together. Provides:
//!
//! * [`Engine`] — the top-level runtime. Owns the dispatcher, outbound map
//!   and the per-inbound listener tasks.
//! * [`Dispatcher`] — looks up the outbound for a given destination using
//!   the routing rules and forwards a stream to it.
//! * [`inbound::SocksInbound`] — SOCKS5 inbound. The first inbound shipped;
//!   HTTP + TUN inbounds follow in subsequent commits.
//! * [`outbound::VlessOutbound`] — VLESS outbound that wires VLESS + Reality
//!   + Raw / XHTTP / Vision together.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::needless_continue,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value
)]

pub mod dispatcher;
pub mod inbound;
pub mod net;
pub mod outbound;
pub mod router;
pub mod runtime;

pub use dispatcher::Dispatcher;
pub use runtime::Engine;
