//! mirage-io
//!
//! Bidirectional byte-pump primitives used by the engine. The goal is to
//! beat the standard `tokio::io::copy_bidirectional` on three axes:
//!
//! 1. **Buffer sizing**. The Tokio default is 8 KiB. For a 100 ms RTT,
//!    100 Mbit path that's a BDP of 1.25 MB — Tokio's loop spends most of
//!    its time round-tripping. We size buffers from the live
//!    [`mirage_mobile::RttEstimator`] so the buffer roughly tracks the
//!    bandwidth-delay product.
//!
//! 2. **Vectored reads**. Where the source supports `try_read_vectored`,
//!    we use a 2-slot iovec so a single syscall can drain the kernel
//!    receive queue and the user-space tail buffer at once.
//!
//! 3. **Zero-copy splice on Linux** (planned). When *both* endpoints are
//!    plain TCP sockets and no transform layer (TLS, Vision padding, …)
//!    sits between them, `splice(2)` moves bytes inside the kernel and
//!    saves two memcpy passes per packet. The plumbing lives in
//!    [`splice`] and ships behind a `splice` cargo feature in a
//!    follow-up commit; the current revision falls back to the adaptive
//!    user-space copy.
//!
//! All public entry points return `(u64, u64)` — the byte counts sent in
//! each direction — matching `tokio::io::copy_bidirectional` so engine
//! code can swap implementations without touching call sites.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::similar_names
)]

pub mod adaptive;
pub mod copy;
pub mod splice;

pub use adaptive::{copy_bidirectional_adaptive, AdaptiveConfig};
pub use copy::copy_bidirectional;
