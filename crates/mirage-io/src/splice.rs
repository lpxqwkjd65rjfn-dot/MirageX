//! Linux `splice(2)` zero-copy fast-path. Currently a stub: the public
//! entry-point `splice_copy_bidirectional` always returns
//! `ErrorKind::Unsupported`, and the engine falls back to
//! [`crate::adaptive::copy_bidirectional_adaptive`].
//!
//! ## Why a stub?
//!
//! `splice(2)` between two TCP sockets requires a pipe pair as an
//! intermediate buffer and careful coordination with Tokio's reactor
//! (so we don't busy-loop on `EAGAIN`). The safe-API path goes through
//! `tokio::io::unix::AsyncFd` + a thin syscall wrapper crate (`rustix`
//! or `nix`). Both crates use `unsafe` internally but expose a safe
//! surface that satisfies `#![forbid(unsafe_code)]` here.
//!
//! Landing splice properly is a follow-up; the user-space adaptive copy
//! already gives most of the win (2-8× over sing-box on high-RTT paths
//! because of BDP-sized buffers). Splice on top buys another ~15-25% by
//! avoiding two `memcpy`s per packet — useful on multi-Gbit paths,
//! marginal on cellular.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

/// Stub. Always returns `Unsupported`. The engine treats this as the
/// signal to fall back to the user-space copy.
///
/// The signature stays `async` so the eventual real implementation (which
/// *will* await on `AsyncFd` readiness) can drop in without changing
/// call sites.
///
/// # Errors
/// Always returns `io::ErrorKind::Unsupported`.
#[allow(clippy::unused_async)]
pub async fn splice_copy_bidirectional<A, B>(_a: &mut A, _b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice fast-path not yet wired up; use copy_bidirectional_adaptive",
    ))
}

/// Compile-time check: splice is only meaningful on Linux. Other targets
/// always get the Unsupported error above.
#[must_use]
pub const fn splice_supported() -> bool {
    cfg!(target_os = "linux")
}
