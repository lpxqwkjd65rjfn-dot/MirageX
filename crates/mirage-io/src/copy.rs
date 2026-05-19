//! Simple bidirectional copy. Wraps `tokio::io::copy_bidirectional` with
//! tracing + an early-exit on either-side EOF.
//!
//! Used as the safe default when the adaptive path can't help (e.g. tiny
//! streams, or when both endpoints are slow enough that the default 8 KiB
//! buffer is fine).

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

/// Pump bytes between `a` and `b` until either side closes.
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let r = tokio::io::copy_bidirectional(a, b).await;
    if let Ok((up, dn)) = r {
        trace!(target: "mirage_io::copy", "bidirectional copy ended: up={up}, dn={dn}");
    }
    r
}
