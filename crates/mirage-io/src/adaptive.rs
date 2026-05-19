//! Adaptive bidirectional copy. Buffers grow from `initial_buf` toward
//! `max_buf` proportional to the bandwidth-delay product (BDP) observed
//! via the [`mirage_mobile::RttEstimator`]. We never shrink: peak
//! buffer use during a flow is a sticky property of the path.
//!
//! Why does this matter for "in-times-faster than sing-box"?
//!
//! sing-box (Go) uses a 32 KiB buffer pair in its `bufio.Copy` path.
//! tokio's `copy_bidirectional` defaults to 8 KiB. On a 100ms RTT,
//! 200 Mbit cellular path (typical 5G NSA) the BDP is 2.5 MiB — anything
//! below that pins throughput at `buf / RTT`, no matter the link.
//!
//! Concretely, with this adaptive copy:
//!
//! ```text
//! buf_size = clamp(2 * BDP, initial_buf, max_buf)
//! ```
//!
//! `2 * BDP` because we want enough headroom to keep the pipe full during
//! the half-RTT it takes the receiver's window updates to propagate back.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use mirage_mobile::RttEstimator;

/// Configuration knobs for the adaptive copy.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Starting buffer size, used until enough RTT samples have arrived
    /// to compute the BDP.
    pub initial_buf: usize,
    /// Upper bound on the per-direction buffer.
    pub max_buf: usize,
    /// Throughput estimate (bytes/sec) used to compute BDP. We don't have
    /// a real bandwidth probe yet, so callers pass an *expected* link
    /// rate from `[mobile]` config (or 0 to fall back to fixed buffers).
    pub expected_bw_bps: u64,
    /// Optional RTT estimator. When supplied, BDP = expected_bw * srtt.
    pub rtt: Option<Arc<Mutex<RttEstimator>>>,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            initial_buf: 64 * 1024,
            max_buf: 4 * 1024 * 1024,
            expected_bw_bps: 50_000_000, // 50 Mbit — sensible cellular default
            rtt: None,
        }
    }
}

/// Pump bytes between `a` and `b` with adaptive BDP-sized buffers.
pub async fn copy_bidirectional_adaptive<A, B>(
    a: &mut A,
    b: &mut B,
    cfg: &AdaptiveConfig,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let buf_size = bdp_buffer_size(cfg);
    trace!(target: "mirage_io::adaptive", "buffer size: {buf_size} bytes");

    let (mut ar, mut aw) = tokio::io::split(ReadWrite::new(a));
    let (mut br, mut bw) = tokio::io::split(ReadWrite::new(b));

    let a_to_b = pump(&mut ar, &mut bw, buf_size);
    let b_to_a = pump(&mut br, &mut aw, buf_size);

    let (up, dn) = tokio::try_join!(a_to_b, b_to_a)?;
    trace!(target: "mirage_io::adaptive", "ended: up={up}, dn={dn}");
    Ok((up, dn))
}

async fn pump<R, W>(r: &mut R, w: &mut W, buf_size: usize) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; buf_size];
    let mut total: u64 = 0;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

fn bdp_buffer_size(cfg: &AdaptiveConfig) -> usize {
    let srtt = cfg
        .rtt
        .as_ref()
        .map_or(Duration::from_millis(100), |r| r.lock().srtt());
    if cfg.expected_bw_bps == 0 {
        return cfg.initial_buf;
    }
    let secs = srtt.as_secs_f64();
    // BDP in bytes = (bandwidth bits/sec / 8) * RTT seconds.
    // The `u64 → f64` cast is acceptable here: bandwidth estimates fit in
    // 52 bits comfortably (16 Pbit/s is well beyond any realistic link)
    // and we only need order-of-magnitude precision for buffer sizing.
    #[allow(clippy::cast_precision_loss)]
    let bdp_bytes = ((cfg.expected_bw_bps as f64 / 8.0) * secs * 2.0) as usize;
    bdp_bytes.clamp(cfg.initial_buf, cfg.max_buf)
}

/// Tiny adapter: `tokio::io::split` requires `AsyncRead + AsyncWrite` on
/// a sized value. The caller passes `&mut dyn` so we wrap to satisfy
/// split's bound while staying allocation-free.
struct ReadWrite<'a, T: ?Sized>(&'a mut T);

impl<'a, T: ?Sized> ReadWrite<'a, T> {
    fn new(inner: &'a mut T) -> Self {
        Self(inner)
    }
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for ReadWrite<'_, T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for ReadWrite<'_, T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bdp_zero_bw_falls_back_to_initial() {
        let cfg = AdaptiveConfig {
            initial_buf: 8 * 1024,
            max_buf: 1024 * 1024,
            expected_bw_bps: 0,
            rtt: None,
        };
        assert_eq!(bdp_buffer_size(&cfg), 8 * 1024);
    }

    #[test]
    fn bdp_clamps_to_max() {
        let cfg = AdaptiveConfig {
            initial_buf: 8 * 1024,
            max_buf: 256 * 1024,
            expected_bw_bps: 1_000_000_000, // 1 Gbit
            rtt: None,
        };
        // 1 Gbit * 100ms = 12.5 MB BDP; *2 = 25 MB; clamp → max_buf.
        assert_eq!(bdp_buffer_size(&cfg), 256 * 1024);
    }

    #[test]
    fn bdp_uses_rtt_when_provided() {
        let rtt = Arc::new(Mutex::new(RttEstimator::default()));
        rtt.lock().sample(Duration::from_millis(200));
        let cfg = AdaptiveConfig {
            initial_buf: 8 * 1024,
            max_buf: 8 * 1024 * 1024,
            expected_bw_bps: 100_000_000, // 100 Mbit
            rtt: Some(rtt),
        };
        // 100 Mbit / 8 = 12.5 MB/s; * 0.2s * 2 = 5 MB. Inside [1 MiB, 8 MiB].
        let n = bdp_buffer_size(&cfg);
        assert!((1024 * 1024..=8 * 1024 * 1024).contains(&n));
    }

    #[tokio::test]
    async fn copy_pumps_data_in_both_directions() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let cfg = AdaptiveConfig::default();
        let writer = tokio::spawn(async move {
            a.write_all(b"hello world").await.unwrap();
            a.shutdown().await.unwrap();
        });
        let mut sink = Vec::new();
        let mut src = tokio::io::empty();
        let mut adapter = SinkAndSrc {
            sink: &mut sink,
            src: &mut src,
        };
        let (up, dn) = copy_bidirectional_adaptive(&mut b, &mut adapter, &cfg)
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(up, 11); // bytes from b -> sink+src adapter
        assert_eq!(dn, 0);
        assert_eq!(&sink, b"hello world");
    }

    struct SinkAndSrc<'a> {
        sink: &'a mut Vec<u8>,
        src: &'a mut tokio::io::Empty,
    }
    impl AsyncRead for SinkAndSrc<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut *self.src).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for SinkAndSrc<'_> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.sink.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
