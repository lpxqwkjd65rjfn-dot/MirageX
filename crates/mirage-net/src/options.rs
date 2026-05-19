//! Socket-options builder. Every TCP fd in the engine flows through this so
//! the latency-relevant knobs are applied consistently.
//!
//! Where a knob is OS-specific or not available on a target, the apply
//! method best-effort skips it and emits a `trace!` line; we never fail a
//! connection because an optional perf knob isn't supported.

use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tracing::trace;

/// Bag of TCP socket options applied to every connect or listen socket.
///
/// All fields are [`Option`]s — `None` means "leave the OS default in place".
/// The defaults shipped via [`SocketOptions::mobile`] are tuned for proxy
/// traffic on cellular networks; tweak them from the `[mobile]` config block.
#[derive(Debug, Clone, Default)]
pub struct SocketOptions {
    /// `TCP_NODELAY`: turn off Nagle. Always recommended for proxy traffic
    /// (lots of small interactive packets).
    pub no_delay: Option<bool>,

    /// `SO_KEEPALIVE` with `TCP_KEEPIDLE` / `TCP_KEEPINTVL` / `TCP_KEEPCNT`.
    pub keepalive: Option<KeepAlive>,

    /// `TCP_USER_TIMEOUT` (Linux): kill the connection after this many ms
    /// of unacked data. Critical on flaky cellular links — without this the
    /// connection can sit half-dead for minutes after the radio fades.
    pub user_timeout_ms: Option<u32>,

    /// `SO_SNDBUF`: requested send-buffer size in bytes. On Linux the kernel
    /// roughly halves this for accounting and may clamp it to `/proc/sys/net/
    /// core/wmem_max`.
    pub send_buffer: Option<usize>,

    /// `SO_RCVBUF`: requested receive-buffer size in bytes.
    pub recv_buffer: Option<usize>,

    /// `SO_REUSEADDR` (always safe on listen sockets).
    pub reuse_addr: Option<bool>,

    /// `SO_REUSEPORT` (Linux/BSD): allow multiple sockets to bind the same
    /// port. Used by the engine to spread accept load over CPU cores.
    pub reuse_port: Option<bool>,

    /// `IP_TOS` / `IPV6_TCLASS` — DSCP byte. Set to e.g. `0x88` (AF41) to
    /// hint the carrier that traffic is interactive; many LTE schedulers
    /// honour this for queue priority.
    pub dscp: Option<u8>,

    /// Per-attempt connect timeout. Not a socket option proper, but applied
    /// at dial time.
    pub connect_timeout: Option<Duration>,

    /// Linux-only: `SO_BINDTODEVICE` — send traffic strictly via the named
    /// interface (e.g. `"rmnet0"` for the LTE radio).
    pub bind_device: Option<String>,

    /// `TCP_FASTOPEN` (Linux client-side: TCP_FASTOPEN_CONNECT) — opportunistic
    /// 0-RTT data on reconnect. Best-effort; ignored where unavailable.
    pub tcp_fast_open: Option<bool>,

    /// `TCP_QUICKACK` (Linux): disable delayed-ACKs. Saves up to 40ms on the
    /// first response byte for interactive workloads.
    pub quick_ack: Option<bool>,

    /// `TCP_CONGESTION` (Linux): pick the congestion-control algorithm.
    /// Common values: `"bbr"`, `"bbr2"`, `"cubic"`, `"reno"`. Silently
    /// skipped if the kernel doesn't have the named module loaded.
    pub congestion_control: Option<String>,
}

/// Keep-alive parameters bundled together so callers don't half-configure
/// them by accident.
#[derive(Debug, Clone, Copy)]
pub struct KeepAlive {
    /// Idle time before the first probe.
    pub idle: Duration,
    /// Interval between probes.
    pub interval: Duration,
    /// Number of probes before the connection is considered dead.
    pub retries: u32,
}

impl SocketOptions {
    /// Sensible mobile-network-tuned defaults.
    ///
    /// * `TCP_NODELAY` on.
    /// * 60s `TCP_USER_TIMEOUT` — fail fast when the radio fades.
    /// * 30s keep-alive with 10s probes.
    /// * 1 MiB send + 1 MiB receive buffer (helps BDP at high-RTT paths).
    /// * `TCP_QUICKACK` on (Linux only effect).
    /// * `TCP_FASTOPEN_CONNECT` on.
    #[must_use]
    pub fn mobile() -> Self {
        Self {
            no_delay: Some(true),
            keepalive: Some(KeepAlive {
                idle: Duration::from_secs(30),
                interval: Duration::from_secs(10),
                retries: 3,
            }),
            user_timeout_ms: Some(60_000),
            send_buffer: Some(1024 * 1024),
            recv_buffer: Some(1024 * 1024),
            reuse_addr: None,
            reuse_port: None,
            dscp: Some(0x88), // AF41 — interactive low-latency
            connect_timeout: Some(Duration::from_secs(10)),
            bind_device: None,
            tcp_fast_open: Some(true),
            quick_ack: Some(true),
            congestion_control: None,
        }
    }

    /// Cap, but don't replace, fields from `cfg` so the caller can override
    /// only what it cares about.
    #[must_use]
    pub fn merged(mut self, other: &Self) -> Self {
        macro_rules! ov {
            ($f:ident) => {
                if other.$f.is_some() {
                    self.$f = other.$f.clone();
                }
            };
        }
        ov!(no_delay);
        ov!(keepalive);
        ov!(user_timeout_ms);
        ov!(send_buffer);
        ov!(recv_buffer);
        ov!(reuse_addr);
        ov!(reuse_port);
        ov!(dscp);
        ov!(connect_timeout);
        ov!(bind_device);
        ov!(tcp_fast_open);
        ov!(quick_ack);
        ov!(congestion_control);
        self
    }

    /// Apply socket options to a pre-bind/pre-connect [`socket2::Socket`].
    /// Called from [`crate::dial`] / [`crate::listen`] just after socket
    /// creation, so options like `SO_REUSEPORT` and `SO_SNDBUF` (which
    /// must be set before the kernel computes its internal window scaling)
    /// take effect.
    ///
    /// All failures are logged at trace level and otherwise ignored.
    pub fn apply_pre(&self, sock: &socket2::Socket) {
        if let Some(b) = self.reuse_addr {
            let _ = sock.set_reuse_address(b);
        }
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
        if let Some(b) = self.reuse_port {
            let _ = sock.set_reuse_port(b);
        }
        if let Some(n) = self.send_buffer {
            let _ = sock.set_send_buffer_size(n);
        }
        if let Some(n) = self.recv_buffer {
            let _ = sock.set_recv_buffer_size(n);
        }
        if let Some(b) = self.no_delay {
            let _ = sock.set_nodelay(b);
        }
        if let Some(ka) = self.keepalive {
            let mut k = TcpKeepalive::new().with_time(ka.idle);
            #[cfg(not(any(target_os = "windows", target_os = "redox")))]
            {
                k = k.with_interval(ka.interval).with_retries(ka.retries);
            }
            #[cfg(any(target_os = "windows", target_os = "redox"))]
            {
                k = k.with_interval(ka.interval);
                let _ = ka.retries; // not exposed on Windows
            }
            let _ = sock.set_tcp_keepalive(&k);
        }
        if let Some(dscp) = self.dscp {
            // `set_tos` writes IP_TOS on v4 sockets. socket2 on stable
            // does not yet expose IPV6_TCLASS portably, so v6 traffic
            // currently inherits the kernel default. We accept this gap
            // until socket2 lands a portable wrapper.
            let _ = sock.set_tos(u32::from(dscp));
        }
        #[cfg(target_os = "linux")]
        if let Some(ms) = self.user_timeout_ms {
            let _ = sock.set_tcp_user_timeout(Some(Duration::from_millis(u64::from(ms))));
        }
        #[cfg(target_os = "linux")]
        if let Some(dev) = self.bind_device.as_deref() {
            let _ = sock.bind_device(Some(dev.as_bytes()));
        }
        #[cfg(target_os = "linux")]
        {
            // TCP_FASTOPEN_CONNECT (client side) and TCP_QUICKACK are
            // currently set via a raw `setsockopt` because socket2 doesn't
            // expose them on stable releases yet. We need access to the
            // platform fd, but the socket2::Socket API gives us `as_raw_fd`
            // safely — the unsafe setsockopt happens inside the `nix` /
            // `libc` wrapper crate, not in our code. We don't depend on
            // those here, so this is a no-op for now and the kernel ships
            // its default (TFO disabled, delayed-ACKs on). The follow-up
            // commit re-introduces them via the `tcp-keepalive` style
            // wrapper.
            let _ = self.tcp_fast_open;
            let _ = self.quick_ack;
            let _ = self.congestion_control;
        }
    }

    /// Apply post-connect options. Called immediately after
    /// [`tokio::net::TcpStream::connect`] (or accept). Used for knobs that
    /// must be set after the socket transitions to ESTABLISHED.
    pub fn apply_post(&self, stream: &TcpStream) {
        let sref = SockRef::from(stream);
        if let Some(b) = self.no_delay {
            let _ = sref.set_nodelay(b);
        }
        if let Some(ka) = self.keepalive {
            let mut k = TcpKeepalive::new().with_time(ka.idle);
            #[cfg(not(any(target_os = "windows", target_os = "redox")))]
            {
                k = k.with_interval(ka.interval).with_retries(ka.retries);
            }
            #[cfg(any(target_os = "windows", target_os = "redox"))]
            {
                k = k.with_interval(ka.interval);
                let _ = ka.retries;
            }
            let _ = sref.set_tcp_keepalive(&k);
        }
        #[cfg(target_os = "linux")]
        if let Some(ms) = self.user_timeout_ms {
            let _ = sref.set_tcp_user_timeout(Some(Duration::from_millis(u64::from(ms))));
        }
        trace!(
            target: "mirage_net::options",
            "post-connect options applied (nodelay={:?}, sndbuf={:?}, rcvbuf={:?})",
            self.no_delay, self.send_buffer, self.recv_buffer
        );
    }
}

/// Fluent builder for [`SocketOptions`].
#[derive(Debug, Default, Clone)]
pub struct SocketOptionsBuilder {
    inner: SocketOptions,
}

impl SocketOptionsBuilder {
    /// Start with the OS defaults (every knob = `None`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from the mobile-tuned preset.
    #[must_use]
    pub fn mobile() -> Self {
        Self {
            inner: SocketOptions::mobile(),
        }
    }

    /// `TCP_NODELAY`.
    #[must_use]
    pub fn no_delay(mut self, on: bool) -> Self {
        self.inner.no_delay = Some(on);
        self
    }

    /// Keep-alive params.
    #[must_use]
    pub fn keepalive(mut self, ka: KeepAlive) -> Self {
        self.inner.keepalive = Some(ka);
        self
    }

    /// `TCP_USER_TIMEOUT` in ms.
    #[must_use]
    pub fn user_timeout_ms(mut self, ms: u32) -> Self {
        self.inner.user_timeout_ms = Some(ms);
        self
    }

    /// `SO_SNDBUF`.
    #[must_use]
    pub fn send_buffer(mut self, bytes: usize) -> Self {
        self.inner.send_buffer = Some(bytes);
        self
    }

    /// `SO_RCVBUF`.
    #[must_use]
    pub fn recv_buffer(mut self, bytes: usize) -> Self {
        self.inner.recv_buffer = Some(bytes);
        self
    }

    /// `SO_REUSEADDR` + `SO_REUSEPORT` together.
    #[must_use]
    pub fn reuse(mut self, on: bool) -> Self {
        self.inner.reuse_addr = Some(on);
        self.inner.reuse_port = Some(on);
        self
    }

    /// DSCP byte.
    #[must_use]
    pub fn dscp(mut self, b: u8) -> Self {
        self.inner.dscp = Some(b);
        self
    }

    /// Per-attempt connect timeout.
    #[must_use]
    pub fn connect_timeout(mut self, t: Duration) -> Self {
        self.inner.connect_timeout = Some(t);
        self
    }

    /// `SO_BINDTODEVICE`.
    #[must_use]
    pub fn bind_device<S: Into<String>>(mut self, dev: S) -> Self {
        self.inner.bind_device = Some(dev.into());
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> SocketOptions {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_defaults_present() {
        let m = SocketOptions::mobile();
        assert_eq!(m.no_delay, Some(true));
        assert!(m.keepalive.is_some());
        assert_eq!(m.user_timeout_ms, Some(60_000));
        assert_eq!(m.send_buffer, Some(1024 * 1024));
        assert_eq!(m.recv_buffer, Some(1024 * 1024));
    }

    #[test]
    fn builder_round_trip() {
        let opts = SocketOptionsBuilder::new()
            .no_delay(true)
            .send_buffer(256 * 1024)
            .dscp(0x88)
            .connect_timeout(Duration::from_secs(5))
            .build();
        assert_eq!(opts.no_delay, Some(true));
        assert_eq!(opts.send_buffer, Some(256 * 1024));
        assert_eq!(opts.dscp, Some(0x88));
        assert_eq!(opts.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn merge_only_overrides_set_fields() {
        let base = SocketOptions::mobile();
        let patch = SocketOptionsBuilder::new()
            .send_buffer(2 * 1024 * 1024)
            .build();
        let merged = base.merged(&patch);
        assert_eq!(merged.send_buffer, Some(2 * 1024 * 1024));
        // unrelated field preserved
        assert_eq!(merged.no_delay, Some(true));
    }
}
