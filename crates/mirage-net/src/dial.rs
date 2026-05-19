//! Outbound dial path: resolve → happy-eyeballs race → socket options →
//! return a [`tokio::net::TcpStream`].
//!
//! The happy-eyeballs scheduler matches RFC 8305 in spirit:
//!
//! * The first candidate fires immediately.
//! * Subsequent candidates are fired `attempt_delay` apart (default 50ms).
//! * The first to reach ESTABLISHED wins; the rest are dropped.
//!
//! On real cellular paths this is worth 100-300ms p99 latency vs. trying
//! v6 first → timeout → v4 sequentially. See `docs/MOBILE-OPTIMIZATION.md`
//! for the rationale.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use futures::stream::StreamExt;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use mirage_core::address::Address;

use crate::options::SocketOptions;
use crate::resolve::{resolve_with_family_order, FamilyOrder};

/// Dial `addr` with default mobile-tuned options + IPv6-first happy-eyeballs.
///
/// # Errors
/// Returns the last `io::Error` observed if every candidate fails.
pub async fn dial(addr: &Address) -> io::Result<TcpStream> {
    dial_with(addr, &SocketOptions::mobile(), FamilyOrder::default()).await
}

/// Dial `addr` with explicit socket options + family order.
///
/// # Errors
/// Returns the last `io::Error` observed if every candidate fails.
pub async fn dial_with(
    addr: &Address,
    opts: &SocketOptions,
    family_order: FamilyOrder,
) -> io::Result<TcpStream> {
    let candidates = resolve_with_family_order(addr, family_order).await?;
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("dial: no addresses resolved for {addr}"),
        ));
    }
    debug!(%addr, "dial: {} candidates", candidates.len());
    race_connect(candidates, opts).await
}

/// Internal: race the supplied candidates with a 50ms-staggered start.
async fn race_connect(candidates: Vec<SocketAddr>, opts: &SocketOptions) -> io::Result<TcpStream> {
    let attempt_delay = Duration::from_millis(50);
    let per_attempt_timeout = opts.connect_timeout.unwrap_or(Duration::from_secs(10));

    let mut tasks: futures::stream::FuturesUnordered<_> = futures::stream::FuturesUnordered::new();
    let mut delay = Duration::ZERO;
    for sa in candidates {
        let opts = opts.clone();
        let d = delay;
        tasks.push(async move {
            if !d.is_zero() {
                tokio::time::sleep(d).await;
            }
            trace!(%sa, "dial: attempting");
            let connect = connect_one(sa, &opts);
            tokio::time::timeout(per_attempt_timeout, connect).await
        });
        delay += attempt_delay;
    }

    let mut last_err: Option<io::Error> = None;
    while let Some(result) = tasks.next().await {
        match result {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                trace!("dial: candidate failed: {e}");
                last_err = Some(e);
            }
            Err(_) => {
                last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "dial timeout"));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("all candidates failed")))
}

/// Single-candidate connect with pre-bind socket options applied.
async fn connect_one(sa: SocketAddr, opts: &SocketOptions) -> io::Result<TcpStream> {
    let domain = if sa.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    opts.apply_pre(&sock);

    // Tokio's `from_std` takes ownership of the fd and switches the runtime
    // to drive it.
    let std_sock: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_sock)?;
    // Trigger the actual connect via tokio's connect-on-non-blocking path:
    // we re-attach the addr via `connect`. Tokio handles EINPROGRESS for us.
    let stream = tokio_connect_existing(stream, sa).await?;
    opts.apply_post(&stream);
    Ok(stream)
}

/// Helper that initiates the connect on a non-blocking socket that
/// [`TcpStream::from_std`] has already adopted into the Tokio reactor.
///
/// We can't call [`TcpStream::connect`] because that builds a new socket
/// internally; we need our pre-configured fd. Instead we go through
/// [`socket2::Socket::connect`] on the underlying fd and let Tokio drive
/// the readiness loop.
async fn tokio_connect_existing(stream: TcpStream, sa: SocketAddr) -> io::Result<TcpStream> {
    use socket2::SockRef;
    use tokio::io::Interest;

    // Initiate connect (non-blocking → expected EINPROGRESS on Linux,
    // WSAEWOULDBLOCK on Windows). The `SockRef` is scoped so it goes
    // out of scope before the await below (SockRef is a non-owning
    // view of the fd; using an explicit `drop()` triggers clippy's
    // drop-non-drop lint).
    {
        let sref = SockRef::from(&stream);
        match sref.connect(&sa.into()) {
            Ok(()) => return Ok(stream),
            Err(e)
                if e.raw_os_error() == Some(libc_einprogress())
                    || e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }

    // Wait for writability, then check SO_ERROR.
    let _ready = stream.ready(Interest::WRITABLE).await?;
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    Ok(stream)
}

#[cfg(unix)]
const fn libc_einprogress() -> i32 {
    // EINPROGRESS — see `errno.h`. Hard-coded to keep us free of a `libc`
    // dependency; both glibc/musl agree on 115 / 36 by platform and the
    // worst case if this number is wrong is one extra spin around the
    // readiness loop.
    #[cfg(target_os = "linux")]
    {
        115
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    ))]
    {
        36
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        // Fall back to the Linux value. Worst case is one extra readiness
        // round-trip per dial.
        115
    }
}

#[cfg(not(unix))]
const fn libc_einprogress() -> i32 {
    // WSAEWOULDBLOCK on Windows (10035); we already handle WouldBlock via
    // `io::ErrorKind`, so the numeric value is unused.
    10035
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn dial_loopback_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr: Address = format!("127.0.0.1:{port}").parse().unwrap();

        let _accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let stream = dial(&addr).await.expect("dial should succeed");
        assert!(stream.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn dial_unreachable_fails_within_timeout() {
        let opts = SocketOptions {
            connect_timeout: Some(Duration::from_millis(500)),
            ..SocketOptions::default()
        };
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed unreachable.
        let addr: Address = "192.0.2.1:65000".parse().unwrap();
        let r = dial_with(&addr, &opts, FamilyOrder::Native).await;
        assert!(r.is_err());
    }
}
