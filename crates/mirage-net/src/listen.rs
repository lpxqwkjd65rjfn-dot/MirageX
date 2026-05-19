//! Listener builder. Applies the same socket-options surface that
//! [`crate::dial`] uses, plus listen-specific knobs (`SO_REUSEPORT`,
//! backlog size).
//!
//! `listen()` returns a [`tokio::net::TcpListener`] — the engine wraps
//! each accepted socket in [`crate::options::SocketOptions::apply_post`]
//! before handing it to the inbound handler so per-flow knobs (NODELAY,
//! keep-alive, USER_TIMEOUT) stay attached.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tracing::{debug, trace};

use crate::options::SocketOptions;

/// Default backlog: 1024. Larger than `tokio::net::TcpListener::bind`'s
/// default of 1024 too — kept the same so behaviour is unchanged unless
/// the caller explicitly tunes it.
pub const DEFAULT_BACKLOG: i32 = 1024;

/// Bind a listener with default mobile-tuned options.
///
/// # Errors
/// Forwards any `io::Error` from `socket(2)` / `bind(2)` / `listen(2)`.
pub async fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
    listen_with(addr, &SocketOptions::mobile(), DEFAULT_BACKLOG).await
}

/// Bind a listener with explicit options + backlog.
///
/// # Errors
/// Forwards any `io::Error` from `socket(2)` / `bind(2)` / `listen(2)`.
pub async fn listen_with(
    addr: SocketAddr,
    opts: &SocketOptions,
    backlog: i32,
) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    // For listen sockets SO_REUSEADDR is essentially always wanted; the
    // mobile preset sets it explicitly via merged options.
    let _ = sock.set_reuse_address(true);
    opts.apply_pre(&sock);
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    let std_listener: std::net::TcpListener = sock.into();
    let listener = TcpListener::from_std(std_listener)?;
    debug!(%addr, "listen: bound with backlog={backlog}");
    trace!(
        target: "mirage_net::listen",
        "listen options applied (reuse_port={:?}, sndbuf={:?}, rcvbuf={:?})",
        opts.reuse_port, opts.send_buffer, opts.recv_buffer
    );
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listen_loopback_binds_random_port() {
        let listener = listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() != 0);
    }
}
