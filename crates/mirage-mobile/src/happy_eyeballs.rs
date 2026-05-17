//! Happy-Eyeballs dialer: races multiple resolved addresses (IPv6 first,
//! IPv4 fallback) and returns the first successful connection.

use std::net::SocketAddr;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tracing::trace;

/// Happy-eyeballs dialer. Default delay between the first IPv6 attempt and
/// the first IPv4 attempt is 50ms (per RFC 8305 §5).
#[derive(Debug, Clone)]
pub struct HappyEyeballs {
    /// Delay before the next-protocol family is tried.
    pub attempt_delay: Duration,
    /// Per-attempt connect timeout.
    pub per_attempt_timeout: Duration,
}

impl Default for HappyEyeballs {
    fn default() -> Self {
        Self {
            attempt_delay: Duration::from_millis(50),
            per_attempt_timeout: Duration::from_secs(5),
        }
    }
}

impl HappyEyeballs {
    /// Race the supplied addresses. Returns the first to connect.
    ///
    /// # Errors
    /// Returns the last `std::io::Error` observed if every attempt fails.
    pub async fn connect(
        &self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> std::io::Result<TcpStream> {
        let mut futs = FuturesUnordered::new();
        let mut delay = Duration::ZERO;
        let mut last_err: Option<std::io::Error> = None;
        for sa in addrs {
            let timeout = self.per_attempt_timeout;
            let d = delay;
            futs.push(async move {
                if !d.is_zero() {
                    tokio::time::sleep(d).await;
                }
                trace!(%sa, "happy-eyeballs: attempt");
                tokio::time::timeout(timeout, TcpStream::connect(sa)).await
            });
            delay += self.attempt_delay;
        }

        while let Some(res) = futs.next().await {
            match res {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => {
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "attempt timeout",
                    ));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addresses")
        }))
    }
}
