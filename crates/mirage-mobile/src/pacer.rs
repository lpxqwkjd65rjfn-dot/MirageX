//! Tiny token-bucket pacer. Used to throttle bursts of writes on transports
//! that the kernel does not pace for us (anything UDP-based). Carriers tend
//! to react badly to ≥1 ms-long microbursts; spreading writes across the same
//! RTT typically translates to a measurable boost in goodput.

use std::time::{Duration, Instant};

/// Token-bucket pacer.
#[derive(Debug, Clone)]
pub struct Pacer {
    /// Target inter-packet interval.
    interval: Duration,
    /// Maximum tokens (burst size, in tokens).
    capacity: u32,
    /// Current tokens.
    tokens: u32,
    /// Last update.
    last: Instant,
}

impl Pacer {
    /// Build a new pacer.
    ///
    /// `tokens_per_sec` is the steady-state rate; `burst` is the maximum
    /// number of tokens that can accumulate while the producer is idle.
    #[must_use]
    pub fn new(tokens_per_sec: u32, burst: u32) -> Self {
        let interval = if tokens_per_sec == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_nanos(1_000_000_000 / u64::from(tokens_per_sec))
        };
        Self {
            interval,
            capacity: burst.max(1),
            tokens: burst.max(1),
            last: Instant::now(),
        }
    }

    /// Try to consume one token. Returns `Ok(())` when a token was available,
    /// or `Err(Duration)` indicating how long the caller should wait before
    /// retrying.
    pub fn try_consume(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last);
        if !self.interval.is_zero() {
            let earned = (elapsed.as_nanos() / self.interval.as_nanos().max(1)) as u32;
            if earned > 0 {
                self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
                self.last = now;
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            Ok(())
        } else {
            Err(self.interval)
        }
    }

    /// Drain N tokens, waiting between each.
    pub async fn pace(&mut self, n: u32) {
        for _ in 0..n {
            while let Err(wait) = self.try_consume() {
                tokio::time::sleep(wait).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_starts_full() {
        let mut p = Pacer::new(1000, 4);
        for _ in 0..4 {
            assert!(p.try_consume().is_ok());
        }
        assert!(p.try_consume().is_err());
    }
}
