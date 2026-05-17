//! RFC-6298-style smoothed RTT / RTT-variance estimator.

use std::time::Duration;

/// Smoothed RTT estimator. Provides `sample(rtt)` for feeding fresh
/// measurements and `srtt()` / `rttvar()` / `pto()` accessors.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT.
    srtt: Duration,
    /// RTT variance.
    rttvar: Duration,
    /// `true` until the first sample is fed in.
    fresh: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Construct an estimator with no samples. `srtt()` returns 100ms until
    /// the first sample is fed in.
    #[must_use]
    pub fn new() -> Self {
        Self {
            srtt: Duration::from_millis(100),
            rttvar: Duration::from_millis(50),
            fresh: true,
        }
    }

    /// Feed a fresh RTT sample.
    pub fn sample(&mut self, sample: Duration) {
        if self.fresh {
            self.srtt = sample;
            self.rttvar = sample / 2;
            self.fresh = false;
            return;
        }
        // RFC 6298: RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|
        //           SRTT  = (1 - alpha) * SRTT  + alpha * RTT
        // alpha = 1/8, beta = 1/4.
        let abs_diff = if self.srtt > sample {
            self.srtt - sample
        } else {
            sample - self.srtt
        };
        self.rttvar = duration_mul_div(self.rttvar, 3, 4) + duration_mul_div(abs_diff, 1, 4);
        self.srtt = duration_mul_div(self.srtt, 7, 8) + duration_mul_div(sample, 1, 8);
    }

    /// Smoothed RTT.
    #[must_use]
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// RTT variance.
    #[must_use]
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Probe Timeout = SRTT + max(4*RTTVAR, k_granularity). Defaults to 1ms grain.
    #[must_use]
    pub fn pto(&self) -> Duration {
        let grain = Duration::from_millis(1);
        self.srtt + std::cmp::max(self.rttvar * 4, grain)
    }
}

fn duration_mul_div(d: Duration, num: u32, denom: u32) -> Duration {
    Duration::from_nanos(u64::from(num) * d.as_nanos() as u64 / u64::from(denom))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_seeds_estimator() {
        let mut r = RttEstimator::new();
        r.sample(Duration::from_millis(200));
        assert_eq!(r.srtt(), Duration::from_millis(200));
        assert_eq!(r.rttvar(), Duration::from_millis(100));
    }

    #[test]
    fn moves_toward_new_samples() {
        let mut r = RttEstimator::new();
        r.sample(Duration::from_millis(100));
        for _ in 0..20 {
            r.sample(Duration::from_millis(50));
        }
        assert!(r.srtt() < Duration::from_millis(100));
        assert!(r.srtt() > Duration::from_millis(50));
    }
}
