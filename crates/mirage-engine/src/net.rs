//! Engine-wide socket-options policy. Every TCP dial / listen in the
//! engine reaches `mirage-net` through this module so that the `[mobile]`
//! block of the user config actually controls behaviour.
//!
//! The translation lives here (and not in `mirage-net`) because `[mobile]`
//! is engine-policy: it conflates kernel-level TCP knobs with engine-level
//! ones (prewarm pool size, FEC, etc.). `mirage-net` only knows about the
//! kernel layer.

use std::time::Duration;

use mirage_config::mobile::{KeepAliveConfig, MobileConfig};
use mirage_net::options::{KeepAlive, SocketOptions};

/// Build a [`SocketOptions`] from the `[mobile]` block.
#[must_use]
pub fn options_from_mobile(cfg: &MobileConfig) -> SocketOptions {
    if !cfg.enabled {
        return SocketOptions::default();
    }
    let base = SocketOptions::mobile();
    let mut out = base;
    out.keepalive = if cfg.keep_alive.enabled {
        Some(keepalive_from_cfg(&cfg.keep_alive))
    } else {
        None
    };
    // BBR / BBRv2 isn't yet wired through (socket2 doesn't expose
    // TCP_CONGESTION portably on stable), but we record the request so a
    // follow-up that calls setsockopt(TCP_CONGESTION) can pick it up.
    out.congestion_control = match cfg.congestion {
        mirage_config::mobile::CongestionControl::Default => None,
        mirage_config::mobile::CongestionControl::Bbr => Some("bbr".into()),
        mirage_config::mobile::CongestionControl::Bbr2 => Some("bbr2".into()),
        mirage_config::mobile::CongestionControl::Cubic => Some("cubic".into()),
        mirage_config::mobile::CongestionControl::Reno => Some("reno".into()),
        mirage_config::mobile::CongestionControl::Prague => Some("prague".into()),
    };
    out
}

fn keepalive_from_cfg(k: &KeepAliveConfig) -> KeepAlive {
    KeepAlive {
        idle: Duration::from_secs(u64::from(k.idle_secs)),
        interval: Duration::from_secs(u64::from(k.interval_secs)),
        retries: k.probes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_mobile_yields_default_options() {
        let m = MobileConfig {
            enabled: false,
            ..MobileConfig::default()
        };
        let opts = options_from_mobile(&m);
        // Default = every knob None.
        assert!(opts.no_delay.is_none());
        assert!(opts.send_buffer.is_none());
    }

    #[test]
    fn enabled_mobile_yields_mobile_preset() {
        let m = MobileConfig::default();
        let opts = options_from_mobile(&m);
        assert_eq!(opts.no_delay, Some(true));
        assert!(opts.send_buffer.is_some());
    }

    #[test]
    fn keepalive_translates_from_config() {
        let m = MobileConfig::default();
        let opts = options_from_mobile(&m);
        let ka = opts.keepalive.expect("keepalive on");
        assert_eq!(ka.idle, Duration::from_secs(30));
        assert_eq!(ka.interval, Duration::from_secs(10));
        assert_eq!(ka.retries, 3);
    }
}
