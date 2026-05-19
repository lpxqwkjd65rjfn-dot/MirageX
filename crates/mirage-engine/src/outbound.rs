//! Outbound implementations. Each variant is reachable from the engine via
//! [`AnyOutbound`], which serves as a static-dispatch enum so the dispatcher
//! never has to deal with `dyn Outbound`.

use async_trait::async_trait;
use tracing::trace;

use mirage_config::mobile::MobileConfig;
use mirage_config::outbound::{
    DirectOutbound, OutboundConfig, OutboundKind, VlessOutbound as VlessCfg,
};
use mirage_core::error::{Error, Result};

use crate::dispatcher::{DuplexStream, Outbound, Session};

mod direct;
mod vless;

pub use direct::Direct;
pub use vless::Vless;

/// All outbound variants the engine currently supports.
pub enum AnyOutbound {
    /// Direct outbound — no proxying.
    Direct(Direct),
    /// VLESS outbound — supports Reality, Vision, XHTTP, Raw.
    Vless(Vless),
    /// Block outbound — drops every flow.
    Block(BlockOutbound),
}

impl AnyOutbound {
    /// Build from a parsed configuration node + the `[mobile]` policy block.
    pub fn from_config(cfg: &OutboundConfig, mobile: &MobileConfig) -> Result<Self> {
        match &cfg.kind {
            OutboundKind::Direct(d) => Ok(Self::Direct(Direct::new(
                cfg.tag.clone(),
                d.clone(),
                mobile,
            ))),
            OutboundKind::Vless(v) => {
                Ok(Self::Vless(Vless::new(cfg.tag.clone(), v.clone(), mobile)?))
            }
            OutboundKind::Block => Ok(Self::Block(BlockOutbound {
                tag: cfg.tag.clone(),
            })),
            OutboundKind::Dns
            | OutboundKind::Vmess(_)
            | OutboundKind::Trojan(_)
            | OutboundKind::Shadowsocks(_)
            | OutboundKind::Socks(_)
            | OutboundKind::Http(_) => Err(Error::Config(format!(
                "outbound `{}`: protocol not yet implemented in MVP",
                cfg.tag
            ))),
        }
    }
}

#[async_trait]
impl Outbound for AnyOutbound {
    fn tag(&self) -> &str {
        match self {
            Self::Direct(o) => o.tag(),
            Self::Vless(o) => o.tag(),
            Self::Block(o) => &o.tag,
        }
    }

    async fn dial(&self, session: &Session) -> Result<Box<dyn DuplexStream>> {
        match self {
            Self::Direct(o) => o.dial(session).await,
            Self::Vless(o) => o.dial(session).await,
            Self::Block(_) => {
                trace!(?session.destination, "block: dropping");
                Err(Error::RoutingRejected(session.destination.to_string()))
            }
        }
    }
}

/// Trivial block outbound. Always errors with [`Error::RoutingRejected`].
pub struct BlockOutbound {
    pub(crate) tag: String,
}

/// Builder for the [`DirectOutbound`] variant — re-exported as `Direct::new`.
pub fn direct(tag: String, cfg: DirectOutbound, mobile: &MobileConfig) -> Direct {
    Direct::new(tag, cfg, mobile)
}

/// Builder for the VLESS variant — re-exported as `Vless::new`.
pub fn vless(tag: String, cfg: VlessCfg, mobile: &MobileConfig) -> Result<Vless> {
    Vless::new(tag, cfg, mobile)
}
