//! Direct outbound — opens a plain TCP connection to the destination via
//! `mirage-net`, so the configured socket-options policy (including
//! happy-eyeballs racing of v4/v6 candidates) applies.

use async_trait::async_trait;
use tracing::trace;

use mirage_config::mobile::MobileConfig;
use mirage_config::outbound::DirectOutbound;
use mirage_core::error::{Error, Result};
use mirage_net::options::SocketOptions;
use mirage_net::resolve::FamilyOrder;

use crate::dispatcher::{DuplexStream, Outbound, Session};
use crate::net::options_from_mobile;

/// Direct outbound implementation.
pub struct Direct {
    tag: String,
    opts: SocketOptions,
    family_order: FamilyOrder,
    _cfg: DirectOutbound,
}

impl Direct {
    /// Construct a direct outbound from its configuration + mobile policy.
    #[must_use]
    pub fn new(tag: String, cfg: DirectOutbound, mobile: &MobileConfig) -> Self {
        Self {
            tag,
            opts: options_from_mobile(mobile),
            family_order: FamilyOrder::default(),
            _cfg: cfg,
        }
    }
}

#[async_trait]
impl Outbound for Direct {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(&self, session: &Session) -> Result<Box<dyn DuplexStream>> {
        if !matches!(session.network, mirage_core::network::Network::Tcp) {
            return Err(Error::Other(
                "direct outbound: UDP not yet implemented".into(),
            ));
        }
        trace!(?session.destination, tag = %self.tag, "direct: dialing");
        let stream =
            mirage_net::dial::dial_with(&session.destination, &self.opts, self.family_order)
                .await
                .map_err(Error::Io)?;
        Ok(Box::new(stream))
    }
}
