//! Direct outbound — opens a plain TCP connection to the destination.

use async_trait::async_trait;
use tracing::trace;

use mirage_config::outbound::DirectOutbound;
use mirage_core::error::{Error, Result};
use mirage_transport_raw::{RawDialOptions, RawDialer};

use crate::dispatcher::{DuplexStream, Outbound, Session};

/// Direct outbound implementation.
pub struct Direct {
    tag: String,
    dialer: RawDialer,
    _cfg: DirectOutbound,
}

impl Direct {
    /// Construct a direct outbound from its configuration.
    #[must_use]
    pub fn new(tag: String, cfg: DirectOutbound) -> Self {
        Self {
            tag,
            dialer: RawDialer::new(RawDialOptions::fast()),
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
        let stream = self
            .dialer
            .connect(&session.destination.to_string())
            .await?;
        Ok(Box::new(stream))
    }
}
