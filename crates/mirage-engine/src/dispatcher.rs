//! Dispatcher — owns the outbound map and is the single entry-point used by
//! inbounds to forward a session.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use mirage_core::address::Address;
use mirage_core::error::{Error, Result};
use mirage_core::network::Network;

use crate::outbound::AnyOutbound;
use crate::router::{Router, RoutingDecision};

/// Materialised representation of an inbound connection, ready to be
/// matched against routing rules.
#[derive(Debug, Clone)]
pub struct Session {
    /// Tag of the inbound that produced this session.
    pub inbound_tag: String,
    /// Destination requested by the client.
    pub destination: Address,
    /// Network (TCP/UDP).
    pub network: Network,
}

/// Dispatcher: looks up the right outbound for a session, forwards to it.
pub struct Dispatcher {
    router: Router,
    outbounds: HashMap<String, Arc<AnyOutbound>>,
}

impl Dispatcher {
    /// Build a dispatcher from a router and an outbound map.
    #[must_use]
    pub fn new(router: Router, outbounds: HashMap<String, Arc<AnyOutbound>>) -> Self {
        Self { router, outbounds }
    }

    /// Look up the outbound that would serve `session` without forwarding.
    pub fn select(&self, session: &Session) -> Result<Arc<AnyOutbound>> {
        match self.router.route(session) {
            RoutingDecision::Block => Err(Error::RoutingRejected(session.destination.to_string())),
            RoutingDecision::Forward(tag) => self
                .outbounds
                .get(&tag)
                .cloned()
                .ok_or_else(|| Error::Config(format!("unknown outbound tag `{tag}`"))),
        }
    }
}

/// Trait implemented by every outbound.
#[async_trait]
pub trait Outbound: Send + Sync + 'static {
    /// Tag.
    fn tag(&self) -> &str;
    /// Dial the destination, returning the resulting bidirectional stream.
    async fn dial(&self, session: &Session) -> Result<Box<dyn DuplexStream>>;
}

/// Marker trait combining `AsyncRead` + `AsyncWrite` + `Send` + `Unpin`.
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> DuplexStream for T {}
