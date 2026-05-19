//! Engine bring-up — parses the config, builds the outbound map, instantiates
//! the dispatcher and spawns inbounds.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::info;

use mirage_config::Config;
use mirage_core::error::Result;

use crate::dispatcher::Dispatcher;
use crate::outbound::AnyOutbound;
use crate::router::Router;

/// Engine handle. Currently the engine runs entirely as detached `tokio::spawn`
/// tasks; `Engine` is a thin orchestrator that owns the dispatcher.
pub struct Engine {
    pub(crate) dispatcher: Arc<Dispatcher>,
}

impl Engine {
    /// Build an engine from a parsed configuration.
    pub fn build(cfg: &Config) -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<AnyOutbound>> = HashMap::new();
        for o in &cfg.outbounds {
            let parsed = AnyOutbound::from_config(o, &cfg.mobile)?;
            outbounds.insert(o.tag.clone(), Arc::new(parsed));
        }
        let router = Router::new(&cfg.routing);
        Ok(Self {
            dispatcher: Arc::new(Dispatcher::new(router, outbounds)),
        })
    }

    /// Bind every inbound listener. Returns once all listeners are bound;
    /// the listeners themselves run as background tasks.
    pub async fn run(&self, cfg: &Config) -> Result<()> {
        let mobile = Arc::new(cfg.mobile.clone());
        for ib in &cfg.inbounds {
            crate::inbound::spawn(ib.clone(), self.dispatcher.clone(), mobile.clone()).await?;
        }
        info!("mirage-engine: all inbounds bound");
        Ok(())
    }
}
