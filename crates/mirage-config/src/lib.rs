//! mirage-config
//!
//! Strongly-typed configuration schema for the MirageX engine. We model the
//! configuration the way Xray does (inbounds → routing → outbounds, with a separate
//! DNS block), but every section is given typed sub-structs so end users get IDE
//! completion in their `client.toml` and so the engine never has to deal with
//! "stringly-typed" config noise at runtime.
//!
//! Both TOML and JSON are accepted on input. JSON ingestion is loose enough to
//! consume `xray.json`-style configs with only minor renames, simplifying migration.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod inbound;
pub mod log;
pub mod mobile;
pub mod outbound;
pub mod routing;
pub mod transport;

pub use inbound::{HttpInbound, InboundConfig, InboundKind, SocksInbound, TunInbound};
pub use log::{LogConfig, LogFormat, LogLevel};
pub use mobile::{
    CongestionControl, KeepAliveConfig, MobileConfig, MultipathMode, PacingConfig,
    RetransmitProfile,
};
pub use outbound::{
    DirectOutbound, FreedomDomainStrategy, OutboundConfig, OutboundKind, RealityConfig,
    ShadowsocksCipher, ShadowsocksOutbound, TlsConfig, TrojanOutbound, VlessOutbound,
    VmessOutbound,
};
pub use routing::{
    DnsConfig, DnsServer, RoutingConfig, RoutingRule, RoutingTargetTag, RuleAction, RuleMatcher,
};
pub use transport::{
    GrpcSettings, HttpUpgradeSettings, RawSettings, TransportSettings, WebsocketSettings,
    XHttpMode, XHttpSettings,
};

/// Top-level MirageX configuration. This is the structure that gets serialised to
/// `client.toml` (or `client.json`) and consumed by the engine on startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Logging configuration.
    pub log: LogConfig,
    /// One or more inbounds (entry-points that accept user traffic).
    pub inbounds: Vec<InboundConfig>,
    /// One or more outbounds (egress paths to the wider Internet or a remote proxy).
    pub outbounds: Vec<OutboundConfig>,
    /// Routing rules and DNS settings.
    #[serde(default)]
    pub routing: RoutingConfig,
    /// DNS configuration (independent of routing for clarity).
    #[serde(default)]
    pub dns: DnsConfig,
    /// Mobile-network adaptation knobs.
    #[serde(default)]
    pub mobile: MobileConfig,
    /// Optional API/control-plane bind address. When `None`, the control plane is
    /// disabled.
    #[serde(default)]
    pub control: Option<ControlConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: LogConfig::default(),
            inbounds: vec![InboundConfig::default()],
            outbounds: vec![OutboundConfig::default()],
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            mobile: MobileConfig::default(),
            control: None,
        }
    }
}

/// Errors that may occur during config loading / validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Underlying I/O error reading the config file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML deserialisation error.
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    /// JSON deserialisation error.
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// Validation failure with a human-readable description.
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    /// Parse a configuration from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError::Toml`] on parse failure or [`ConfigError::Invalid`]
    /// on validation failure.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse a configuration from a JSON string.
    ///
    /// # Errors
    /// Returns [`ConfigError::Json`] on parse failure or [`ConfigError::Invalid`]
    /// on validation failure.
    pub fn from_json_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load a configuration from a path. The format is auto-detected by extension
    /// (`.toml` / `.json`). Unknown extensions are treated as TOML.
    ///
    /// # Errors
    /// Returns [`ConfigError`] on any I/O or parse failure.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("toml");
        match ext {
            "json" | "json5" => Self::from_json_str(&data),
            _ => Self::from_toml_str(&data),
        }
    }

    /// Validate that the configuration is internally consistent.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] with a descriptive message.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.inbounds.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one inbound is required".into(),
            ));
        }
        if self.outbounds.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one outbound is required".into(),
            ));
        }
        // Ensure outbound tags referenced by routing exist.
        let known: std::collections::HashSet<&str> =
            self.outbounds.iter().map(|o| o.tag.as_str()).collect();
        for rule in &self.routing.rules {
            if let RuleAction::Forward { outbound } = &rule.action {
                if !known.contains(outbound.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "routing rule references unknown outbound tag `{outbound}`",
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Optional embedded control / RPC plane. Useful for the GUIs to subscribe to
/// stats, swap outbounds at runtime, or trigger health probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Bind address for the control plane (e.g. `127.0.0.1:9090`).
    pub listen: String,
    /// Optional bearer token required on every request.
    #[serde(default)]
    pub token: Option<String>,
    /// Enable Prometheus-format metrics under `/metrics`.
    #[serde(default = "default_true")]
    pub metrics: bool,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_round_trip() {
        let cfg = Config::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        let cfg2: Config = toml::from_str(&toml_str).unwrap();
        cfg2.validate().unwrap();
    }
}
