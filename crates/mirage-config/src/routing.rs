//! Routing rules and DNS configuration.

use serde::{Deserialize, Serialize};

/// Routing engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RoutingConfig {
    /// Domain-resolution strategy used while matching rules. `as-is` skips
    /// resolution, `ip-on-demand` resolves only when a rule needs an IP, and
    /// `ip-if-non-match` resolves only if all domain rules miss.
    pub domain_strategy: DomainStrategy,
    /// Ordered list of rules. The first match wins.
    pub rules: Vec<RoutingRule>,
    /// Fallback outbound when no rule matches.
    pub final_outbound: RoutingTargetTag,
}

/// Domain resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DomainStrategy {
    /// Never resolve domains while routing.
    #[default]
    AsIs,
    /// Resolve only when an IP-matching rule is encountered.
    IpOnDemand,
    /// Resolve only if all domain rules miss.
    IpIfNonMatch,
}

/// A single routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Matchers. The rule fires when **all** matchers match.
    pub when: RuleMatcher,
    /// Action to take when the rule fires.
    pub action: RuleAction,
}

/// All matchers that may be combined inside a single rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RuleMatcher {
    /// Inbound tags this rule applies to.
    pub inbound_tag: Vec<String>,
    /// Destination domains (exact / suffix / regex prefixed by `domain:` / `suffix:` / `regexp:`).
    pub domain: Vec<String>,
    /// Destination CIDRs (e.g. `10.0.0.0/8`).
    pub ip_cidr: Vec<String>,
    /// Destination ports (e.g. `443`, `80,443`, `5000-6000`).
    pub port: Vec<String>,
    /// Networks to match (`tcp`, `udp`, or both).
    pub network: Vec<String>,
    /// Geosite tags (e.g. `geosite:cn`). Stub by default; resolved by the
    /// geosite database when loaded.
    pub geosite: Vec<String>,
    /// GeoIP tags (e.g. `geoip:cn`). Resolved by the GeoIP database.
    pub geoip: Vec<String>,
    /// Source addresses / CIDRs.
    pub source: Vec<String>,
    /// Process name (where supported).
    pub process_name: Vec<String>,
    /// Match only after the inbound's `sniffing` step detected this protocol
    /// (`tls`, `http`, `quic`).
    pub sniffed: Vec<String>,
}

/// Action a routing rule performs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleAction {
    /// Forward to a specific outbound (by tag).
    Forward {
        /// Outbound tag.
        outbound: String,
    },
    /// Block / drop.
    Block,
    /// Resolve only — used in DNS routing.
    Resolve,
}

/// Convenience alias for outbound tags in the `final_outbound` slot.
pub type RoutingTargetTag = String;

/// DNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsConfig {
    /// Upstream DNS servers, queried in order.
    pub servers: Vec<DnsServer>,
    /// Local DNS cache size (entries). Zero disables.
    pub cache_size: u32,
    /// Whether to disable the cache for queries that yielded NXDOMAIN.
    pub no_negative_cache: bool,
    /// Force the use of the system resolver instead of `servers`. Useful when
    /// `dnsmasq` / `systemd-resolved` is already trusted.
    pub use_system_resolver: bool,
    /// Bypass DNS resolution for hostnames matching these suffixes (handed
    /// through to the OS as-is). Useful for `.local`/`.lan`.
    pub bypass_suffixes: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![DnsServer {
                address: "https://cloudflare-dns.com/dns-query".into(),
                detour: None,
                fallback: false,
                tag: "doh-default".into(),
            }],
            cache_size: 4096,
            no_negative_cache: false,
            use_system_resolver: false,
            bypass_suffixes: vec!["local".into(), "lan".into(), "home.arpa".into()],
        }
    }
}

/// A single DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
    /// Upstream URL. Supports `udp://`, `tcp://`, `tls://`, `https://`, `quic://`,
    /// or a plain IP (treated as `udp://`).
    pub address: String,
    /// Optional outbound tag — route DNS queries through that outbound.
    #[serde(default)]
    pub detour: Option<String>,
    /// Mark this server as a fallback. Fallback servers are only queried if
    /// every non-fallback server failed or timed out.
    #[serde(default)]
    pub fallback: bool,
    /// Stable tag (used for logging / control-plane queries).
    pub tag: String,
}
