//! Routing engine. Implements the rules from [`mirage_config::RoutingConfig`]
//! against [`Session`] objects produced by the inbound dispatchers.

use mirage_config::routing::{RoutingConfig, RuleAction, RuleMatcher};
use mirage_core::address::Host;

use crate::dispatcher::Session;

/// Result of evaluating a routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Forward to the named outbound.
    Forward(String),
    /// Drop the connection.
    Block,
}

/// Engine that looks up routing decisions.
#[derive(Debug, Clone)]
pub struct Router {
    rules: Vec<(RuleMatcher, RuleAction)>,
    fallback: String,
}

impl Router {
    /// Build a router from a [`RoutingConfig`].
    #[must_use]
    pub fn new(cfg: &RoutingConfig) -> Self {
        let rules = cfg
            .rules
            .iter()
            .map(|r| (r.when.clone(), r.action.clone()))
            .collect();
        let fallback = if cfg.final_outbound.is_empty() {
            "direct".into()
        } else {
            cfg.final_outbound.clone()
        };
        Self { rules, fallback }
    }

    /// Match a session against the rules.
    #[must_use]
    pub fn route(&self, session: &Session) -> RoutingDecision {
        for (matcher, action) in &self.rules {
            if matches(matcher, session) {
                return match action {
                    RuleAction::Forward { outbound } => RoutingDecision::Forward(outbound.clone()),
                    RuleAction::Block => RoutingDecision::Block,
                    RuleAction::Resolve => RoutingDecision::Forward(self.fallback.clone()),
                };
            }
        }
        RoutingDecision::Forward(self.fallback.clone())
    }
}

fn matches(matcher: &RuleMatcher, session: &Session) -> bool {
    if !matcher.inbound_tag.is_empty()
        && !matcher
            .inbound_tag
            .iter()
            .any(|t| t == &session.inbound_tag)
    {
        return false;
    }
    if !matcher.network.is_empty()
        && !matcher
            .network
            .iter()
            .any(|n| n.eq_ignore_ascii_case(session.network.as_str()))
    {
        return false;
    }
    if !matcher.port.is_empty() && !port_matches(&matcher.port, session.destination.port) {
        return false;
    }
    if !matcher.domain.is_empty() {
        let Host::Domain(d) = &session.destination.host else {
            return false;
        };
        if !matcher.domain.iter().any(|pat| domain_matches(pat, d)) {
            return false;
        }
    }
    true
}

fn port_matches(patterns: &[String], port: u16) -> bool {
    for raw in patterns {
        for part in raw.split(',') {
            let part = part.trim();
            if let Some((lo, hi)) = part.split_once('-') {
                if let (Ok(lo), Ok(hi)) = (lo.parse::<u16>(), hi.parse::<u16>()) {
                    if (lo..=hi).contains(&port) {
                        return true;
                    }
                }
            } else if let Ok(p) = part.parse::<u16>() {
                if p == port {
                    return true;
                }
            }
        }
    }
    false
}

fn domain_matches(pattern: &str, domain: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("domain:") {
        return domain.eq_ignore_ascii_case(rest);
    }
    if let Some(rest) = pattern.strip_prefix("suffix:") {
        return domain
            .to_ascii_lowercase()
            .ends_with(&rest.to_ascii_lowercase());
    }
    if pattern.starts_with("regexp:") {
        // Regex matchers are intentionally not pulled in here to keep the
        // dependency surface small. They will be wired in once the geosite
        // database is implemented; until then `regexp:` rules are treated as
        // exact matches with the prefix stripped.
        return domain.eq_ignore_ascii_case(pattern.trim_start_matches("regexp:"));
    }
    // Default: suffix match.
    domain
        .to_ascii_lowercase()
        .ends_with(&pattern.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_config::routing::{DomainStrategy, RoutingRule};
    use mirage_core::address::Address;
    use mirage_core::network::Network;

    fn ses(domain: &str, port: u16) -> Session {
        Session {
            inbound_tag: "socks-in".into(),
            destination: Address::domain(domain, port),
            network: Network::Tcp,
        }
    }

    #[test]
    fn final_outbound_used_when_no_rules() {
        let cfg = RoutingConfig {
            domain_strategy: DomainStrategy::AsIs,
            rules: vec![],
            final_outbound: "proxy".into(),
        };
        let r = Router::new(&cfg);
        assert_eq!(
            r.route(&ses("example.com", 443)),
            RoutingDecision::Forward("proxy".into())
        );
    }

    #[test]
    fn suffix_domain_match_forwards() {
        let cfg = RoutingConfig {
            domain_strategy: DomainStrategy::AsIs,
            rules: vec![RoutingRule {
                description: None,
                when: RuleMatcher {
                    domain: vec!["suffix:example.com".into()],
                    ..Default::default()
                },
                action: RuleAction::Forward {
                    outbound: "proxy".into(),
                },
            }],
            final_outbound: "direct".into(),
        };
        let r = Router::new(&cfg);
        assert_eq!(
            r.route(&ses("api.example.com", 443)),
            RoutingDecision::Forward("proxy".into())
        );
        assert_eq!(
            r.route(&ses("api.other.com", 443)),
            RoutingDecision::Forward("direct".into())
        );
    }
}
