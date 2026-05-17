//! Network type — TCP or UDP, plus a couple of helpers.

use serde::{Deserialize, Serialize};

/// Network kind. The MirageX engine handles TCP and UDP uniformly through the same
/// trait object so this enum is mostly used for routing decisions and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Reliable, ordered, byte-stream.
    Tcp,
    /// Unordered, datagram.
    Udp,
}

impl Network {
    /// Returns the lower-case ASCII name of the network.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
