//! VLESS request types.

use uuid::Uuid;

use mirage_core::address::Address;

/// VLESS command byte.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `0x01` — TCP CONNECT.
    Tcp = 0x01,
    /// `0x02` — UDP ASSOCIATE (single endpoint).
    Udp = 0x02,
    /// `0x03` — Mux. The payload is a sub-multiplexed stream framed by mux.cool.
    Mux = 0x03,
}

impl Command {
    /// Try to convert a raw command byte into a [`Command`].
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            0x03 => Some(Self::Mux),
            _ => None,
        }
    }
}

/// Addons block carried in a VLESS request.
///
/// We model the two fields that matter in practice (`flow`, `seed`) and
/// keep an opaque `extra` byte-string for forward compatibility.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestAddons {
    /// Flow marker (`xtls-rprx-vision`, `""` for plain).
    pub flow: String,
    /// Seed used by some experimental flows.
    pub seed: Vec<u8>,
    /// Anything we did not recognise — preserved for forward compat.
    pub extra: Vec<u8>,
}

impl RequestAddons {
    /// Build a no-op (empty) addons block.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build an addons block with just the flow marker filled in.
    #[must_use]
    pub fn with_flow(flow: impl Into<String>) -> Self {
        Self {
            flow: flow.into(),
            ..Self::default()
        }
    }

    /// Returns `true` when this addons block carries no meaningful data and
    /// therefore can be emitted as a zero-length addons section.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flow.is_empty() && self.seed.is_empty() && self.extra.is_empty()
    }
}

/// A complete decoded VLESS request header. The payload that follows is
/// streamed verbatim and is not part of this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Authenticated user ID.
    pub uuid: Uuid,
    /// Addons block.
    pub addons: RequestAddons,
    /// Command (TCP/UDP/Mux).
    pub command: Command,
    /// Destination address.
    pub destination: Address,
}
