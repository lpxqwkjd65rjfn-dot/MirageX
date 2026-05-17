//! VLESS response types.

/// Decoded VLESS response header (excluding the payload).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// Opaque addons emitted by the server. We currently never act on
    /// these — they exist purely for forward compatibility.
    pub addons: Vec<u8>,
}
