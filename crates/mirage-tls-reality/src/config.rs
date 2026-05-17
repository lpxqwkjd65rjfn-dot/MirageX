//! Reality client configuration.

use mirage_core::error::{Error, Result};

/// Reality TLS client configuration. Mirrors the user-facing config in
/// `mirage-config` but materialised into ready-to-use bytes (decoded
/// public key, short id, etc.).
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Server name to forge in the ClientHello SNI.
    pub server_name: String,
    /// 32-byte X25519 server public key.
    pub server_public_key: [u8; 32],
    /// Short id (0–8 bytes). Empty when the server is configured with no
    /// short id.
    pub short_id: Vec<u8>,
    /// Optional spider-x identifier used to derive auth bytes for the inner
    /// flow. Empty when unused.
    pub spider_x: String,
    /// Outer ClientHello fingerprint to emulate (`chrome`, `firefox`,
    /// `safari`, `ios`, `random`).
    pub fingerprint: String,
    /// ALPN preferences for the outer ClientHello.
    pub alpn: Vec<String>,
}

impl RealityConfig {
    /// Build a configuration from the user-supplied hex-encoded strings, with
    /// validation.
    ///
    /// # Errors
    /// Returns [`Error::Config`] when:
    /// * `server_name` is empty;
    /// * `public_key_hex` is not 64 lower-case hex chars (32 bytes);
    /// * `short_id_hex` is longer than 16 hex chars (8 bytes).
    pub fn new(
        server_name: impl Into<String>,
        public_key_hex: &str,
        short_id_hex: &str,
        spider_x: impl Into<String>,
        fingerprint: impl Into<String>,
        alpn: Vec<String>,
    ) -> Result<Self> {
        let server_name = server_name.into();
        if server_name.is_empty() {
            return Err(Error::config("reality: server_name must not be empty"));
        }
        let pk_bytes = hex::decode(public_key_hex)
            .map_err(|e| Error::config(format!("reality: invalid public_key hex: {e}")))?;
        if pk_bytes.len() != 32 {
            return Err(Error::config(
                "reality: public_key must be 32 bytes (64 hex chars)",
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);

        let short_id_bytes = if short_id_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(short_id_hex)
                .map_err(|e| Error::config(format!("reality: invalid short_id hex: {e}")))?
        };
        if short_id_bytes.len() > 8 {
            return Err(Error::config("reality: short_id is limited to 8 bytes"));
        }

        Ok(Self {
            server_name,
            server_public_key: pk,
            short_id: short_id_bytes,
            spider_x: spider_x.into(),
            fingerprint: fingerprint.into(),
            alpn,
        })
    }
}
