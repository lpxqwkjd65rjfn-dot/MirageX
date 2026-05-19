//! AEAD wrapper used by the TLS 1.3 record layer.
//!
//! Reality is locked to the two SHA-256 cipher suites of TLS 1.3:
//!
//! * `TLS_AES_128_GCM_SHA256` — AES-128-GCM, 16-byte key, 12-byte IV.
//! * `TLS_CHACHA20_POLY1305_SHA256` — ChaCha20-Poly1305, 32-byte key, 12-byte IV.
//!
//! Both produce a 16-byte authentication tag, which TLS 1.3 appends after
//! the ciphertext within the `TLSCiphertext.encrypted_record` field.
//!
//! The nonce construction is the same for both ciphers (RFC 8446 §5.3):
//!
//! ```text
//!     iv_xor_seq = IV XOR (zero-padded sequence-number, big-endian)
//! ```
//!
//! …where the sequence number starts at zero for each traffic-key epoch
//! and is incremented after every record. We expose that XOR construction
//! as [`Aead::nonce_for`] so the record layer doesn't need to know which
//! cipher it's using.

use std::fmt;

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;

use mirage_core::error::{Error, Result};

/// TLS 1.3 nonce / IV length (96-bit AEAD nonce).
pub const NONCE_LEN: usize = 12;
/// TLS 1.3 AEAD authentication tag length.
pub const TAG_LEN: usize = 16;

/// The two AEADs supported by Reality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadKind {
    /// `TLS_AES_128_GCM_SHA256` — 16-byte key.
    Aes128Gcm,
    /// `TLS_CHACHA20_POLY1305_SHA256` — 32-byte key.
    ChaCha20Poly1305,
}

impl AeadKind {
    /// Key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// IV / nonce length in bytes — always 12 for both TLS 1.3 AEADs.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn iv_len(self) -> usize {
        NONCE_LEN
    }
}

impl fmt::Display for AeadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm => f.write_str("AES-128-GCM"),
            Self::ChaCha20Poly1305 => f.write_str("ChaCha20-Poly1305"),
        }
    }
}

/// AEAD instance, ready to seal / open records. The key is stored
/// internally; callers only need to supply the nonce (computed from the
/// per-record sequence number) and AAD.
pub struct Aead {
    inner: AeadCipher,
    iv: [u8; NONCE_LEN],
}

// Aes128Gcm carries the AES round keys inline (~736 bytes), much larger
// than ChaCha20Poly1305's 32-byte key. Box it so the enum stays small
// (clippy::large_enum_variant) — the indirection cost is paid once per
// AEAD construction, never per record.
enum AeadCipher {
    Aes(Box<Aes128Gcm>),
    Chacha(ChaCha20Poly1305),
}

impl Aead {
    /// Build an AEAD from a derived traffic-key + IV.
    ///
    /// # Errors
    /// Returns [`Error::Tls`] when `key.len()` or `iv.len()` are wrong for
    /// `kind` (this should never happen in practice — the key schedule
    /// always derives the correct lengths).
    pub fn new(kind: AeadKind, key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != NONCE_LEN {
            return Err(Error::tls(format!(
                "reality aead: bad iv length {} (want {NONCE_LEN})",
                iv.len()
            )));
        }
        let mut iv_buf = [0u8; NONCE_LEN];
        iv_buf.copy_from_slice(iv);

        let cipher = match kind {
            AeadKind::Aes128Gcm => {
                if key.len() != 16 {
                    return Err(Error::tls(format!(
                        "reality aead: aes-128-gcm needs 16-byte key, got {}",
                        key.len()
                    )));
                }
                AeadCipher::Aes(Box::new(
                    Aes128Gcm::new_from_slice(key).map_err(stringify_aead_error)?,
                ))
            }
            AeadKind::ChaCha20Poly1305 => {
                if key.len() != 32 {
                    return Err(Error::tls(format!(
                        "reality aead: chacha20-poly1305 needs 32-byte key, got {}",
                        key.len()
                    )));
                }
                AeadCipher::Chacha(
                    ChaCha20Poly1305::new_from_slice(key).map_err(stringify_aead_error)?,
                )
            }
        };
        Ok(Self {
            inner: cipher,
            iv: iv_buf,
        })
    }

    /// Compute the per-record nonce from this AEAD's IV and a sequence
    /// number, per RFC 8446 §5.3.
    ///
    /// The sequence number is encoded as a big-endian 64-bit integer
    /// right-aligned in a 12-byte zero-padded buffer, then XOR'd with the
    /// IV.
    #[must_use]
    pub fn nonce_for(&self, seq: u64) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        let seq_bytes = seq.to_be_bytes();
        // XOR the 8-byte seq into the trailing 8 bytes of the nonce.
        for (i, b) in seq_bytes.iter().enumerate() {
            nonce[i + 4] ^= b;
        }
        nonce
    }

    /// Seal `plaintext` with associated data `aad`, returning
    /// `ciphertext || tag` (the tag is always 16 bytes appended at the end).
    ///
    /// # Errors
    /// Returns [`Error::Tls`] if the underlying AEAD fails (which only
    /// happens for plaintexts larger than `2^36 - 31` bytes, far beyond
    /// any single TLS record).
    pub fn seal(&self, seq: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce_for(seq);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match &self.inner {
            AeadCipher::Aes(c) => c
                .encrypt(generic_nonce(&nonce).into(), payload)
                .map_err(stringify_aead_error),
            AeadCipher::Chacha(c) => c
                .encrypt(generic_nonce(&nonce).into(), payload)
                .map_err(stringify_aead_error),
        }
    }

    /// Open `ciphertext_and_tag` (= `ciphertext || 16-byte tag`) with
    /// associated data `aad`, returning the plaintext.
    ///
    /// # Errors
    /// Returns [`Error::AuthFailed`] on tag mismatch (the typical case for
    /// MitM / bit flips); any other failure path is wrapped as
    /// [`Error::Tls`].
    pub fn open(&self, seq: u64, aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce_for(seq);
        let payload = Payload {
            msg: ciphertext_and_tag,
            aad,
        };
        let result = match &self.inner {
            AeadCipher::Aes(c) => c.decrypt(generic_nonce(&nonce).into(), payload),
            AeadCipher::Chacha(c) => c.decrypt(generic_nonce(&nonce).into(), payload),
        };
        result.map_err(|_| Error::AuthFailed)
    }
}

impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aead").field("iv", &"[redacted]").finish()
    }
}

fn stringify_aead_error<E: fmt::Display>(e: E) -> Error {
    Error::tls(format!("aead error: {e}"))
}

fn generic_nonce(n: &[u8; NONCE_LEN]) -> &[u8; NONCE_LEN] {
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_xor_construction_zeroes_at_seq_zero() {
        let key = [0u8; 16];
        let iv = [0u8; NONCE_LEN];
        let aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        assert_eq!(aead.nonce_for(0), [0u8; NONCE_LEN]);
    }

    #[test]
    fn nonce_xor_construction_matches_rfc_layout() {
        let key = [0u8; 16];
        // Pattern IV — easy to eyeball XOR.
        let iv = [0xAB, 0xCD, 0xEF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        let aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        let n = aead.nonce_for(0x0102_0304_0506_0708);
        // First 4 bytes unchanged. Last 8 bytes = IV[4..12] XOR seq.
        assert_eq!(
            n,
            [0xAB, 0xCD, 0xEF, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn seal_then_open_aes_round_trips() {
        let key = [0x11; 16];
        let iv = [0x22; NONCE_LEN];
        let aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        let ct = aead.seal(7, b"aad", b"hello mirage").unwrap();
        let pt = aead.open(7, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello mirage");
    }

    #[test]
    fn seal_then_open_chacha_round_trips() {
        let key = [0x33; 32];
        let iv = [0x44; NONCE_LEN];
        let aead = Aead::new(AeadKind::ChaCha20Poly1305, &key, &iv).unwrap();
        let ct = aead.seal(42, b"hello", b"world!").unwrap();
        let pt = aead.open(42, b"hello", &ct).unwrap();
        assert_eq!(pt, b"world!");
    }

    #[test]
    fn open_with_tampered_tag_fails_as_auth_failed() {
        let key = [0xAA; 16];
        let iv = [0xBB; NONCE_LEN];
        let aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        let mut ct = aead.seal(0, b"", b"secret").unwrap();
        *ct.last_mut().unwrap() ^= 0x01;
        let err = aead.open(0, b"", &ct).unwrap_err();
        assert!(
            matches!(err, Error::AuthFailed),
            "tampered tag should map to AuthFailed, got {err:?}"
        );
    }

    #[test]
    fn key_iv_mismatch_rejected_eagerly() {
        // 4-byte key — invalid for both ciphers.
        let key = [0u8; 4];
        let iv = [0u8; NONCE_LEN];
        assert!(Aead::new(AeadKind::Aes128Gcm, &key, &iv).is_err());
        assert!(Aead::new(AeadKind::ChaCha20Poly1305, &key, &iv).is_err());
    }
}
