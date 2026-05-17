//! Cryptographic primitives shared by both the Reality handshake and the
//! Vision flow keyer.
//!
//! Reality derives a 32-byte authentication key by performing an X25519
//! ECDH between the freshly generated client ephemeral private key (which
//! ends up encoded into the ClientHello's `key_share` extension) and the
//! server's static Reality public key. That secret then feeds an HKDF
//! with an info string of `"REALITY"` to derive the inner `auth_key`. The
//! authentication tag itself is `HMAC-SHA256(auth_key, short_id || sni)`
//! truncated to 16 bytes, and lives inside the ClientHello session-id
//! field.
//!
//! These two helpers expose those steps as plain functions so they can
//! be unit-tested in isolation.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive the inner Reality `auth_key` from an X25519 shared secret.
#[must_use]
pub fn auth_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    // `expand` only fails when out.len() > 255 * Hash::OutputSize.
    hkdf.expand(b"REALITY", &mut out).expect("hkdf expand fits");
    out
}

/// Compute the 16-byte authentication signature embedded into the session-id.
///
/// # Panics
///
/// Never panics — `Hmac::new_from_slice` only fails for empty keys, and a
/// 32-byte input is always valid.
#[must_use]
pub fn auth_signature(auth_key: &[u8; 32], short_id: &[u8], sni: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(auth_key).expect("32-byte key valid");
    mac.update(short_id);
    mac.update(sni);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_is_deterministic() {
        let ss = [0u8; 32];
        let a = auth_key(&ss);
        let b = auth_key(&ss);
        assert_eq!(a, b);
    }

    #[test]
    fn auth_signature_is_deterministic_and_changes_on_input() {
        let key = [7u8; 32];
        let s1 = auth_signature(&key, b"", b"example.com");
        let s2 = auth_signature(&key, b"", b"example.com");
        let s3 = auth_signature(&key, b"\x01\x02", b"example.com");
        let s4 = auth_signature(&key, b"", b"example.org");
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s1, s4);
    }
}
