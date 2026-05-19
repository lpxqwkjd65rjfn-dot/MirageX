//! TLS 1.3 key schedule (RFC 8446 §7.1) used by the Reality handshake.
//!
//! The "key schedule" is the chain of HKDF derivations that turns the
//! shared secret produced by the X25519 ECDH into the four traffic keys
//! that protect the wire: client/server handshake traffic keys + client/
//! server application traffic keys. Reality uses TLS 1.3 unchanged here
//! — the censor-evading sleight of hand lives entirely in the unencrypted
//! `ClientHello` and `ServerHello` frames, not in the key derivation.
//!
//! ```text
//!                       0
//!                       |
//!                       v
//!     PSK ->  HKDF-Extract = Early Secret
//!                       |
//!                       +-----> Derive-Secret(.,  "ext binder" | …)
//!                       v
//!               Derive-Secret(., "derived", "")
//!                       |
//!                       v
//!   (EC)DHE -> HKDF-Extract = Handshake Secret
//!                       |
//!                       +-----> Derive-Secret(.,  "c hs traffic", ClientHello..ServerHello)
//!                       +-----> Derive-Secret(.,  "s hs traffic", ClientHello..ServerHello)
//!                       v
//!               Derive-Secret(., "derived", "")
//!                       |
//!                       v
//!         0  ->  HKDF-Extract = Master Secret
//!                       |
//!                       +-----> Derive-Secret(.,  "c ap traffic", ClientHello..ServerFinished)
//!                       +-----> Derive-Secret(.,  "s ap traffic", ClientHello..ServerFinished)
//!                       +-----> Derive-Secret(.,  "exp master",   ClientHello..ServerFinished)
//!                       +-----> Derive-Secret(.,  "res master",   ClientHello..ClientFinished)
//! ```
//!
//! All routines here operate on SHA-256 outputs only — Reality is locked
//! to TLS 1.3 cipher suites that hash to 32 bytes (`TLS_AES_128_GCM_SHA256`
//! and `TLS_CHACHA20_POLY1305_SHA256`). TLS 1.3 with SHA-384 would require
//! a small generalisation, which is intentionally out of scope.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::wire::TlsWriter;

/// SHA-256 output length, in bytes. Repeated as a named constant because
/// every routine here uses it.
pub const HASH_LEN: usize = 32;

/// A 32-byte secret produced by the key schedule (early / handshake / master
/// / handshake-traffic / application-traffic / exporter / resumption).
pub type Secret = [u8; HASH_LEN];

/// SHA-256 of the empty string. Used as the `transcript_hash` argument to
/// the "derived" derivation at the start of the schedule (RFC 8446 §7.1
/// "0" → Derive-Secret(., "derived", "")). Pre-computed at compile time
/// to keep the call sites free of an explicit `Sha256::digest(b"")` line.
pub const EMPTY_TRANSCRIPT_HASH: Secret = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// HKDF-Expand-Label per RFC 8446 §7.1.
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// # Panics
/// `hkdf::expand` only fails when the requested output length is greater
/// than `255 * HashLen`; our callers only ever ask for 32, 16, or 12 bytes,
/// so we never trip that branch.
#[must_use]
pub fn hkdf_expand_label(secret: &Secret, label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut w = TlsWriter::with_capacity(2 + 1 + label.len() + 7 + 1 + context.len());
    w.push_u16(u16::try_from(length).unwrap_or(u16::MAX));
    w.with_u8_len(|w| {
        w.push_bytes(b"tls13 ");
        w.push_bytes(label);
    });
    w.with_u8_len(|w| w.push_bytes(context));
    let info = w.into_bytes();

    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("32-byte PRK is valid");
    let mut out = vec![0u8; length];
    hkdf.expand(&info, &mut out).expect("expand output fits");
    out
}

/// Derive-Secret per RFC 8446 §7.1.
///
/// ```text
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
/// ```
#[must_use]
pub fn derive_secret(secret: &Secret, label: &[u8], transcript_hash: &Secret) -> Secret {
    let v = hkdf_expand_label(secret, label, transcript_hash, HASH_LEN);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&v);
    out
}

/// Compute SHA-256(`data`). Returned as a fixed-size array so it can be
/// passed straight into [`derive_secret`].
#[must_use]
pub fn sha256(data: &[u8]) -> Secret {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; HASH_LEN];
    buf.copy_from_slice(&out);
    buf
}

/// Incremental SHA-256 transcript. The handshake state machine feeds the
/// raw bytes of every handshake message into this hasher in the order
/// they're sent/received on the wire (excluding record-layer framing).
#[derive(Debug, Clone, Default)]
pub struct Transcript {
    inner: Sha256,
}

impl Transcript {
    /// New empty transcript.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw handshake-message bytes (with their TLS handshake header,
    /// per RFC 8446) into the transcript.
    pub fn extend(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Snapshot the current transcript hash. Calling this does not reset
    /// the hasher — subsequent [`extend`](Self::extend) calls continue to
    /// extend the same transcript.
    #[must_use]
    pub fn current_hash(&self) -> Secret {
        let snapshot = self.inner.clone();
        let out = snapshot.finalize();
        let mut buf = [0u8; HASH_LEN];
        buf.copy_from_slice(&out);
        buf
    }
}

/// The four "phase" secrets produced by the TLS 1.3 key schedule. The
/// state machine drives the handshake by mutating this struct as the
/// transcript grows.
#[derive(Debug, Clone)]
pub struct KeySchedule {
    /// Output of `HKDF-Extract(0, PSK | 0)`. Reality runs without a PSK
    /// (no session resumption) so this is always
    /// `HKDF-Extract(0, [0; 32])`.
    pub early_secret: Secret,
    /// Output of `HKDF-Extract(Derive-Secret(early, "derived", ""), DHE)`.
    pub handshake_secret: Secret,
    /// `Derive-Secret(handshake_secret, "c hs traffic", ClientHello..ServerHello)`.
    pub client_hs_traffic: Secret,
    /// `Derive-Secret(handshake_secret, "s hs traffic", ClientHello..ServerHello)`.
    pub server_hs_traffic: Secret,
    /// `HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)`.
    pub master_secret: Secret,
    /// `Derive-Secret(master_secret, "c ap traffic", ClientHello..ServerFinished)`.
    pub client_ap_traffic: Secret,
    /// `Derive-Secret(master_secret, "s ap traffic", ClientHello..ServerFinished)`.
    pub server_ap_traffic: Secret,
}

impl KeySchedule {
    /// Compute the full TLS 1.3 key schedule from the ECDH shared secret
    /// and the two transcript snapshots the schedule requires.
    ///
    /// * `dhe_shared_secret` — 32-byte X25519 output (`ECDHE` step).
    /// * `transcript_after_server_hello` — SHA-256 of
    ///   ClientHello || ServerHello, used to derive the handshake-traffic
    ///   secrets.
    /// * `transcript_after_server_finished` — SHA-256 of
    ///   ClientHello..ServerFinished, used to derive the
    ///   application-traffic secrets.
    #[must_use]
    pub fn derive(
        dhe_shared_secret: &[u8; 32],
        transcript_after_server_hello: &Secret,
        transcript_after_server_finished: &Secret,
    ) -> Self {
        let zero = [0u8; HASH_LEN];

        // 1. Early secret. Reality has no PSK → IKM is all zeros.
        let early_secret = hkdf_extract(&zero, &zero);

        // 2. Derived from early, then mixed with DHE.
        let early_derived = derive_secret(&early_secret, b"derived", &EMPTY_TRANSCRIPT_HASH);
        let handshake_secret = hkdf_extract(&early_derived, dhe_shared_secret);

        // 3. Handshake traffic secrets.
        let client_hs_traffic = derive_secret(
            &handshake_secret,
            b"c hs traffic",
            transcript_after_server_hello,
        );
        let server_hs_traffic = derive_secret(
            &handshake_secret,
            b"s hs traffic",
            transcript_after_server_hello,
        );

        // 4. Master secret = HKDF-Extract(Derive(handshake, "derived", ""), 0).
        let handshake_derived =
            derive_secret(&handshake_secret, b"derived", &EMPTY_TRANSCRIPT_HASH);
        let master_secret = hkdf_extract(&handshake_derived, &zero);

        // 5. Application traffic secrets, derived against the
        //    ClientHello..ServerFinished transcript.
        let client_ap_traffic = derive_secret(
            &master_secret,
            b"c ap traffic",
            transcript_after_server_finished,
        );
        let server_ap_traffic = derive_secret(
            &master_secret,
            b"s ap traffic",
            transcript_after_server_finished,
        );

        Self {
            early_secret,
            handshake_secret,
            client_hs_traffic,
            server_hs_traffic,
            master_secret,
            client_ap_traffic,
            server_ap_traffic,
        }
    }
}

/// HKDF-Extract — see RFC 5869 §2.2.
#[must_use]
pub fn hkdf_extract(salt: &Secret, ikm: &[u8]) -> Secret {
    let (prk, _hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&prk);
    out
}

/// Derive an AEAD key + IV from a phase traffic secret.
///
/// * `key_len` — 16 for AES-128-GCM, 32 for ChaCha20-Poly1305.
/// * `iv_len` — always 12 for TLS 1.3 (96-bit AEAD nonce).
#[must_use]
pub fn derive_key_iv(secret: &Secret, key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let key = hkdf_expand_label(secret, b"key", b"", key_len);
    let iv = hkdf_expand_label(secret, b"iv", b"", iv_len);
    (key, iv)
}

/// Derive the `finished` HMAC key for the `Finished` message of a given
/// traffic phase.
#[must_use]
pub fn derive_finished_key(secret: &Secret) -> Vec<u8> {
    hkdf_expand_label(secret, b"finished", b"", HASH_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_transcript_hash_matches_sha256_of_empty() {
        assert_eq!(sha256(&[]), EMPTY_TRANSCRIPT_HASH);
    }

    /// RFC 8448 §3 "Simple 1-RTT Handshake" — early secret.
    ///
    /// HKDF-Extract(0, 0) (zeroed salt, zeroed IKM) with SHA-256 should
    /// produce the well-known constant:
    /// `33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a`.
    #[test]
    fn early_secret_matches_rfc8448() {
        let zero = [0u8; HASH_LEN];
        let early = hkdf_extract(&zero, &zero);
        let expected =
            hex::decode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
                .unwrap();
        assert_eq!(&early[..], &expected[..]);
    }

    /// RFC 8448 §3 — derive `early_derived` (the secret that is then mixed
    /// with the ECDHE input).
    ///
    /// `Derive-Secret(early, "derived", "")` should equal
    /// `6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba`.
    #[test]
    fn early_derived_matches_rfc8448() {
        let zero = [0u8; HASH_LEN];
        let early = hkdf_extract(&zero, &zero);
        let derived = derive_secret(&early, b"derived", &EMPTY_TRANSCRIPT_HASH);
        let expected =
            hex::decode("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
                .unwrap();
        assert_eq!(&derived[..], &expected[..]);
    }

    #[test]
    fn transcript_hash_is_consistent_with_external_sha256() {
        let mut t = Transcript::new();
        t.extend(b"hello ");
        t.extend(b"world");
        let h = t.current_hash();
        let expected = sha256(b"hello world");
        assert_eq!(h, expected);
    }

    #[test]
    fn key_iv_lengths() {
        let secret = [0x42u8; HASH_LEN];
        let (key, iv) = derive_key_iv(&secret, 32, 12);
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 12);
    }
}
