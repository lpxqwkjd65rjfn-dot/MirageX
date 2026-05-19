//! TLS 1.3 ClientHello forging + ServerHello parsing for Reality.
//!
//! The [`ClientHelloBuilder`] builds bytes that look on the wire like the
//! browser fingerprint named by [`Fingerprint`]. The key-share extension
//! carries our X25519 ephemeral public key (which the handshake state
//! machine in PR-4 will combine with the server's reply to derive the
//! shared secret). The session-id field optionally carries a Reality
//! authentication signature so a Reality-aware server can identify us
//! while a passive DPI just sees a normal session id.
//!
//! The [`ServerHelloParser`] is the dual: given the bytes coming back
//! from the server, it extracts the server's X25519 public key from the
//! key_share extension, the legacy session id (which an unaware server
//! mirrors back from the client's), and the selected cipher suite.
//!
//! Both routines validate strictly: any malformed length, unsupported
//! version, or non-x25519 key_share is rejected eagerly.
//!
//! ## What this module does *not* do (yet)
//!
//! This is the wire-format layer only. It does *not* drive the TLS
//! handshake (no `EncryptedExtensions` / `Certificate` / `Finished`
//! processing — that's the state machine in PR-4). It also does not
//! claim byte-for-byte parity with xray-core's Reality `session_id`
//! construction; the construction here is documented inline and tested
//! end-to-end against itself, but full interop with xray-core remains a
//! follow-up (see `docs/ROADMAP.md` P0-3).

use mirage_core::error::{Error, Result};
use rand::RngCore;

use crate::auth::{auth_key, auth_signature};
use crate::config::RealityConfig;
use crate::fingerprint::{cipher, ext, grease_for, group, Fingerprint, Profile};
use crate::wire::{TlsReader, TlsWriter};

/// TLS record-layer constants.
mod record_type {
    pub const HANDSHAKE: u8 = 22;
}

/// Handshake-message types we care about.
mod hs {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
}

/// Legacy version field — every TLS 1.3 ClientHello sets `legacy_version
/// = TLS 1.2 (0x0303)` and negotiates the real version via the
/// supported_versions extension.
const LEGACY_VERSION_TLS12: u16 = 0x0303;
const SUPPORTED_VERSION_TLS13: u16 = 0x0304;

/// TLS 1.3 session_id length used by every browser fingerprint.
pub const SESSION_ID_LEN: usize = 32;
/// X25519 public-key length.
pub const X25519_KEY_LEN: usize = 32;

/// One built ClientHello, ready to be wrapped in a TLS record.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Full handshake-message bytes, including the 4-byte handshake header
    /// (msg_type + length). Suitable both for hashing into the transcript
    /// and for wrapping in a record.
    pub handshake_message: Vec<u8>,
    /// The 32-byte ClientHello.Random — preserved because the handshake
    /// state machine needs it later (e.g. for binder computation in the
    /// 0-RTT path, which Reality currently does not use, but we keep the
    /// hook for completeness).
    pub random: [u8; 32],
    /// The 32-byte session_id we sent — the server is expected to mirror
    /// it back in its ServerHello.
    pub session_id: [u8; SESSION_ID_LEN],
    /// Our ephemeral X25519 public key (the one announced in the
    /// key_share extension).
    pub x25519_public_key: [u8; X25519_KEY_LEN],
}

impl ClientHello {
    /// Wrap [`Self::handshake_message`] in a TLS record (record type 22 =
    /// handshake, legacy version `0x0301` per RFC 8446 §5.1 for the very
    /// first flight).
    #[must_use]
    pub fn to_record(&self) -> Vec<u8> {
        let mut w = TlsWriter::with_capacity(5 + self.handshake_message.len());
        w.push_u8(record_type::HANDSHAKE);
        // legacy_record_version per RFC 8446 §5.1: TLS 1.0 (0x0301) for
        // the very first ClientHello.
        w.push_u16(0x0301);
        w.push_u16(u16::try_from(self.handshake_message.len()).unwrap_or(u16::MAX));
        w.push_bytes(&self.handshake_message);
        w.into_bytes()
    }
}

/// Builder for forged ClientHello messages.
///
/// Reality-specific extensions kick in when [`Self::with_reality_auth`] is
/// called. Without it, the builder produces a regular forged ClientHello
/// that just impersonates a browser — useful for plain-TLS outbounds.
pub struct ClientHelloBuilder<'a> {
    server_name: &'a str,
    profile: Profile,
    /// 32-byte X25519 ephemeral public key (callers generate the secret +
    /// public key with [`x25519_dalek`] and pass the public half here).
    x25519_public_key: [u8; X25519_KEY_LEN],
    /// Optional Reality config; when present, the session_id will carry
    /// a Reality auth signature derived from `auth_key`.
    reality_auth_key: Option<[u8; 32]>,
    reality_short_id: Vec<u8>,
    /// Optional seed for the random nonces. When `None`, fresh entropy
    /// is drawn from the OS. Provided primarily so unit tests can pin
    /// the random outputs.
    deterministic_random: Option<[u8; 32]>,
    deterministic_session_id: Option<[u8; SESSION_ID_LEN]>,
}

impl<'a> ClientHelloBuilder<'a> {
    /// Build a forged ClientHello impersonating `fingerprint` against
    /// `server_name`, with the supplied X25519 ephemeral public key.
    #[must_use]
    pub fn new(
        server_name: &'a str,
        fingerprint: Fingerprint,
        x25519_public_key: [u8; X25519_KEY_LEN],
    ) -> Self {
        Self {
            server_name,
            profile: Profile::for_fingerprint(fingerprint),
            x25519_public_key,
            reality_auth_key: None,
            reality_short_id: Vec::new(),
            deterministic_random: None,
            deterministic_session_id: None,
        }
    }

    /// Compute the Reality auth key from the supplied X25519 shared secret
    /// (derived externally by ECDH against the server's published Reality
    /// public key) and the configuration, and embed the corresponding
    /// signature into the session_id.
    ///
    /// The shared secret is the output of
    /// `x25519_dalek::StaticSecret::diffie_hellman(client_ephemeral,
    /// server_reality_public)`. The caller must own the ephemeral private
    /// key that matches [`Self::new`]'s public-key argument.
    #[must_use]
    pub fn with_reality_auth(mut self, cfg: &RealityConfig, shared_secret: &[u8; 32]) -> Self {
        self.reality_auth_key = Some(auth_key(shared_secret));
        self.reality_short_id.clone_from(&cfg.short_id);
        self
    }

    /// Override the random bytes used in `ClientHello.Random` and the
    /// session_id. Test-only — production code never sets this.
    #[must_use]
    pub fn with_deterministic_random(mut self, r: [u8; 32]) -> Self {
        self.deterministic_random = Some(r);
        self
    }

    /// Override the session_id directly. Test-only — production code never
    /// sets this; it lets us assert on the exact bytes produced.
    #[must_use]
    pub fn with_deterministic_session_id(mut self, sid: [u8; SESSION_ID_LEN]) -> Self {
        self.deterministic_session_id = Some(sid);
        self
    }

    /// Finalise the ClientHello.
    ///
    /// # Errors
    /// Returns [`Error::Tls`] when the server name is empty or longer than
    /// `u16::MAX` (TLS hard-cap).
    pub fn build(self) -> Result<ClientHello> {
        if self.server_name.is_empty() {
            return Err(Error::tls("forged hello: empty server_name"));
        }

        // 1. Random + session_id.
        let mut random = [0u8; 32];
        let mut session_id = [0u8; SESSION_ID_LEN];
        if let Some(r) = self.deterministic_random {
            random = r;
        } else {
            rand::thread_rng().fill_bytes(&mut random);
        }
        if let Some(sid) = self.deterministic_session_id {
            session_id = sid;
        } else {
            rand::thread_rng().fill_bytes(&mut session_id);
        }

        // 2. Reality auth signature (when enabled). The signature is
        //    HMAC-SHA256(auth_key, short_id || sni) truncated to 16
        //    bytes; we place it into the first 16 bytes of the session_id
        //    and leave the remaining 16 bytes as the (random) plaintext
        //    session id. A Reality-aware server recomputes the signature
        //    and verifies it; an unaware server just mirrors the 32 bytes
        //    back as a regular session id.
        if let Some(key) = self.reality_auth_key {
            let sig = auth_signature(&key, &self.reality_short_id, self.server_name.as_bytes());
            session_id[..16].copy_from_slice(&sig);
        }

        // 3. GREASE pick — Chrome derives this from a CSPRNG; we seed it
        //    off `random[0]` so each handshake picks a different value.
        let grease = grease_for(random[0]);

        // 4. Build the body.
        let mut body = TlsWriter::with_capacity(512);

        // legacy_version
        body.push_u16(LEGACY_VERSION_TLS12);
        // random
        body.push_bytes(&random);
        // legacy_session_id <0..32>
        body.with_u8_len(|w| w.push_bytes(&session_id));
        // cipher_suites <2..2^16-2> — GREASE first.
        body.with_u16_len(|w| {
            w.push_u16(grease);
            for cs in &self.profile.cipher_suites {
                w.push_u16(*cs);
            }
        });
        // compression_methods <1..2^8-1> — TLS 1.3 forbids compression.
        body.with_u8_len(|w| w.push_u8(0));
        // extensions <8..2^16-1>.
        body.with_u16_len(|w| {
            // GREASE always first.
            w.push_u16(grease);
            w.with_u16_len(|_| {});
            // Then the profile's ordered extensions.
            for ext_id in self.profile.extension_order.clone() {
                self.write_extension(w, ext_id);
            }
            // GREASE always last.
            let trailing = grease ^ 0x4a4a; // pick a *different* GREASE
            w.push_u16(trailing);
            w.with_u16_len(|_| {});
        });

        // 5. Optional padding so the on-the-wire record reaches the
        //    profile's `padding_target` byte count (RFC 7685).
        let body_bytes = body.into_bytes();
        let body_bytes = pad_to_target(body_bytes, self.profile.padding_target);

        // 6. Wrap in a handshake header.
        let mut hs_msg = TlsWriter::with_capacity(4 + body_bytes.len());
        hs_msg.push_u8(hs::CLIENT_HELLO);
        hs_msg.with_u24_len(|w| w.push_bytes(&body_bytes));
        let handshake_message = hs_msg.into_bytes();

        Ok(ClientHello {
            handshake_message,
            random,
            session_id,
            x25519_public_key: self.x25519_public_key,
        })
    }

    /// Emit one extension by its u16 ID. Each branch writes the extension
    /// header `(ext_id, u16 body_len)` and then the body itself.
    fn write_extension(&self, w: &mut TlsWriter, ext_id: u16) {
        w.push_u16(ext_id);
        match ext_id {
            ext::SERVER_NAME => w.with_u16_len(|w| {
                // server_name_list <1..2^16-1>
                w.with_u16_len(|w| {
                    w.push_u8(0); // name_type = host_name
                    w.with_u16_len(|w| w.push_bytes(self.server_name.as_bytes()));
                });
            }),
            ext::EXTENDED_MASTER_SECRET | ext::SESSION_TICKET => w.with_u16_len(|_| {}),
            ext::RENEGOTIATION_INFO => w.with_u16_len(|w| {
                // renegotiation_info <0..255> — always empty for the
                // initial handshake.
                w.with_u8_len(|_| {});
            }),
            ext::SUPPORTED_GROUPS => w.with_u16_len(|w| {
                w.with_u16_len(|w| {
                    for g in &self.profile.supported_groups {
                        w.push_u16(*g);
                    }
                });
            }),
            ext::EC_POINT_FORMATS => w.with_u16_len(|w| {
                w.with_u8_len(|w| {
                    if self.profile.send_ec_point_formats {
                        w.push_u8(0); // uncompressed
                    }
                });
            }),
            ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => w.with_u16_len(|w| {
                w.with_u16_len(|w| {
                    for proto in &self.profile.alpn {
                        w.with_u8_len(|w| w.push_bytes(proto.as_bytes()));
                    }
                });
            }),
            ext::STATUS_REQUEST => w.with_u16_len(|w| {
                w.push_u8(1); // status_type = ocsp
                w.with_u16_len(|_| {}); // responder_id_list — empty
                w.with_u16_len(|_| {}); // request_extensions — empty
            }),
            ext::SIGNATURE_ALGORITHMS => w.with_u16_len(|w| {
                w.with_u16_len(|w| {
                    for sa in &self.profile.signature_algorithms {
                        w.push_u16(*sa);
                    }
                });
            }),
            ext::SIGNED_CERTIFICATE_TIMESTAMP => w.with_u16_len(|_| {}),
            ext::KEY_SHARE => w.with_u16_len(|w| {
                w.with_u16_len(|w| {
                    w.push_u16(group::X25519);
                    w.with_u16_len(|w| w.push_bytes(&self.x25519_public_key));
                });
            }),
            ext::PSK_KEY_EXCHANGE_MODES => w.with_u16_len(|w| {
                w.with_u8_len(|w| w.push_u8(1)); // psk_ke + psk_dhe = 1 (dhe_ke)
            }),
            ext::SUPPORTED_VERSIONS => w.with_u16_len(|w| {
                w.with_u8_len(|w| {
                    w.push_u16(SUPPORTED_VERSION_TLS13);
                    w.push_u16(LEGACY_VERSION_TLS12);
                });
            }),
            ext::COMPRESS_CERTIFICATE => w.with_u16_len(|w| {
                w.with_u8_len(|w| {
                    w.push_u16(0x0002); // brotli
                });
            }),
            ext::APPLICATION_SETTINGS => w.with_u16_len(|w| {
                w.with_u16_len(|w| {
                    if self.profile.send_application_settings {
                        for proto in &self.profile.alpn {
                            w.with_u8_len(|w| w.push_bytes(proto.as_bytes()));
                        }
                    }
                });
            }),
            _ => {
                // Unknown extension — emit zero-length body. This branch
                // is only reachable when a profile lists an extension ID
                // we forgot to implement (a bug we want to surface in
                // tests, not silently corrupt the wire).
                w.with_u16_len(|_| {});
            }
        }
    }
}

/// Pad `body` with a `padding` extension so the *body* length is roughly
/// `target` bytes. The 4-byte handshake header and 5-byte record header
/// are *not* counted — they're added later.
fn pad_to_target(mut body: Vec<u8>, target: Option<usize>) -> Vec<u8> {
    let Some(target) = target else {
        return body;
    };

    // Estimate the size of the eventual handshake-wrapped record:
    //   record_header(5) + handshake_header(4) + body
    // Browsers actually target the body (legacy heuristic); follow suit.
    let extension_overhead = 4; // (u16 ext_id, u16 ext_body_len)
    if body.len() + extension_overhead >= target {
        return body;
    }
    let pad_body_len = target - body.len() - extension_overhead;

    // Pop the trailing extensions u16-length and rewrite. We rely on the
    // builder having placed the extensions block at the very tail of
    // `body`. To stay independent of that detail we instead append a
    // *new* `padding` extension at the end, and rewrite the *parent*
    // extensions length. That parent length lives at a known offset:
    //
    //   bytes [0..2]   legacy_version
    //   bytes [2..34]  random
    //   bytes [34]     session_id length
    //   bytes [35..35+sid_len] session_id
    //   …
    //
    // Rather than parse, we recompute the parent length by treating the
    // existing body as opaque and recursively patching: extract the
    // 2-byte "extensions length" near the tail, append the padding
    // extension, then write the new length back.
    //
    // The extensions block is the last variable-length field in the
    // ClientHello body, so its length prefix is at offset
    // `body.len() - ext_list_len - 2`. We find it by working backwards
    // from `body.len()`.

    // Compute the parent extensions list length: it's the field whose
    // u16 sits right before the extensions payload. Find its offset by
    // re-parsing the body header.
    let Some(ext_list_offset) = locate_extensions_list_offset(&body) else {
        return body; // shouldn't happen — leave unpadded
    };
    let cur_len = u16::from_be_bytes([body[ext_list_offset], body[ext_list_offset + 1]]) as usize;
    // Append `padding` extension to the body.
    body.extend_from_slice(&ext::PADDING.to_be_bytes());
    body.extend_from_slice(&u16::try_from(pad_body_len).unwrap_or(0).to_be_bytes());
    body.extend(std::iter::repeat(0u8).take(pad_body_len));
    let new_len = cur_len + extension_overhead + pad_body_len;
    let new_len_be = u16::try_from(new_len).unwrap_or(u16::MAX).to_be_bytes();
    body[ext_list_offset] = new_len_be[0];
    body[ext_list_offset + 1] = new_len_be[1];
    body
}

/// Locate the 2-byte length prefix of the extensions list inside a
/// ClientHello body. Returns `None` if the body is malformed.
fn locate_extensions_list_offset(body: &[u8]) -> Option<usize> {
    let mut r = TlsReader::new(body);
    r.read_u16().ok()?; // legacy_version
    r.read_bytes(32).ok()?; // random
    let sid_len = r.read_u8().ok()? as usize;
    r.read_bytes(sid_len).ok()?;
    let ciphers_len = r.read_u16().ok()? as usize;
    r.read_bytes(ciphers_len).ok()?;
    let compression_len = r.read_u8().ok()? as usize;
    r.read_bytes(compression_len).ok()?;
    Some(r.position())
}

/// Parsed ServerHello — just the bits the handshake state machine needs.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// 32-byte random sent by the server. Reality state machine binds it
    /// into the transcript hash like any TLS 1.3 client.
    pub random: [u8; 32],
    /// session_id mirrored from our request. A Reality-aware server
    /// produces a server-side proof of knowledge of `auth_key` here.
    pub session_id: Vec<u8>,
    /// Negotiated cipher suite.
    pub cipher_suite: u16,
    /// Server's X25519 public key from the key_share extension.
    pub server_x25519_public: [u8; X25519_KEY_LEN],
    /// Whether the supported_versions extension confirmed TLS 1.3. We
    /// only continue Reality when this is `true`.
    pub negotiated_tls13: bool,
}

/// Parse a TLS handshake-layer ServerHello (no record header).
///
/// `bytes` is expected to start with the handshake header (1 byte
/// `msg_type` + 3-byte length) and contain the entire ServerHello.
///
/// # Errors
/// Returns [`Error::Tls`] on any malformed length, unsupported version,
/// or non-x25519 key_share.
pub fn parse_server_hello(bytes: &[u8]) -> Result<ServerHello> {
    let mut r = TlsReader::new(bytes);

    let msg_type = r.read_u8().map_err(tls)?;
    if msg_type != hs::SERVER_HELLO {
        return Err(Error::tls(format!(
            "server hello: unexpected handshake type {msg_type:#x}"
        )));
    }
    let body_len = r.read_u24().map_err(tls)? as usize;
    if r.remaining() < body_len {
        return Err(Error::tls("server hello: truncated body"));
    }

    // legacy_version
    let _legacy_version = r.read_u16().map_err(tls)?;
    // random
    let random = {
        let s = r.read_bytes(32).map_err(tls)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        out
    };
    // legacy_session_id_echo <0..32>
    let session_id = r.read_u8_prefixed().map_err(tls)?.to_vec();
    // cipher_suite
    let cipher_suite = r.read_u16().map_err(tls)?;
    if !matches!(
        cipher_suite,
        cipher::TLS_AES_128_GCM_SHA256 | cipher::TLS_CHACHA20_POLY1305_SHA256
    ) {
        return Err(Error::tls(format!(
            "server hello: unsupported cipher_suite {cipher_suite:#06x} (only AES-128-GCM / ChaCha20-Poly1305 with SHA-256 are supported)"
        )));
    }
    // legacy_compression_method
    let _compression = r.read_u8().map_err(tls)?;
    // extensions <6..2^16-1>
    let extensions = r.read_u16_prefixed().map_err(tls)?;

    let (server_pub, negotiated_tls13) = parse_server_hello_extensions(extensions)?;

    Ok(ServerHello {
        random,
        session_id,
        cipher_suite,
        server_x25519_public: server_pub,
        negotiated_tls13,
    })
}

fn parse_server_hello_extensions(buf: &[u8]) -> Result<([u8; X25519_KEY_LEN], bool)> {
    let mut r = TlsReader::new(buf);
    let mut server_pub: Option<[u8; X25519_KEY_LEN]> = None;
    let mut tls13 = false;

    while !r.is_empty() {
        let ext_id = r.read_u16().map_err(tls)?;
        let ext_body = r.read_u16_prefixed().map_err(tls)?;
        match ext_id {
            ext::SUPPORTED_VERSIONS => {
                // ServerHello carries a single u16 selected_version.
                if ext_body.len() != 2 {
                    return Err(Error::tls("server hello: supported_versions wrong length"));
                }
                let v = u16::from_be_bytes([ext_body[0], ext_body[1]]);
                if v != SUPPORTED_VERSION_TLS13 {
                    return Err(Error::tls(format!("server hello: not TLS 1.3 ({v:#06x})")));
                }
                tls13 = true;
            }
            ext::KEY_SHARE => {
                // ServerHello.KeyShare: { NamedGroup group; <key_exchange><1..2^16-1> }
                let mut kr = TlsReader::new(ext_body);
                let g = kr.read_u16().map_err(tls)?;
                let ks = kr.read_u16_prefixed().map_err(tls)?;
                if g != group::X25519 {
                    return Err(Error::tls(format!(
                        "server hello: non-x25519 key_share ({g:#06x})"
                    )));
                }
                if ks.len() != X25519_KEY_LEN {
                    return Err(Error::tls("server hello: bad x25519 key share length"));
                }
                let mut pk = [0u8; X25519_KEY_LEN];
                pk.copy_from_slice(ks);
                server_pub = Some(pk);
            }
            _ => {} // Skip unknown extensions.
        }
    }

    let server_pub =
        server_pub.ok_or_else(|| Error::tls("server hello: missing key_share extension"))?;
    if !tls13 {
        return Err(Error::tls(
            "server hello: missing supported_versions(=TLS 1.3) — pre-1.3 cleartext rejected",
        ));
    }
    Ok((server_pub, tls13))
}

fn tls(e: impl std::fmt::Display) -> Error {
    Error::tls(format!("server hello: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        k
    }

    #[test]
    fn build_chrome_hello_emits_well_formed_record() {
        let hello =
            ClientHelloBuilder::new("www.example.com", Fingerprint::Chrome120, dummy_pubkey())
                .with_deterministic_random([0xAA; 32])
                .with_deterministic_session_id([0x55; SESSION_ID_LEN])
                .build()
                .expect("hello builds");

        assert_eq!(hello.random, [0xAA; 32]);
        assert_eq!(hello.session_id, [0x55; SESSION_ID_LEN]);

        let record = hello.to_record();
        assert_eq!(record[0], record_type::HANDSHAKE);
        // Record-layer legacy version is 0x0301.
        assert_eq!(&record[1..3], &[0x03, 0x01]);
        // Handshake msg type at offset 5 is ClientHello.
        assert_eq!(record[5], hs::CLIENT_HELLO);
        // ClientHello.legacy_version at offset 9 is TLS 1.2 (0x0303).
        assert_eq!(&record[9..11], &[0x03, 0x03]);
    }

    #[test]
    fn reality_signature_appears_in_first_16_bytes_of_session_id() {
        let cfg = RealityConfig {
            server_name: "vk.com".into(),
            server_public_key: [0xCC; 32],
            short_id: vec![0xab, 0xcd],
            spider_x: String::new(),
            fingerprint: "chrome".into(),
            alpn: vec!["h2".into()],
        };
        // Use a fixed shared secret so the test is deterministic.
        let shared = [0x11u8; 32];

        let hello = ClientHelloBuilder::new("vk.com", Fingerprint::Chrome120, dummy_pubkey())
            .with_deterministic_random([0; 32])
            .with_deterministic_session_id([0xFF; SESSION_ID_LEN])
            .with_reality_auth(&cfg, &shared)
            .build()
            .unwrap();

        // The Reality signature should have replaced the first 16 bytes
        // of the session_id, leaving the trailing 16 bytes untouched
        // (still 0xFF).
        let key = auth_key(&shared);
        let expected_sig = auth_signature(&key, &cfg.short_id, cfg.server_name.as_bytes());
        assert_eq!(&hello.session_id[..16], &expected_sig);
        assert_eq!(&hello.session_id[16..], &[0xFF; 16]);
    }

    #[test]
    fn build_rejects_empty_server_name() {
        let err = ClientHelloBuilder::new("", Fingerprint::Chrome120, dummy_pubkey())
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Tls(_)));
    }

    #[test]
    fn parse_server_hello_recovers_x25519_pubkey() {
        // Manually build a minimal but valid ServerHello.
        let server_pub = [0x77; 32];
        let session_id = vec![0xAB; SESSION_ID_LEN];

        let mut body = TlsWriter::with_capacity(128);
        body.push_u16(LEGACY_VERSION_TLS12); // legacy_version
        body.push_bytes(&[0xDD; 32]); // random
        body.with_u8_len(|w| w.push_bytes(&session_id)); // session_id_echo
        body.push_u16(cipher::TLS_AES_128_GCM_SHA256); // cipher_suite
        body.push_u8(0); // compression
        body.with_u16_len(|w| {
            // supported_versions = TLS 1.3
            w.push_u16(ext::SUPPORTED_VERSIONS);
            w.with_u16_len(|w| w.push_u16(SUPPORTED_VERSION_TLS13));
            // key_share = x25519, our pub key
            w.push_u16(ext::KEY_SHARE);
            w.with_u16_len(|w| {
                w.push_u16(group::X25519);
                w.with_u16_len(|w| w.push_bytes(&server_pub));
            });
        });
        let body = body.into_bytes();

        let mut msg = TlsWriter::with_capacity(body.len() + 4);
        msg.push_u8(hs::SERVER_HELLO);
        msg.with_u24_len(|w| w.push_bytes(&body));
        let bytes = msg.into_bytes();

        let sh = parse_server_hello(&bytes).expect("parses");
        assert_eq!(sh.server_x25519_public, server_pub);
        assert_eq!(sh.session_id, session_id);
        assert_eq!(sh.cipher_suite, cipher::TLS_AES_128_GCM_SHA256);
        assert!(sh.negotiated_tls13);
    }

    #[test]
    fn parse_server_hello_rejects_tls12_only() {
        // Same as above but supported_versions = TLS 1.2 — must be
        // rejected because Reality requires TLS 1.3.
        let mut body = TlsWriter::with_capacity(128);
        body.push_u16(LEGACY_VERSION_TLS12);
        body.push_bytes(&[0; 32]);
        body.with_u8_len(|_| {});
        body.push_u16(cipher::TLS_AES_128_GCM_SHA256);
        body.push_u8(0);
        body.with_u16_len(|w| {
            w.push_u16(ext::SUPPORTED_VERSIONS);
            w.with_u16_len(|w| w.push_u16(0x0303));
            w.push_u16(ext::KEY_SHARE);
            w.with_u16_len(|w| {
                w.push_u16(group::X25519);
                w.with_u16_len(|w| w.push_bytes(&[0; 32]));
            });
        });
        let body = body.into_bytes();

        let mut msg = TlsWriter::with_capacity(body.len() + 4);
        msg.push_u8(hs::SERVER_HELLO);
        msg.with_u24_len(|w| w.push_bytes(&body));
        let bytes = msg.into_bytes();

        let err = parse_server_hello(&bytes).unwrap_err();
        assert!(matches!(err, Error::Tls(_)));
    }

    #[test]
    fn parse_server_hello_rejects_non_x25519_keyshare() {
        let mut body = TlsWriter::with_capacity(128);
        body.push_u16(LEGACY_VERSION_TLS12);
        body.push_bytes(&[0; 32]);
        body.with_u8_len(|_| {});
        body.push_u16(cipher::TLS_AES_128_GCM_SHA256);
        body.push_u8(0);
        body.with_u16_len(|w| {
            w.push_u16(ext::SUPPORTED_VERSIONS);
            w.with_u16_len(|w| w.push_u16(SUPPORTED_VERSION_TLS13));
            w.push_u16(ext::KEY_SHARE);
            w.with_u16_len(|w| {
                w.push_u16(group::SECP256R1); // not x25519
                w.with_u16_len(|w| w.push_bytes(&[0; 65]));
            });
        });
        let body = body.into_bytes();

        let mut msg = TlsWriter::with_capacity(body.len() + 4);
        msg.push_u8(hs::SERVER_HELLO);
        msg.with_u24_len(|w| w.push_bytes(&body));
        let bytes = msg.into_bytes();

        let err = parse_server_hello(&bytes).unwrap_err();
        assert!(matches!(err, Error::Tls(_)));
    }

    #[test]
    fn padding_brings_hello_close_to_target_length() {
        let hello = ClientHelloBuilder::new("a.com", Fingerprint::Chrome120, dummy_pubkey())
            .with_deterministic_random([0; 32])
            .with_deterministic_session_id([0; SESSION_ID_LEN])
            .build()
            .unwrap();
        // Chrome targets 517 bytes. We tolerate a few bytes of slack.
        let body_len = hello.handshake_message.len() - 4; // strip hs header
        assert!(
            (510..=520).contains(&body_len),
            "padding brought body to {body_len}"
        );
    }
}
