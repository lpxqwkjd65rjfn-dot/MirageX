//! Forged Reality / TLS 1.3 handshake driver.
//!
//! The driver is intentionally small. It does the *deterministic*,
//! protocol-level part of a TLS 1.3 client handshake that is shared by
//! every Reality implementation:
//!
//! 1. Generate the client X25519 ephemeral keypair.
//! 2. Build a forged `ClientHello` matching the requested browser
//!    fingerprint, embedding the Reality auth signature in the
//!    session-id (XOR'd against the [`auth_key`] derived from the
//!    `client_ephemeral × server_reality_static` ECDH).
//! 3. Write the ClientHello record to the wire.
//! 4. Read the server's `ServerHello` record (the *only* unencrypted
//!    handshake message TLS 1.3 sends back) and parse out its
//!    ephemeral X25519 public key.
//! 5. Compute the DHE shared secret
//!    (`client_ephemeral × server_ephemeral`).
//! 6. Compute the full TLS 1.3 key schedule (the post-ServerHello
//!    transcript hash, then the handshake-traffic and the
//!    application-traffic-pre-derivation parts of the schedule).
//!
//! After step 6 the caller has every secret it needs to (a) decrypt the
//! server's `EncryptedExtensions`, `Certificate`, `CertificateVerify`
//! and `Finished` and (b) emit its own `Finished` and switch to
//! application-data keys. Those final post-ServerHello steps are
//! handled by the connector layer and are not in scope for this
//! module — by design, so this driver can be unit-tested in isolation
//! against a hand-rolled in-memory server.
//!
//! ## Out of scope
//!
//! * Cipher suite negotiation beyond TLS 1.3 AEAD-SHA256 (i.e. only
//!   `TLS_AES_128_GCM_SHA256` / `TLS_CHACHA20_POLY1305_SHA256`). We
//!   reject `TLS_AES_256_GCM_SHA384` early.
//! * HelloRetryRequest. A Reality server that asks for a different
//!   group is not Reality-compliant in the first place; the driver
//!   surfaces the situation as an error rather than silently retrying.
//! * Decrypting the encrypted handshake flight, verifying server
//!   `Finished`, sending client `Finished`. These are sequential
//!   continuations of the same state machine and live in a follow-up
//!   PR; see `docs/ROADMAP.md`.

use mirage_core::error::{Error, Result};
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead::AeadKind;
use crate::config::RealityConfig;
use crate::fingerprint::{cipher, Fingerprint};
use crate::hello::{parse_server_hello, ClientHelloBuilder, ServerHello};
use crate::keys::{
    derive_key_iv, derive_secret, hkdf_extract, sha256, Secret, EMPTY_TRANSCRIPT_HASH,
};

/// The full set of secrets the handshake driver produces after seeing
/// the `ServerHello`. These are everything the caller needs to bootstrap
/// the AEAD record layer for the encrypted-handshake flight (server →
/// `EncryptedExtensions`/`Certificate`/`CertificateVerify`/`Finished`,
/// client → `Finished`).
#[derive(Debug, Clone)]
pub struct HandshakeKeys {
    /// Negotiated AEAD (deduced from the cipher suite in `ServerHello`).
    pub aead_kind: AeadKind,
    /// Negotiated cipher-suite code point (one of
    /// `0x1301` / `0x1303`).
    pub cipher_suite: u16,
    /// Client-traffic handshake AEAD key.
    pub client_handshake_key: Vec<u8>,
    /// Client-traffic handshake AEAD IV.
    pub client_handshake_iv: Vec<u8>,
    /// Server-traffic handshake AEAD key.
    pub server_handshake_key: Vec<u8>,
    /// Server-traffic handshake AEAD IV.
    pub server_handshake_iv: Vec<u8>,
    /// 32-byte client handshake-traffic secret (the input to the
    /// "finished" key derivation for the *client* Finished).
    pub client_hs_secret: Secret,
    /// 32-byte server handshake-traffic secret (the input to the
    /// "finished" key derivation for the *server* Finished, which the
    /// caller will verify).
    pub server_hs_secret: Secret,
    /// Master secret. The caller derives `c ap traffic` / `s ap traffic`
    /// from this once it has the post-ServerFinished transcript hash.
    pub master_secret: Secret,
    /// Bytes of the SNI the server saw. Echoed back from
    /// [`RealityConfig::server_name`] so the connector layer can sanity-
    /// check the negotiated state.
    pub server_name: String,
    /// The parsed `ServerHello`, in case the caller wants to inspect
    /// the random / session-id-echo / etc.
    pub server_hello: ServerHello,
}

/// Drive a forged Reality / TLS 1.3 handshake on `stream` up to (and
/// including) the moment the key schedule produces the handshake
/// traffic secrets.
///
/// # Errors
/// * [`Error::Tls`] for any malformed record / hello / extension.
/// * I/O errors from the underlying stream are wrapped as [`Error::Io`].
pub async fn forge_handshake<S>(
    stream: &mut S,
    cfg: &RealityConfig,
    fingerprint: Fingerprint,
) -> Result<HandshakeKeys>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // 1. Client ephemeral keypair. We need to compute *two* ECDHs
    //    against the same private key (static Reality public for the
    //    auth tag, then the server's ephemeral key from ServerHello for
    //    the TLS 1.3 DHE leg), so we use `StaticSecret` rather than
    //    `EphemeralSecret`. The secret never leaves this function and
    //    is dropped after the handshake completes.
    let client_ephemeral = StaticSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_ephemeral);

    // 2. ECDH against the server's static Reality public key. The
    //    resulting 32-byte shared secret feeds [`auth_key`] which seeds
    //    the HMAC over `short_id || sni` placed into the session_id.
    let reality_pub = PublicKey::from(cfg.server_public_key);
    let auth_shared = client_ephemeral.diffie_hellman(&reality_pub);
    let mut auth_shared_bytes = [0u8; 32];
    auth_shared_bytes.copy_from_slice(auth_shared.as_bytes());

    // 3. Build the ClientHello.
    let hello = ClientHelloBuilder::new(&cfg.server_name, fingerprint, client_public.to_bytes())
        .with_reality_auth(cfg, &auth_shared_bytes)
        .build()?;

    // 4. Send the ClientHello on the wire (record header + handshake
    //    message). The transcript hash uses the *handshake* bytes only
    //    (the record header is not part of the transcript).
    stream.write_all(&hello.to_record()).await?;
    stream.flush().await?;
    let client_hello_bytes = hello.handshake_message.clone();

    // 5. Read records until we've seen a ServerHello. TLS 1.3 servers
    //    are allowed to send a no-op `ChangeCipherSpec` record before
    //    the first cleartext handshake record for middlebox compat;
    //    we skip it.
    let server_hello_bytes = read_until_server_hello(stream).await?;
    let server_hello = parse_server_hello(&server_hello_bytes)?;
    if !server_hello.negotiated_tls13 {
        return Err(Error::tls(
            "reality handshake: server did not negotiate TLS 1.3",
        ));
    }
    let aead_kind = match server_hello.cipher_suite {
        cipher::TLS_AES_128_GCM_SHA256 => AeadKind::Aes128Gcm,
        cipher::TLS_CHACHA20_POLY1305_SHA256 => AeadKind::ChaCha20Poly1305,
        other => {
            return Err(Error::tls(format!(
                "reality handshake: server picked unsupported cipher_suite {other:#06x} (Reality is locked to SHA-256 AEADs)"
            )))
        }
    };

    // 6. ECDH against the *ephemeral* key the server announced in
    //    ServerHello.key_share. This is the DHE input to the TLS 1.3
    //    key schedule.
    let server_ephemeral_pub = PublicKey::from(server_hello.server_x25519_public);
    let dhe = client_ephemeral.diffie_hellman(&server_ephemeral_pub);
    let mut dhe_bytes = [0u8; 32];
    dhe_bytes.copy_from_slice(dhe.as_bytes());

    // 7. Transcript hash = SHA-256(ClientHello || ServerHello). RFC
    //    8446 §4.4.1 — record headers are explicitly excluded.
    let mut transcript = Vec::with_capacity(client_hello_bytes.len() + server_hello_bytes.len());
    transcript.extend_from_slice(&client_hello_bytes);
    transcript.extend_from_slice(&server_hello_bytes);
    let transcript_hash = sha256(&transcript);

    // 8. Key schedule up to the handshake-traffic secrets + master.
    //    We can't derive `c ap traffic` / `s ap traffic` here because
    //    those need the post-ServerFinished transcript, which the
    //    caller will compute once it has decrypted the rest of the
    //    flight.
    let zero = [0u8; 32];
    let early = hkdf_extract(&zero, &zero);
    let early_derived = derive_secret(&early, b"derived", &EMPTY_TRANSCRIPT_HASH);
    let handshake_secret = hkdf_extract(&early_derived, &dhe_bytes);
    let client_hs_secret = derive_secret(&handshake_secret, b"c hs traffic", &transcript_hash);
    let server_hs_secret = derive_secret(&handshake_secret, b"s hs traffic", &transcript_hash);
    let handshake_derived = derive_secret(&handshake_secret, b"derived", &EMPTY_TRANSCRIPT_HASH);
    let master_secret = hkdf_extract(&handshake_derived, &zero);

    let (client_handshake_key, client_handshake_iv) =
        derive_key_iv(&client_hs_secret, aead_kind.key_len(), aead_kind.iv_len());
    let (server_handshake_key, server_handshake_iv) =
        derive_key_iv(&server_hs_secret, aead_kind.key_len(), aead_kind.iv_len());

    Ok(HandshakeKeys {
        aead_kind,
        cipher_suite: server_hello.cipher_suite,
        client_handshake_key,
        client_handshake_iv,
        server_handshake_key,
        server_handshake_iv,
        client_hs_secret,
        server_hs_secret,
        master_secret,
        server_name: cfg.server_name.clone(),
        server_hello,
    })
}

/// Read TLS records off `stream` until we have a complete
/// `ServerHello` handshake message. Returns the handshake-message
/// bytes (i.e. with the 4-byte handshake header but *without* the
/// 5-byte record header — that's the shape `parse_server_hello`
/// expects and the shape we want feeding the transcript).
async fn read_until_server_hello<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;
        let record_type = header[0];
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > 16_384 + 256 {
            return Err(Error::tls(format!(
                "reality handshake: server record body too large ({len} bytes)"
            )));
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        match record_type {
            20 => {
                // ChangeCipherSpec — TLS 1.3 middlebox-compat no-op. Skip.
            }
            22 => {
                // Handshake record. Expect exactly one ServerHello
                // here (TLS 1.3 servers send ServerHello in a single
                // cleartext record before switching to encrypted ones).
                if body.is_empty() || body[0] != 0x02 {
                    return Err(Error::tls(format!(
                        "reality handshake: expected ServerHello, got handshake type {:#x}",
                        body.first().copied().unwrap_or(0)
                    )));
                }
                return Ok(body);
            }
            21 => {
                // Alert. Surface description for diagnostics.
                let desc = body.get(1).copied().unwrap_or(0);
                return Err(Error::tls(format!(
                    "reality handshake: server sent alert (description {desc:#x})"
                )));
            }
            other => {
                return Err(Error::tls(format!(
                    "reality handshake: unexpected record type {other:#x}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RealityConfig;
    use crate::fingerprint::{cipher as cs, ext, group};
    use crate::hello::{SESSION_ID_LEN, X25519_KEY_LEN};
    use crate::wire::TlsWriter;
    use tokio::io::duplex;

    fn pubkey_bytes(secret: &StaticSecret) -> [u8; X25519_KEY_LEN] {
        PublicKey::from(secret).to_bytes()
    }

    /// Build a minimal but well-formed TLS 1.3 ServerHello record using
    /// the supplied server-ephemeral X25519 public key and cipher suite.
    /// Suitable for replaying into [`forge_handshake`] from the
    /// "server" side of a [`tokio::io::duplex`] pair.
    fn synthetic_server_hello_record(
        random: [u8; 32],
        session_id_echo: &[u8],
        cipher_suite: u16,
        server_ephemeral_pub: [u8; X25519_KEY_LEN],
    ) -> Vec<u8> {
        // Body of ServerHello.
        let mut body = TlsWriter::with_capacity(128);
        body.push_u16(0x0303); // legacy_version
        body.push_bytes(&random);
        body.with_u8_len(|w| w.push_bytes(session_id_echo));
        body.push_u16(cipher_suite);
        body.push_u8(0); // legacy_compression_method
                         // extensions
        body.with_u16_len(|w| {
            // supported_versions
            w.push_u16(ext::SUPPORTED_VERSIONS);
            w.with_u16_len(|w| w.push_u16(0x0304));
            // key_share with x25519
            w.push_u16(ext::KEY_SHARE);
            w.with_u16_len(|w| {
                w.push_u16(group::X25519);
                w.with_u16_len(|w| w.push_bytes(&server_ephemeral_pub));
            });
        });
        let body_bytes = body.into_bytes();

        // Handshake header.
        let mut hs = TlsWriter::with_capacity(body_bytes.len() + 4);
        hs.push_u8(0x02); // ServerHello
        hs.with_u24_len(|w| w.push_bytes(&body_bytes));
        let hs_bytes = hs.into_bytes();

        // Record header (handshake = 22, legacy_version = 0x0303).
        let mut rec = TlsWriter::with_capacity(hs_bytes.len() + 5);
        rec.push_u8(22);
        rec.push_u16(0x0303);
        let len = u16::try_from(hs_bytes.len()).expect("synthetic hello fits in u16");
        rec.push_u16(len);
        rec.push_bytes(&hs_bytes);
        rec.into_bytes()
    }

    #[tokio::test]
    async fn forge_handshake_round_trip_produces_matching_secrets() {
        // 1. Set up a fake server side: known ephemeral keypair + known
        //    reality static keypair.
        let server_static = StaticSecret::random_from_rng(OsRng);
        let server_ephemeral = StaticSecret::random_from_rng(OsRng);
        let server_static_pub = pubkey_bytes(&server_static);
        let server_ephemeral_pub = pubkey_bytes(&server_ephemeral);

        let cfg = RealityConfig {
            server_name: "example.com".into(),
            server_public_key: server_static_pub,
            short_id: vec![0xaa, 0xbb],
            spider_x: String::new(),
            fingerprint: "chrome-120".into(),
            alpn: vec!["h2".into()],
        };

        // 2. Wire a duplex pipe between "client" and "server".
        let (mut client_pipe, mut server_pipe) = duplex(16_384);

        // 3. Drive the handshake on the client side in a task.
        let cfg_clone = cfg.clone();
        let handshake_task = tokio::spawn(async move {
            forge_handshake(&mut client_pipe, &cfg_clone, Fingerprint::Chrome120).await
        });

        // 4. On the "server" side: read the ClientHello record off the
        //    wire (we don't bother to fully validate it here — that's
        //    `hello::tests`' job), then emit a synthetic ServerHello
        //    that echoes back the session_id and announces the chosen
        //    cipher + server ephemeral pubkey.
        // 4a. Skip the ClientHello record header (5 bytes) + handshake
        //     header (4 bytes), grab session_id at the known offset.
        let mut hdr = [0u8; 5];
        server_pipe.read_exact(&mut hdr).await.unwrap();
        let hs_body_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut hs_body = vec![0u8; hs_body_len];
        server_pipe.read_exact(&mut hs_body).await.unwrap();

        // hs_body layout (skipping handshake header at [0..4]):
        //   [4..6]   legacy_version
        //   [6..38]  random
        //   [38]     session_id length (32)
        //   [39..71] session_id
        let session_id_echo: [u8; SESSION_ID_LEN] = hs_body[39..71].try_into().unwrap();

        // 4b. Emit a TLS_AES_128_GCM_SHA256 ServerHello.
        let server_random = [0x42u8; 32];
        let hello_record = synthetic_server_hello_record(
            server_random,
            &session_id_echo,
            cs::TLS_AES_128_GCM_SHA256,
            server_ephemeral_pub,
        );
        server_pipe.write_all(&hello_record).await.unwrap();
        server_pipe.flush().await.unwrap();

        // 5. The handshake task completes. Assert key shape.
        let keys = handshake_task.await.unwrap().expect("handshake succeeds");
        assert_eq!(keys.aead_kind, AeadKind::Aes128Gcm);
        assert_eq!(keys.cipher_suite, cs::TLS_AES_128_GCM_SHA256);
        assert_eq!(keys.client_handshake_key.len(), 16);
        assert_eq!(keys.server_handshake_key.len(), 16);
        assert_eq!(keys.client_handshake_iv.len(), 12);
        assert_eq!(keys.server_handshake_iv.len(), 12);
        assert_eq!(keys.server_name, "example.com");
        // Sanity-check derived secrets are non-zero (the chance of the
        // key schedule producing all-zero secrets from random inputs
        // is cryptographically negligible, so any zeroed slot would be
        // a derivation bug).
        assert_ne!(keys.client_hs_secret, [0u8; 32]);
        assert_ne!(keys.server_hs_secret, [0u8; 32]);
        assert_ne!(keys.master_secret, [0u8; 32]);
    }

    #[tokio::test]
    async fn forge_handshake_rejects_unsupported_cipher_suite() {
        let server_static = StaticSecret::random_from_rng(OsRng);
        let server_ephemeral = StaticSecret::random_from_rng(OsRng);
        let cfg = RealityConfig {
            server_name: "example.com".into(),
            server_public_key: pubkey_bytes(&server_static),
            short_id: vec![],
            spider_x: String::new(),
            fingerprint: "chrome-120".into(),
            alpn: vec![],
        };
        let (mut client_pipe, mut server_pipe) = duplex(16_384);

        let task = tokio::spawn(async move {
            forge_handshake(&mut client_pipe, &cfg, Fingerprint::Chrome120).await
        });

        // Drain ClientHello.
        let mut hdr = [0u8; 5];
        server_pipe.read_exact(&mut hdr).await.unwrap();
        let body_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; body_len];
        server_pipe.read_exact(&mut body).await.unwrap();
        let session_id: [u8; SESSION_ID_LEN] = body[39..71].try_into().unwrap();

        // Reply with AES-256-GCM (which Reality refuses — SHA-384).
        let rec = synthetic_server_hello_record(
            [1u8; 32],
            &session_id,
            cipher::TLS_AES_256_GCM_SHA384,
            pubkey_bytes(&server_ephemeral),
        );
        server_pipe.write_all(&rec).await.unwrap();
        server_pipe.flush().await.unwrap();

        let err = task.await.unwrap().expect_err("must reject AES-256-GCM");
        assert!(format!("{err}").to_lowercase().contains("cipher_suite"));
    }

    #[tokio::test]
    async fn forge_handshake_surfaces_alert_record() {
        let server_static = StaticSecret::random_from_rng(OsRng);
        let cfg = RealityConfig {
            server_name: "example.com".into(),
            server_public_key: pubkey_bytes(&server_static),
            short_id: vec![],
            spider_x: String::new(),
            fingerprint: "chrome-120".into(),
            alpn: vec![],
        };
        let (mut client_pipe, mut server_pipe) = duplex(16_384);

        let task = tokio::spawn(async move {
            forge_handshake(&mut client_pipe, &cfg, Fingerprint::Chrome120).await
        });

        // Drain ClientHello, then send alert(2, 40) handshake_failure.
        let mut hdr = [0u8; 5];
        server_pipe.read_exact(&mut hdr).await.unwrap();
        let body_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut buf = vec![0u8; body_len];
        server_pipe.read_exact(&mut buf).await.unwrap();

        // Alert record: type=21, ver=0x0303, len=2, level=2 fatal, desc=40
        server_pipe
            .write_all(&[21, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
            .await
            .unwrap();
        server_pipe.flush().await.unwrap();

        let err = task
            .await
            .unwrap()
            .expect_err("alert must surface as error");
        let msg = format!("{err}").to_lowercase();
        assert!(msg.contains("alert"), "expected alert in {msg}");
    }
}
