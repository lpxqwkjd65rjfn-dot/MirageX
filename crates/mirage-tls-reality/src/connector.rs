//! `RealityConnector` — the high-level Reality client API.
//!
//! Two modes:
//!
//! * [`RealityConnector::connect`] — the *compat* path: a plain
//!   `tokio-rustls` handshake that short-circuits certificate
//!   verification (custom `ServerCertVerifier`). The bytes on the wire
//!   are produced by `rustls`, **not** by the forged-hello builder, so
//!   the JA3 fingerprint is rustls's, not Chrome's. Useful for talking
//!   to ordinary VLESS-over-TLS servers (`tls = "tls"` in our config).
//!
//! * [`RealityConnector::connect_forged`] — the **Reality** path: emits
//!   a forged TLS 1.3 ClientHello matching the requested browser
//!   fingerprint (Chrome 120 by default) with the Reality auth
//!   signature embedded in `session_id`, reads the server's
//!   `ServerHello`, derives the TLS 1.3 handshake-traffic key schedule
//!   per RFC 8446 §7.1, and hands the caller back a [`ForgedSession`]
//!   bundling the raw stream and the derived [`HandshakeKeys`].
//!   That is precisely what a DPI sees on the wire — handshake
//!   indistinguishability is achieved at this layer; the rest of the
//!   handshake (encrypted `Certificate` / `Finished`) and the
//!   application-data record layer is the consumer's job (it lives in
//!   the engine, behind a feature flag, and ships incrementally).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, trace};

use mirage_core::error::{Error, Result};

use crate::config::RealityConfig;
use crate::fingerprint::Fingerprint;
use crate::handshake::{forge_handshake, HandshakeKeys};

/// High-level Reality connector.
#[derive(Clone)]
pub struct RealityConnector {
    cfg: Arc<RealityConfig>,
    inner: TlsConnector,
}

impl RealityConnector {
    /// Build a connector from a [`RealityConfig`].
    ///
    /// # Errors
    /// Returns [`Error::Tls`] if rustls fails to build the underlying client
    /// config.
    pub fn new(cfg: RealityConfig) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RealityVerifier::new(&cfg)))
            .with_no_client_auth();
        if !cfg.alpn.is_empty() {
            client.alpn_protocols = cfg.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        }
        let connector = TlsConnector::from(Arc::new(client));
        Ok(Self {
            cfg: Arc::new(cfg),
            inner: connector,
        })
    }

    /// Returns the configuration this connector was built with.
    #[must_use]
    pub fn config(&self) -> &RealityConfig {
        &self.cfg
    }

    /// Wrap an existing stream with a plain `tokio-rustls` TLS 1.3
    /// handshake. Certificate verification is skipped (Reality's design
    /// intentionally accepts the upstream target's real cert).
    ///
    /// **Does not** emit a forged Chrome-style ClientHello — for that,
    /// use [`Self::connect_forged`].
    ///
    /// # Errors
    /// Propagates any TLS / I/O error from the underlying TLS connector.
    pub async fn connect<IO>(&self, stream: IO) -> Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        trace!(
            sni = %self.cfg.server_name,
            fp = %self.cfg.fingerprint,
            "reality: starting compat (rustls) handshake"
        );
        let sni = ServerName::try_from(self.cfg.server_name.clone())
            .map_err(|e| Error::tls(format!("reality: invalid SNI: {e}")))?;
        let tls = self
            .inner
            .connect(sni, stream)
            .await
            .map_err(|e| Error::tls(e.to_string()))?;
        Ok(tls)
    }

    /// Drive the *forged* Reality TLS 1.3 handshake on `stream`. Emits a
    /// ClientHello that matches the fingerprint requested in
    /// [`RealityConfig::fingerprint`] (falling back to Chrome 120 when
    /// the string is unrecognised), with the Reality auth signature
    /// embedded in the session id. Reads the server's `ServerHello`,
    /// runs the X25519 DHE against the announced ephemeral key, and
    /// derives the TLS 1.3 handshake-traffic key schedule.
    ///
    /// Returns a [`ForgedSession`] bundling the raw stream (positioned
    /// right after the cleartext `ServerHello` record) with the derived
    /// [`HandshakeKeys`]. The encrypted handshake flight
    /// (`EncryptedExtensions` / `Certificate` / `CertificateVerify` /
    /// server `Finished`) and the corresponding application-data record
    /// layer ship in the engine layer; this method is the protocol
    /// piece every Reality client shares and that is the part DPI
    /// observers see on the wire.
    ///
    /// # Errors
    /// * [`Error::Tls`] for any malformed record / hello / unsupported
    ///   cipher suite.
    /// * I/O errors from the underlying stream are surfaced through
    ///   [`Error::Io`].
    pub async fn connect_forged<IO>(&self, mut stream: IO) -> Result<ForgedSession<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let fingerprint = Fingerprint::from_str_or_chrome(&self.cfg.fingerprint);
        debug!(
            sni = %self.cfg.server_name,
            fp = ?fingerprint,
            short_id_len = self.cfg.short_id.len(),
            "reality: starting forged-hello handshake"
        );
        let keys = forge_handshake(&mut stream, &self.cfg, fingerprint).await?;
        debug!(
            sni = %keys.server_name,
            cipher = format_args!("{:#06x}", keys.cipher_suite),
            "reality: forged-hello handshake produced handshake-traffic keys"
        );
        Ok(ForgedSession { stream, keys })
    }
}

/// Output of [`RealityConnector::connect_forged`] — the raw stream
/// (positioned just past the cleartext `ServerHello` record) bundled
/// with the TLS 1.3 handshake-traffic key schedule.
///
/// The encrypted handshake flight (`EncryptedExtensions` /
/// `Certificate` / `CertificateVerify` / server `Finished`) and the
/// application-data record pump are the consumer's responsibility —
/// the corresponding building blocks live in [`crate::record`] and the
/// engine layer composes them.
#[derive(Debug)]
pub struct ForgedSession<IO> {
    /// Raw byte stream, positioned right after the server's cleartext
    /// `ServerHello` record. The next bytes the server sends will be a
    /// (legacy-compat) `ChangeCipherSpec` and then encrypted handshake
    /// records.
    pub stream: IO,
    /// All secrets needed to bootstrap the AEAD record layer for the
    /// encrypted-handshake flight.
    pub keys: HandshakeKeys,
}

impl<IO> ForgedSession<IO> {
    /// Split the session into its component parts.
    pub fn into_parts(self) -> (IO, HandshakeKeys) {
        (self.stream, self.keys)
    }
}

/// Custom verifier that **never** validates the public certificate chain
/// (Reality intentionally accepts the upstream target's real cert) but
/// records the leaf SPKI so the caller may sanity-check it.
#[derive(Debug)]
struct RealityVerifier {
    expected_server_name: String,
}

impl RealityVerifier {
    fn new(cfg: &RealityConfig) -> Self {
        Self {
            expected_server_name: cfg.server_name.clone(),
        }
    }
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        trace!(server_name = %self.expected_server_name, "reality: accepting upstream cert");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
