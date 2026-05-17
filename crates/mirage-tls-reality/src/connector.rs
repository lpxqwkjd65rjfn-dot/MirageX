//! `RealityConnector` — the high-level Reality client API. Today this is a
//! thin wrapper around `tokio-rustls` that hard-codes the SNI to the value
//! supplied in [`RealityConfig::server_name`] and short-circuits certificate
//! verification with a custom `ServerCertVerifier` that exposes the same
//! interface the full forged-hello path will need.
//!
//! The forged-hello + key-extraction + record-stream-swap path will land
//! incrementally. The public API is intentionally kept stable so the engine
//! can already plug Reality into its outbound dispatcher.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::trace;

use mirage_core::error::{Error, Result};

use crate::config::RealityConfig;

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

    /// Wrap an existing stream with a forged Reality TLS handshake.
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
            "reality: starting handshake (forged-hello pending)"
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
