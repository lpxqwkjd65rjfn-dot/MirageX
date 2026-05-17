//! mirage-tls-reality
//!
//! Reality is an "uTLS-on-the-wire" handshake that forges a ClientHello matching
//! a real fingerprint (Chrome, Firefox, etc.), establishes a TLS session against
//! the *real* target host's certificate, and only after the handshake completes
//! does the client switch the encrypted record stream over to the proxy server
//! (which has been transparently man-in-the-middling the handshake using a
//! pre-shared X25519 key + SNI).
//!
//! This crate provides:
//!
//! * [`RealityConfig`] — the static configuration (public key, short id, fingerprint).
//! * [`RealityConnector`] — the connector trait that turns a [`tokio::net::TcpStream`]
//!   into an authenticated, Reality-encrypted [`tokio::io::AsyncRead`] +
//!   [`tokio::io::AsyncWrite`] stream.
//! * [`auth_key`] / [`auth_signature`] — primitive helpers (X25519 → HKDF → HMAC)
//!   that the rest of the engine can also use for sanity checks.
//!
//! The full Reality handshake is large (rustls client patches + uTLS-style hello
//! forging) and is being implemented incrementally. The current crate provides
//! the cryptographic primitives, the configuration plumbing, and a vetted public
//! API that the higher layers can already use. The `connect` method calls into
//! `tokio-rustls` with the configured SNI; once the forged-hello layer lands
//! this remains the externally visible interface.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::unnecessary_wraps
)]

pub mod auth;
pub mod config;
pub mod connector;

pub use auth::{auth_key, auth_signature};
pub use config::RealityConfig;
pub use connector::RealityConnector;
