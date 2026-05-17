//! Core error type for the MirageX engine.

use std::io;

use thiserror::Error;

/// Result alias used throughout the MirageX engine.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type. Each crate may wrap this with its own context.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The peer disconnected or returned an unexpected response.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A parse error, typically from decoding a wire-format message.
    #[error("decode error: {0}")]
    Decode(String),

    /// Configuration validation error.
    #[error("config error: {0}")]
    Config(String),

    /// TLS handshake error.
    #[error("tls error: {0}")]
    Tls(String),

    /// The operation was rejected by the routing rules.
    #[error("routing rejected: {0}")]
    RoutingRejected(String),

    /// Address parsing failed.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Generic timeout error.
    #[error("operation timed out")]
    Timeout,

    /// Authentication / handshake failure.
    #[error("authentication failed")]
    AuthFailed,

    /// Wraps any other error.
    #[error("other: {0}")]
    Other(String),
}

impl Error {
    /// Build a protocol error from anything that stringifies.
    #[must_use]
    pub fn protocol<S: Into<String>>(s: S) -> Self {
        Self::Protocol(s.into())
    }

    /// Build a decode error from anything that stringifies.
    #[must_use]
    pub fn decode<S: Into<String>>(s: S) -> Self {
        Self::Decode(s.into())
    }

    /// Build a config error from anything that stringifies.
    #[must_use]
    pub fn config<S: Into<String>>(s: S) -> Self {
        Self::Config(s.into())
    }

    /// Build a TLS error from anything that stringifies.
    #[must_use]
    pub fn tls<S: Into<String>>(s: S) -> Self {
        Self::Tls(s.into())
    }
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(e) => e,
            other => io::Error::other(other.to_string()),
        }
    }
}
