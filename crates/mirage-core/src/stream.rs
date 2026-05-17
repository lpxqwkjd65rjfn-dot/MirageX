//! Trait object that all proxy connections (raw TCP, Reality TLS, XHTTP-tunnelled,
//! Vision-wrapped, etc.) implement. Using a single trait simplifies the engine's
//! copy loop and lets every transport be composed identically.

use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

/// Marker trait that combines [`AsyncRead`] + [`AsyncWrite`] + `Send` + `Unpin`. Every
/// transport in MirageX boxes itself as a `Pin<Box<dyn ProxyStream>>`.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized {}

/// Convenience alias for the boxed trait object actually carried around by the engine.
pub type BoxedStream = Pin<Box<dyn ProxyStream>>;

/// Helper extension trait — currently empty but reserved for future hot-path helpers
/// (e.g. `splice`/`zero-copy` shortcuts on Linux, vectored I/O, ECN signalling).
pub trait ProxyStreamExt: ProxyStream {}

impl<T: ProxyStream + ?Sized> ProxyStreamExt for T {}
