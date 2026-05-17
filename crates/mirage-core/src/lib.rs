//! mirage-core
//!
//! Shared types and traits used across the MirageX engine. This crate is intentionally
//! tiny and dependency-light so that every other crate in the workspace can depend on it
//! without dragging in heavyweight transitive dependencies.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

pub mod address;
pub mod error;
pub mod network;
pub mod stream;

pub use address::{Address, AddressKind};
pub use error::{Error, Result};
pub use network::Network;
pub use stream::{ProxyStream, ProxyStreamExt};
