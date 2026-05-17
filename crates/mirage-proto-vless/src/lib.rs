//! mirage-proto-vless
//!
//! VLESS protocol implementation (wire format compatible with Xray / V2Fly).
//!
//! VLESS is intentionally stateless and crypto-free: all confidentiality is
//! delegated to the outer layer (Reality / TLS), and the framing is a tiny
//! handshake header followed by the raw payload. That makes it trivial to
//! pipe through alternative transports (XHTTP, gRPC, WebSocket, raw TCP)
//! without changing the wire format.
//!
//! Wire format (request, client → server):
//!
//! ```text
//! +--------+---------+-----------+---------+--------+---------+------+----------+--------+
//! | ver(1) | UUID(16)| addonLen(1)| addons | cmd(1) | port(2) | atyp | addr...  | payload|
//! +--------+---------+-----------+---------+--------+---------+------+----------+--------+
//! ```
//!
//! Response (server → client):
//! ```text
//! +--------+-----------+--------+----------+
//! | ver(1) | addonLen(1)| addons | payload |
//! +--------+-----------+--------+----------+
//! ```
//!
//! `addons` carries optional metadata such as the `flow` marker
//! (`xtls-rprx-vision`). Inside Xray it is serialised as a length-prefixed
//! protobuf `Addons` message; for interoperability we accept and emit the
//! exact same encoding.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::checked_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

pub mod codec;
pub mod request;
pub mod response;

pub use codec::{decode_request, encode_request, encode_response, parse_response_header};
pub use request::{Command, Request, RequestAddons};
pub use response::Response;

/// VLESS protocol version. Only `0` is currently used in the wild.
pub const VERSION: u8 = 0;
