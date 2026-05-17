//! Encoder / decoder for the VLESS wire format. We do **not** use the
//! `protobuf` crate for the addons block; instead we hand-roll a minimal
//! parser that covers exactly the two fields Xray emits in practice. That
//! keeps the dependency surface small and the code auditable.
//!
//! Format quick reference (request):
//! ```text
//! +--------+---------+-----------+---------+--------+---------+------+----------+
//! | ver(1) | UUID(16)| addonLen(1)| addons | cmd(1) | port(2) | atyp | addr...  |
//! +--------+---------+-----------+---------+--------+---------+------+----------+
//! ```
//!
//! Address type byte (`atyp`):
//! * `0x01` IPv4 (4 bytes)
//! * `0x02` Domain (1-byte length-prefix, then UTF-8 bytes)
//! * `0x03` IPv6 (16 bytes)

use std::net::IpAddr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use uuid::Uuid;

use mirage_core::address::{Address, Host};
use mirage_core::error::{Error, Result};

use crate::request::{Command, Request, RequestAddons};
use crate::response::Response;
use crate::VERSION;

/// Encode a request header into the supplied buffer. The buffer is **not**
/// cleared; bytes are appended.
///
/// # Errors
/// Returns [`Error::Protocol`] when the destination address or addons block
/// exceed the wire-format limits.
pub fn encode_request(req: &Request, out: &mut BytesMut) -> Result<()> {
    out.put_u8(VERSION);
    out.put_slice(req.uuid.as_bytes());

    // Encode addons into a temporary buffer first so we can length-prefix.
    let mut addons_buf = BytesMut::with_capacity(64);
    encode_addons(&req.addons, &mut addons_buf)?;
    if addons_buf.len() > u8::MAX as usize {
        return Err(Error::protocol("vless addons block too large"));
    }
    out.put_u8(addons_buf.len() as u8);
    out.put_slice(&addons_buf);

    out.put_u8(req.command as u8);
    out.put_u16(req.destination.port);

    match &req.destination.host {
        Host::Ip(IpAddr::V4(v4)) => {
            out.put_u8(0x01);
            out.put_slice(&v4.octets());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            out.put_u8(0x03);
            out.put_slice(&v6.octets());
        }
        Host::Domain(d) => {
            let bytes = d.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(Error::protocol("vless domain length out of range"));
            }
            out.put_u8(0x02);
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
        }
    }
    Ok(())
}

/// Decode a request header from a contiguous buffer. The remainder of the
/// buffer (after the header) is the start of the payload and is returned to
/// the caller as a [`Bytes`] slice via the returned tuple.
///
/// # Errors
/// Returns [`Error::Decode`] on any malformed input.
pub fn decode_request(mut input: Bytes) -> Result<(Request, Bytes)> {
    if input.remaining() < 1 + 16 + 1 + 1 + 2 + 1 {
        return Err(Error::decode("vless request truncated"));
    }
    let ver = input.get_u8();
    if ver != VERSION {
        return Err(Error::decode(format!("unsupported vless version: {ver}")));
    }
    let mut uuid_bytes = [0u8; 16];
    input.copy_to_slice(&mut uuid_bytes);
    let uuid = Uuid::from_bytes(uuid_bytes);

    let addons_len = input.get_u8() as usize;
    if input.remaining() < addons_len + 1 + 2 + 1 {
        return Err(Error::decode("vless addons block truncated"));
    }
    let addons_bytes = input.split_to(addons_len);
    let addons = decode_addons(addons_bytes)?;

    let cmd_byte = input.get_u8();
    let command = Command::from_u8(cmd_byte)
        .ok_or_else(|| Error::decode(format!("unknown vless command: {cmd_byte}")))?;

    let port = input.get_u16();
    let atyp = input.get_u8();
    let host = match atyp {
        0x01 => {
            if input.remaining() < 4 {
                return Err(Error::decode("vless ipv4 truncated"));
            }
            let mut o = [0u8; 4];
            input.copy_to_slice(&mut o);
            Host::Ip(IpAddr::V4(o.into()))
        }
        0x02 => {
            if input.remaining() < 1 {
                return Err(Error::decode("vless domain length truncated"));
            }
            let len = input.get_u8() as usize;
            if input.remaining() < len {
                return Err(Error::decode("vless domain bytes truncated"));
            }
            let bytes = input.split_to(len);
            let domain = std::str::from_utf8(&bytes)
                .map_err(|_| Error::decode("vless domain not UTF-8"))?
                .to_owned();
            Host::Domain(domain)
        }
        0x03 => {
            if input.remaining() < 16 {
                return Err(Error::decode("vless ipv6 truncated"));
            }
            let mut o = [0u8; 16];
            input.copy_to_slice(&mut o);
            Host::Ip(IpAddr::V6(o.into()))
        }
        other => return Err(Error::decode(format!("unknown atyp byte: {other}"))),
    };

    let req = Request {
        uuid,
        addons,
        command,
        destination: Address { host, port },
    };
    Ok((req, input))
}

/// Encode a server response (header only). Append the payload directly after.
pub fn encode_response(resp: &Response, out: &mut BytesMut) {
    out.put_u8(VERSION);
    debug_assert!(resp.addons.len() <= u8::MAX as usize);
    out.put_u8(resp.addons.len() as u8);
    out.put_slice(&resp.addons);
}

/// Try to parse a VLESS response header from a buffer.
///
/// Returns `Ok(Some((response, header_len)))` if the header is fully present,
/// `Ok(None)` if more bytes are needed, or `Err` on malformed input.
///
/// # Errors
/// Returns [`Error::Decode`] on malformed input.
pub fn parse_response_header(buf: &[u8]) -> Result<Option<(Response, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let ver = buf[0];
    if ver != VERSION {
        return Err(Error::decode(format!("unsupported vless version: {ver}")));
    }
    let addons_len = buf[1] as usize;
    let total = 2 + addons_len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((
        Response {
            addons: buf[2..total].to_vec(),
        },
        total,
    )))
}

/// Encode an [`RequestAddons`] block into the supplied buffer using a minimal
/// protobuf-compatible encoding. We emit only the two well-known fields
/// (`flow = 1`, `seed = 2`) and any opaque `extra` bytes are appended
/// verbatim. This is byte-for-byte compatible with Xray's emission.
fn encode_addons(a: &RequestAddons, out: &mut BytesMut) -> Result<()> {
    if a.is_empty() {
        return Ok(());
    }
    if !a.flow.is_empty() {
        // tag 1 (LEN) => 0x0A
        out.put_u8(0x0A);
        put_varint(a.flow.len() as u64, out)?;
        out.put_slice(a.flow.as_bytes());
    }
    if !a.seed.is_empty() {
        // tag 2 (LEN) => 0x12
        out.put_u8(0x12);
        put_varint(a.seed.len() as u64, out)?;
        out.put_slice(&a.seed);
    }
    if !a.extra.is_empty() {
        out.put_slice(&a.extra);
    }
    Ok(())
}

fn decode_addons(mut input: Bytes) -> Result<RequestAddons> {
    let mut addons = RequestAddons::default();
    let mut extra = BytesMut::new();
    while input.has_remaining() {
        let tag = input.get_u8();
        match tag {
            0x0A => {
                let len = read_varint(&mut input)?;
                let bytes = read_n(&mut input, len)?;
                addons.flow = String::from_utf8(bytes)
                    .map_err(|_| Error::decode("vless addons flow not UTF-8"))?;
            }
            0x12 => {
                let len = read_varint(&mut input)?;
                addons.seed = read_n(&mut input, len)?;
            }
            other => {
                // Preserve any unknown tag verbatim (including the tag byte).
                extra.put_u8(other);
                // Best-effort length skip: assume LEN wire-type (0bxxxx_010).
                if other & 0x07 == 0x02 {
                    let len = read_varint(&mut input)?;
                    // We re-emit the length as a varint into `extra` for byte-for-byte round-trip.
                    put_varint(len as u64, &mut extra)?;
                    let bytes = read_n(&mut input, len)?;
                    extra.put_slice(&bytes);
                } else {
                    return Err(Error::decode(format!(
                        "unsupported vless addons wire-type for tag {other:#x}",
                    )));
                }
            }
        }
    }
    addons.extra = extra.to_vec();
    Ok(addons)
}

fn put_varint(mut value: u64, out: &mut BytesMut) -> Result<()> {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
            out.put_u8(b);
        } else {
            out.put_u8(b);
            return Ok(());
        }
    }
}

fn read_varint(input: &mut Bytes) -> Result<usize> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        if !input.has_remaining() {
            return Err(Error::decode("vless varint truncated"));
        }
        let b = input.get_u8();
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(value as usize);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::decode("vless varint too long"));
        }
    }
}

fn read_n(input: &mut Bytes, n: usize) -> Result<Vec<u8>> {
    if input.remaining() < n {
        return Err(Error::decode("vless varint payload truncated"));
    }
    Ok(input.split_to(n).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::address::Address;
    use std::net::Ipv4Addr;

    fn sample_uuid() -> Uuid {
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap()
    }

    #[test]
    fn round_trip_tcp_ipv4_plain() {
        let req = Request {
            uuid: sample_uuid(),
            addons: RequestAddons::empty(),
            command: Command::Tcp,
            destination: Address::v4(Ipv4Addr::new(1, 2, 3, 4), 443),
        };
        let mut buf = BytesMut::new();
        encode_request(&req, &mut buf).unwrap();
        let (decoded, rest) = decode_request(buf.freeze()).unwrap();
        assert_eq!(decoded, req);
        assert!(rest.is_empty());
    }

    #[test]
    fn round_trip_tcp_domain_vision() {
        let req = Request {
            uuid: sample_uuid(),
            addons: RequestAddons::with_flow("xtls-rprx-vision"),
            command: Command::Tcp,
            destination: Address::domain("example.com", 443),
        };
        let mut buf = BytesMut::new();
        encode_request(&req, &mut buf).unwrap();
        let (decoded, _) = decode_request(buf.freeze()).unwrap();
        assert_eq!(decoded.addons.flow, "xtls-rprx-vision");
        assert_eq!(decoded.destination.host_string(), "example.com");
    }

    #[test]
    fn round_trip_udp_ipv6() {
        let req = Request {
            uuid: sample_uuid(),
            addons: RequestAddons::empty(),
            command: Command::Udp,
            destination: Address::v6("2001:db8::1".parse().unwrap(), 5353),
        };
        let mut buf = BytesMut::new();
        encode_request(&req, &mut buf).unwrap();
        let (decoded, _) = decode_request(buf.freeze()).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn truncated_request_rejected() {
        let bad = Bytes::from_static(&[0u8; 4]);
        assert!(decode_request(bad).is_err());
    }

    #[test]
    fn response_round_trip() {
        let mut buf = BytesMut::new();
        let r = Response {
            addons: vec![1, 2, 3],
        };
        encode_response(&r, &mut buf);
        let parsed = parse_response_header(&buf).unwrap().unwrap();
        assert_eq!(parsed.0, r);
        assert_eq!(parsed.1, buf.len());
    }

    #[test]
    fn response_incomplete_returns_none() {
        let half = [0u8, 4u8, 1u8];
        assert!(parse_response_header(&half).unwrap().is_none());
    }
}
