//! Low-level TLS wire-format helpers.
//!
//! TLS 1.3 messages are length-prefixed nested byte vectors. RFC 8446 calls
//! them `<min..max>` variable-length vectors and they appear at every depth:
//! a [`ClientHello`](super::hello::ClientHello) contains a list of
//! extensions, each extension carries a `u16`-length payload, the payload
//! may itself contain a `u8`- or `u16`-length list, and so on.
//!
//! Rather than spreading hand-rolled `extend_from_slice + put_u16_be` blocks
//! across every builder, we collect them here as one small reader / writer
//! pair. The writer's [`with_u16_len`](TlsWriter::with_u16_len) and friends
//! handle the bookkeeping of "reserve a length placeholder, run the closure,
//! patch the length in afterwards" so the call sites read top-down like the
//! actual TLS message structure.
//!
//! Forbidding `unsafe_code` is inherited from the crate root.

use std::io;

/// Minimal byte writer with length-prefixed scopes. Bytes are written
/// big-endian (network order) — TLS, like virtually every IETF protocol,
/// uses big-endian on the wire.
#[derive(Debug, Default)]
pub struct TlsWriter {
    buf: Vec<u8>,
}

impl TlsWriter {
    /// Build a writer with an initial capacity hint.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Append a single byte.
    pub fn push_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Append a big-endian `u16`.
    pub fn push_u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian 24-bit length (TLS uses these for handshake
    /// message body lengths and a few certificate-chain fields).
    pub fn push_u24(&mut self, value: u32) {
        let bytes = value.to_be_bytes();
        self.buf.extend_from_slice(&bytes[1..4]);
    }

    /// Append `data` verbatim.
    pub fn push_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Reserve a `u8` length placeholder, run `f`, then patch the placeholder
    /// with the actual number of bytes written.
    pub fn with_u8_len<F: FnOnce(&mut Self)>(&mut self, f: F) {
        let start = self.buf.len();
        self.buf.push(0);
        f(self);
        let len = self.buf.len() - start - 1;
        debug_assert!(u8::try_from(len).is_ok(), "u8 length overflow ({len})");
        self.buf[start] = u8::try_from(len).unwrap_or(u8::MAX);
    }

    /// Reserve a `u16` length placeholder, run `f`, then patch the placeholder
    /// with the actual number of bytes written.
    pub fn with_u16_len<F: FnOnce(&mut Self)>(&mut self, f: F) {
        let start = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        f(self);
        let len = self.buf.len() - start - 2;
        debug_assert!(u16::try_from(len).is_ok(), "u16 length overflow ({len})");
        let len = u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
        self.buf[start] = len[0];
        self.buf[start + 1] = len[1];
    }

    /// Reserve a 24-bit length placeholder, run `f`, then patch the
    /// placeholder with the actual number of bytes written. Used for the
    /// outer handshake-message body length and for certificate-chain
    /// vectors.
    pub fn with_u24_len<F: FnOnce(&mut Self)>(&mut self, f: F) {
        let start = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0]);
        f(self);
        let len = self.buf.len() - start - 3;
        debug_assert!(len <= 0x00FF_FFFF, "u24 length overflow ({len})");
        let n = u32::try_from(len).unwrap_or(0x00FF_FFFF);
        let n = n & 0x00FF_FFFF;
        let bytes = n.to_be_bytes();
        self.buf[start] = bytes[1];
        self.buf[start + 1] = bytes[2];
        self.buf[start + 2] = bytes[3];
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` iff nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume the writer and return the underlying buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the underlying buffer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Cursor-style byte reader for parsing TLS messages.
///
/// Every read method advances the internal cursor and returns
/// `Err(io::ErrorKind::UnexpectedEof)` when the buffer is too short. This
/// keeps the parsers free of explicit bounds-checking everywhere and gives
/// us one clean place to wrap errors.
#[derive(Debug)]
pub struct TlsReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    /// Wrap `buf` for reading. The cursor starts at zero.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Remaining bytes in the buffer.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current cursor position.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Returns `true` iff the cursor is at end-of-buffer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read a single byte.
    ///
    /// # Errors
    /// `UnexpectedEof` when fewer than 1 byte remain.
    pub fn read_u8(&mut self) -> io::Result<u8> {
        if self.remaining() < 1 {
            return Err(short_read("u8"));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a big-endian `u16`.
    ///
    /// # Errors
    /// `UnexpectedEof` when fewer than 2 bytes remain.
    pub fn read_u16(&mut self) -> io::Result<u16> {
        if self.remaining() < 2 {
            return Err(short_read("u16"));
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a big-endian 24-bit length (returned as `u32` since `u24`
    /// doesn't exist).
    ///
    /// # Errors
    /// `UnexpectedEof` when fewer than 3 bytes remain.
    pub fn read_u24(&mut self) -> io::Result<u32> {
        if self.remaining() < 3 {
            return Err(short_read("u24"));
        }
        let v = (u32::from(self.buf[self.pos]) << 16)
            | (u32::from(self.buf[self.pos + 1]) << 8)
            | u32::from(self.buf[self.pos + 2]);
        self.pos += 3;
        Ok(v)
    }

    /// Read exactly `n` bytes.
    ///
    /// # Errors
    /// `UnexpectedEof` when fewer than `n` bytes remain.
    pub fn read_bytes(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(short_read("bytes"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a `u8`-length prefixed slice.
    ///
    /// # Errors
    /// Propagates short-read errors from the length and from the slice body.
    pub fn read_u8_prefixed(&mut self) -> io::Result<&'a [u8]> {
        let n = self.read_u8()? as usize;
        self.read_bytes(n)
    }

    /// Read a `u16`-length prefixed slice.
    ///
    /// # Errors
    /// Propagates short-read errors from the length and from the slice body.
    pub fn read_u16_prefixed(&mut self) -> io::Result<&'a [u8]> {
        let n = self.read_u16()? as usize;
        self.read_bytes(n)
    }

    /// Read a 24-bit length prefixed slice.
    ///
    /// # Errors
    /// Propagates short-read errors from the length and from the slice body.
    pub fn read_u24_prefixed(&mut self) -> io::Result<&'a [u8]> {
        let n = self.read_u24()? as usize;
        self.read_bytes(n)
    }
}

fn short_read(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("tls wire: short read for {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_u16_scope() {
        let mut w = TlsWriter::with_capacity(0);
        w.push_u8(0xAA);
        w.with_u16_len(|w| {
            w.push_bytes(&[1, 2, 3, 4]);
        });
        w.push_u8(0xBB);

        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAA, 0x00, 0x04, 1, 2, 3, 4, 0xBB]);

        let mut r = TlsReader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0xAA);
        let inner = r.read_u16_prefixed().unwrap();
        assert_eq!(inner, &[1, 2, 3, 4]);
        assert_eq!(r.read_u8().unwrap(), 0xBB);
        assert!(r.is_empty());
    }

    #[test]
    fn nested_lengths_patch_correctly() {
        let mut w = TlsWriter::default();
        w.with_u24_len(|outer| {
            outer.push_u8(0x11);
            outer.with_u16_len(|mid| {
                mid.with_u8_len(|inner| {
                    inner.push_bytes(b"hi");
                });
            });
            outer.push_u8(0x22);
        });
        // outer body: 0x11 [u16 len = 3 ] [u8 len=2 'h' 'i'] 0x22 = 7 bytes
        let bytes = w.into_bytes();
        assert_eq!(
            bytes,
            vec![0x00, 0x00, 0x07, 0x11, 0x00, 0x03, 0x02, b'h', b'i', 0x22]
        );
    }

    #[test]
    fn reader_reports_short_read() {
        let bytes = [0u8; 1];
        let mut r = TlsReader::new(&bytes);
        assert!(r.read_u16().is_err());
    }

    #[test]
    fn u24_round_trips() {
        let mut w = TlsWriter::default();
        w.push_u24(0x0012_3456);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56]);
        let mut r = TlsReader::new(&bytes);
        assert_eq!(r.read_u24().unwrap(), 0x0012_3456);
    }
}
