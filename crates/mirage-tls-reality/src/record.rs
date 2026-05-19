//! TLS 1.3 record layer used by the Reality forged-hello path.
//!
//! After the handshake hands us a pair of `Aead` instances (one for each
//! direction) and per-direction sequence counters, every byte that goes
//! out or comes in is wrapped in a `TLSCiphertext` record:
//!
//! ```text
//!     struct {
//!         ContentType opaque_type = application_data;  /* 23 */
//!         ProtocolVersion legacy_record_version = 0x0303;
//!         uint16 length;
//!         opaque encrypted_record[TLSCiphertext.length];
//!     } TLSCiphertext;
//! ```
//!
//! `encrypted_record` is the AEAD-sealed `TLSInnerPlaintext`:
//!
//! ```text
//!     struct {
//!         opaque content[TLSPlaintext.length];
//!         ContentType type;
//!         uint8 zeros[length_of_padding];
//!     } TLSInnerPlaintext;
//! ```
//!
//! The 5-byte record header is the AAD.
//!
//! This module is **synchronous** byte-pushing logic — no I/O, just
//! "given a plaintext, give me the wire bytes" and the reverse. The
//! async wrapper that drives a real socket lives in `stream.rs`.

use mirage_core::error::{Error, Result};

use crate::aead::{Aead, TAG_LEN};

/// TLS 1.3 record outer content type for application data.
pub const RECORD_APPLICATION_DATA: u8 = 23;
/// TLS 1.3 record outer content type for handshake (only used pre-record-layer).
pub const RECORD_HANDSHAKE: u8 = 22;
/// TLS 1.3 record outer content type for ChangeCipherSpec (legacy compat).
pub const RECORD_CHANGE_CIPHER_SPEC: u8 = 20;
/// TLS 1.3 record outer content type for alerts.
pub const RECORD_ALERT: u8 = 21;

/// Maximum TLS 1.3 plaintext length (RFC 8446 §5.1).
pub const MAX_PLAINTEXT_LEN: usize = 16_384;
/// Maximum TLS 1.3 ciphertext length (plaintext + content-type byte + tag,
/// plus the implementation's padding budget).
pub const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 256;
/// Size of the on-the-wire record header.
pub const RECORD_HEADER_LEN: usize = 5;

/// One direction of the record layer: an AEAD + monotonically-increasing
/// sequence counter.
pub struct RecordCipher {
    aead: Aead,
    seq: u64,
}

impl RecordCipher {
    /// Construct from an AEAD instance. Sequence starts at zero.
    #[must_use]
    pub fn new(aead: Aead) -> Self {
        Self { aead, seq: 0 }
    }

    /// Current sequence number (the next seal/open will use it, then
    /// increment).
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.seq
    }

    /// Encrypt `plaintext` as a TLS 1.3 record of the supplied inner
    /// content type and return the full wire bytes (5-byte header
    /// followed by ciphertext+tag). Increments the sequence counter.
    ///
    /// # Errors
    /// Returns [`Error::Tls`] if the plaintext exceeds
    /// [`MAX_PLAINTEXT_LEN`].
    pub fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::tls(format!(
                "record: plaintext too long ({} > {MAX_PLAINTEXT_LEN})",
                plaintext.len()
            )));
        }
        // TLSInnerPlaintext = content || type || padding (no padding here).
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(inner_type);

        // Header. The length is the post-AEAD length: inner + tag.
        let cipher_len = inner.len() + TAG_LEN;
        let len_u16 = u16::try_from(cipher_len)
            .map_err(|_| Error::tls(format!("record: ciphertext length overflow {cipher_len}")))?;
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = RECORD_APPLICATION_DATA;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&len_u16.to_be_bytes());

        let sealed = self.aead.seal(self.seq, &header, &inner)?;
        self.seq = self.seq.wrapping_add(1);

        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt the body of a TLS 1.3 record into `(inner_type, payload)`.
    /// `header` is the 5-byte record header and `ciphertext_and_tag` is
    /// everything after it. Increments the sequence counter on success.
    ///
    /// # Errors
    /// Returns [`Error::AuthFailed`] on AEAD tag mismatch and
    /// [`Error::Tls`] for malformed inner plaintext (no content-type byte
    /// after stripping padding).
    pub fn open(&mut self, header: [u8; RECORD_HEADER_LEN], body: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut inner = self.aead.open(self.seq, &header, body)?;
        self.seq = self.seq.wrapping_add(1);
        // Strip trailing zero padding (RFC 8446 §5.4 — TLSInnerPlaintext
        // has zero or more padding bytes; the *last* non-zero byte is the
        // real content type).
        while let Some(&0) = inner.last() {
            inner.pop();
        }
        let Some(inner_type) = inner.pop() else {
            return Err(Error::tls("record: empty inner plaintext"));
        };
        Ok((inner_type, inner))
    }
}

/// Parse a 5-byte TLS record header.
///
/// # Errors
/// Returns [`Error::Tls`] if `header` is shorter than 5 bytes.
pub fn parse_record_header(header: &[u8]) -> Result<RecordHeader> {
    if header.len() < RECORD_HEADER_LEN {
        return Err(Error::tls("record: header too short"));
    }
    Ok(RecordHeader {
        outer_type: header[0],
        legacy_version: u16::from_be_bytes([header[1], header[2]]),
        length: u16::from_be_bytes([header[3], header[4]]),
    })
}

/// Decoded record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Outer record content type (e.g. 23 for application_data).
    pub outer_type: u8,
    /// Legacy protocol version (always 0x0303 in TLS 1.3 records).
    pub legacy_version: u16,
    /// Payload length following the header.
    pub length: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{Aead, AeadKind};

    fn pair() -> (RecordCipher, RecordCipher) {
        let key = [0x77u8; 16];
        let iv = [0x88u8; 12];
        let writer_aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        let reader_aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        (
            RecordCipher::new(writer_aead),
            RecordCipher::new(reader_aead),
        )
    }

    #[test]
    fn seal_then_open_application_data_round_trips() {
        let (mut w, mut r) = pair();
        let wire = w.seal(RECORD_APPLICATION_DATA, b"hello reality").unwrap();
        let hdr = parse_record_header(&wire[..5]).unwrap();
        assert_eq!(hdr.outer_type, RECORD_APPLICATION_DATA);
        assert_eq!(hdr.legacy_version, 0x0303);
        assert_eq!(usize::from(hdr.length), wire.len() - 5);

        let mut header_buf = [0u8; 5];
        header_buf.copy_from_slice(&wire[..5]);
        let (inner_type, plaintext) = r.open(header_buf, &wire[5..]).unwrap();
        assert_eq!(inner_type, RECORD_APPLICATION_DATA);
        assert_eq!(plaintext, b"hello reality");
    }

    #[test]
    fn seal_advances_sequence_per_record() {
        let (mut w, _) = pair();
        assert_eq!(w.sequence(), 0);
        let _ = w.seal(RECORD_APPLICATION_DATA, b"a").unwrap();
        assert_eq!(w.sequence(), 1);
        let _ = w.seal(RECORD_APPLICATION_DATA, b"b").unwrap();
        assert_eq!(w.sequence(), 2);
    }

    #[test]
    fn open_with_padding_strips_trailing_zeros() {
        // Hand-craft a sealed record with synthetic padding so we exercise
        // the padding-stripping branch independently from the encoder.
        let key = [0x12u8; 16];
        let iv = [0x34u8; 12];
        let aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();

        // Inner = "payload" || type || 16 zero pad bytes.
        let mut inner = Vec::from(*b"payload");
        inner.push(RECORD_APPLICATION_DATA);
        inner.extend(std::iter::repeat(0).take(16));

        // Build header with the post-AEAD length.
        let cipher_len = inner.len() + TAG_LEN;
        let len = u16::try_from(cipher_len).unwrap();
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = RECORD_APPLICATION_DATA;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&len.to_be_bytes());

        let sealed = aead.seal(0, &header, &inner).unwrap();

        let reader_aead = Aead::new(AeadKind::Aes128Gcm, &key, &iv).unwrap();
        let mut r = RecordCipher::new(reader_aead);
        let (inner_type, plaintext) = r.open(header, &sealed).unwrap();
        assert_eq!(inner_type, RECORD_APPLICATION_DATA);
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn parse_record_header_rejects_short_input() {
        assert!(parse_record_header(&[0x17, 0x03]).is_err());
    }

    #[test]
    fn parse_record_header_reads_length_big_endian() {
        let hdr = parse_record_header(&[0x17, 0x03, 0x03, 0x01, 0x23]).unwrap();
        assert_eq!(hdr.outer_type, 0x17);
        assert_eq!(hdr.legacy_version, 0x0303);
        assert_eq!(hdr.length, 0x0123);
    }

    #[test]
    fn seal_rejects_overlong_plaintext() {
        let (mut w, _) = pair();
        let huge = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert!(w.seal(RECORD_APPLICATION_DATA, &huge).is_err());
    }
}
