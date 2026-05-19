//! Per-browser ClientHello fingerprint profiles.
//!
//! The whole point of Reality / uTLS is to make our ClientHello byte-for-byte
//! match what some real, ubiquitous browser would send so that a DPI box
//! can't single us out via JA3 or JA4 hashes. Every profile here therefore
//! captures four orthogonal facets that together determine the JA3:
//!
//! 1. **Cipher suites** — exact list and exact order.
//! 2. **Extensions** — list, order, and per-extension payload.
//! 3. **Supported groups** — exact list and exact order.
//! 4. **Signature algorithms** — exact list and exact order.
//!
//! The values here come from sniffing live Chrome 120, Firefox 120, Safari
//! 17, and iOS 17 sessions against `tls.peet.ws`. They are intentionally
//! verbatim; do not "improve" the order. The fingerprint is the asset.

/// Supported browser fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome 120 on Windows (the most common JA3 on the open Internet).
    Chrome120,
    /// Firefox 120 on Windows.
    Firefox120,
    /// Safari 17 on macOS Sonoma.
    Safari17,
    /// iOS 17 Safari (mobile Safari).
    Ios17,
    /// Edge 120 on Windows (similar to Chrome but distinct enough to want
    /// its own profile).
    Edge120,
}

impl Fingerprint {
    /// Parse the user-facing string from `[outbound.reality].fingerprint`.
    /// Falls back to [`Fingerprint::Chrome120`] for unknown strings, with
    /// an info-level log emitted by the caller.
    #[must_use]
    pub fn from_str_or_chrome(s: &str) -> Self {
        // The wildcard arm intentionally maps to Chrome 120 (the safest
        // default on the open Internet). It collapses with the
        // "chrome"/"chrome120" cases in body, but we keep both arms so
        // the explicit listing remains discoverable in `as_str` output.
        match s.to_ascii_lowercase().as_str() {
            "firefox" | "firefox120" | "firefox-120" => Self::Firefox120,
            "safari" | "safari17" | "safari-17" => Self::Safari17,
            "ios" | "ios17" | "ios-17" => Self::Ios17,
            "edge" | "edge120" | "edge-120" => Self::Edge120,
            _ => Self::Chrome120,
        }
    }

    /// User-facing name for diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chrome120 => "chrome-120",
            Self::Firefox120 => "firefox-120",
            Self::Safari17 => "safari-17",
            Self::Ios17 => "ios-17",
            Self::Edge120 => "edge-120",
        }
    }
}

/// One of the 16 GREASE values defined in RFC 8701 §3.
///
/// GREASE values are 16-bit code points of the form `0xJaJa` (so the high
/// and low nibbles match). A given ClientHello picks any one of these and
/// sprinkles it into the cipher-suite list, the extensions list, the
/// supported-groups list, etc. — the purpose is to force middle-boxes to
/// tolerate unknown values, so the choice is essentially random.
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Pick a GREASE value indexed by `seed`. Callers pass a small seed (e.g.
/// the low byte of the client-random) so a given ClientHello picks one
/// consistent value across all the places it needs to appear, but two
/// successive ClientHellos pick different values.
#[must_use]
pub fn grease_for(seed: u8) -> u16 {
    GREASE_VALUES[usize::from(seed) % GREASE_VALUES.len()]
}

/// TLS 1.3 cipher suite numbers used in this crate.
pub mod cipher {
    /// `TLS_AES_128_GCM_SHA256`.
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    /// `TLS_AES_256_GCM_SHA384`.
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
}

/// Named groups recognised by the supported_groups extension.
pub mod group {
    /// X25519 (RFC 7748).
    pub const X25519: u16 = 0x001d;
    /// secp256r1 / P-256.
    pub const SECP256R1: u16 = 0x0017;
    /// secp384r1 / P-384.
    pub const SECP384R1: u16 = 0x0018;
}

/// Signature algorithm values used in the signature_algorithms extension.
pub mod sig {
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
}

/// Extension type values used in the extensions field.
pub mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 0x0010;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub const APPLICATION_SETTINGS: u16 = 0x4469;
    pub const PADDING: u16 = 0x0015;
}

/// A complete fingerprint profile resolved to the raw values that go on
/// the wire.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Cipher suite ordering (excluding the GREASE prefix, which is
    /// injected at build time so it can vary per-handshake).
    pub cipher_suites: Vec<u16>,
    /// Supported groups, in order. The first group is the one we generate
    /// a key_share for (X25519 in every current profile).
    pub supported_groups: Vec<u16>,
    /// Signature algorithms, in order.
    pub signature_algorithms: Vec<u16>,
    /// Extension types, in order. The builder uses this slice to emit
    /// extensions in the exact order the browser does.
    pub extension_order: Vec<u16>,
    /// ALPN protocols, in order of preference.
    pub alpn: Vec<&'static str>,
    /// Whether the application_settings extension is sent. Chrome sends
    /// it (`APLN` mirror); Firefox/Safari don't.
    pub send_application_settings: bool,
    /// Whether a 1-byte EC point format extension (uncompressed only,
    /// `0x00`) is sent. Chrome / Firefox do; some other clients don't.
    pub send_ec_point_formats: bool,
    /// Optional padding-extension target length (RFC 7685). When set, the
    /// builder pads the ClientHello so the on-the-wire record reaches
    /// `target` bytes.
    pub padding_target: Option<usize>,
}

impl Profile {
    /// Resolve a [`Fingerprint`] to a concrete [`Profile`].
    #[must_use]
    pub fn for_fingerprint(fp: Fingerprint) -> Self {
        match fp {
            Fingerprint::Chrome120 | Fingerprint::Edge120 => chrome_120(),
            Fingerprint::Firefox120 => firefox_120(),
            Fingerprint::Safari17 => safari_17(),
            Fingerprint::Ios17 => ios_17(),
        }
    }
}

fn chrome_120() -> Profile {
    Profile {
        cipher_suites: vec![
            cipher::TLS_AES_128_GCM_SHA256,
            cipher::TLS_AES_256_GCM_SHA384,
            cipher::TLS_CHACHA20_POLY1305_SHA256,
            // Legacy compatibility ciphers Chrome still advertises so a
            // TLS 1.2 server has something to pick. We never negotiate
            // these because supported_versions caps us at TLS 1.3.
            0xc02b,
            0xc02f,
            0xc02c,
            0xc030,
            0xcca9,
            0xcca8,
            0xc013,
            0xc014,
            0x009c,
            0x009d,
            0x002f,
            0x0035,
        ],
        supported_groups: vec![group::X25519, group::SECP256R1, group::SECP384R1],
        signature_algorithms: vec![
            sig::ECDSA_SECP256R1_SHA256,
            sig::RSA_PSS_RSAE_SHA256,
            sig::RSA_PKCS1_SHA256,
            sig::ECDSA_SECP384R1_SHA384,
            sig::RSA_PSS_RSAE_SHA384,
            sig::RSA_PKCS1_SHA384,
            sig::RSA_PSS_RSAE_SHA512,
            sig::RSA_PKCS1_SHA512,
        ],
        extension_order: vec![
            ext::SERVER_NAME,
            ext::EXTENDED_MASTER_SECRET,
            ext::RENEGOTIATION_INFO,
            ext::SUPPORTED_GROUPS,
            ext::EC_POINT_FORMATS,
            ext::SESSION_TICKET,
            ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            ext::STATUS_REQUEST,
            ext::SIGNATURE_ALGORITHMS,
            ext::SIGNED_CERTIFICATE_TIMESTAMP,
            ext::KEY_SHARE,
            ext::PSK_KEY_EXCHANGE_MODES,
            ext::SUPPORTED_VERSIONS,
            ext::COMPRESS_CERTIFICATE,
            ext::APPLICATION_SETTINGS,
        ],
        alpn: vec!["h2", "http/1.1"],
        send_application_settings: true,
        send_ec_point_formats: true,
        // Chrome pads its ClientHellos to land in [512, 517] bytes. The
        // builder will refine the actual padding length once it knows the
        // post-extension length.
        padding_target: Some(517),
    }
}

fn firefox_120() -> Profile {
    Profile {
        cipher_suites: vec![
            cipher::TLS_AES_128_GCM_SHA256,
            cipher::TLS_CHACHA20_POLY1305_SHA256,
            cipher::TLS_AES_256_GCM_SHA384,
            0xc02b,
            0xc02f,
            0xcca9,
            0xcca8,
            0xc02c,
            0xc030,
            0xc00a,
            0xc009,
            0xc013,
            0xc014,
            0x009c,
            0x009d,
            0x002f,
            0x0035,
        ],
        supported_groups: vec![
            group::X25519,
            group::SECP256R1,
            group::SECP384R1,
            // Firefox additionally advertises secp521r1 and ffdhe2048.
            0x0019,
            0x0100,
        ],
        signature_algorithms: vec![
            sig::ECDSA_SECP256R1_SHA256,
            sig::ECDSA_SECP384R1_SHA384,
            0x0807, // ed25519
            sig::RSA_PSS_RSAE_SHA256,
            sig::RSA_PSS_RSAE_SHA384,
            sig::RSA_PSS_RSAE_SHA512,
            sig::RSA_PKCS1_SHA256,
            sig::RSA_PKCS1_SHA384,
            sig::RSA_PKCS1_SHA512,
        ],
        extension_order: vec![
            ext::SERVER_NAME,
            ext::EXTENDED_MASTER_SECRET,
            ext::RENEGOTIATION_INFO,
            ext::SUPPORTED_GROUPS,
            ext::EC_POINT_FORMATS,
            ext::SESSION_TICKET,
            ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            ext::STATUS_REQUEST,
            ext::SIGNATURE_ALGORITHMS,
            ext::SIGNED_CERTIFICATE_TIMESTAMP,
            ext::KEY_SHARE,
            ext::PSK_KEY_EXCHANGE_MODES,
            ext::SUPPORTED_VERSIONS,
        ],
        alpn: vec!["h2", "http/1.1"],
        send_application_settings: false,
        send_ec_point_formats: true,
        padding_target: Some(517),
    }
}

fn safari_17() -> Profile {
    Profile {
        cipher_suites: vec![
            cipher::TLS_AES_128_GCM_SHA256,
            cipher::TLS_AES_256_GCM_SHA384,
            cipher::TLS_CHACHA20_POLY1305_SHA256,
            0xc02c,
            0xc02b,
            0xcca9,
            0xc030,
            0xc02f,
            0xcca8,
            0xc024,
            0xc023,
            0xc028,
            0xc027,
            0xc00a,
            0xc009,
            0xc014,
            0xc013,
            0x009d,
            0x009c,
            0x003d,
            0x003c,
            0x0035,
            0x002f,
        ],
        supported_groups: vec![
            group::X25519,
            group::SECP256R1,
            group::SECP384R1,
            0x0019, // secp521r1
        ],
        signature_algorithms: vec![
            sig::ECDSA_SECP256R1_SHA256,
            sig::RSA_PSS_RSAE_SHA256,
            sig::RSA_PKCS1_SHA256,
            sig::ECDSA_SECP384R1_SHA384,
            0x0303, // ecdsa_sha384 (legacy)
            sig::RSA_PSS_RSAE_SHA384,
            sig::RSA_PKCS1_SHA384,
            sig::RSA_PSS_RSAE_SHA512,
            sig::RSA_PKCS1_SHA512,
            0x0203, // ecdsa_sha1 (legacy)
            0x0201, // rsa_pkcs1_sha1 (legacy)
        ],
        extension_order: vec![
            ext::SERVER_NAME,
            ext::EXTENDED_MASTER_SECRET,
            ext::RENEGOTIATION_INFO,
            ext::SUPPORTED_GROUPS,
            ext::EC_POINT_FORMATS,
            ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            ext::STATUS_REQUEST,
            ext::SIGNATURE_ALGORITHMS,
            ext::SIGNED_CERTIFICATE_TIMESTAMP,
            ext::KEY_SHARE,
            ext::PSK_KEY_EXCHANGE_MODES,
            ext::SUPPORTED_VERSIONS,
        ],
        alpn: vec!["h2", "http/1.1"],
        send_application_settings: false,
        send_ec_point_formats: true,
        padding_target: None,
    }
}

fn ios_17() -> Profile {
    // iOS Safari is close to macOS Safari but reorders a few extensions.
    let mut p = safari_17();
    p.extension_order = vec![
        ext::SERVER_NAME,
        ext::EXTENDED_MASTER_SECRET,
        ext::RENEGOTIATION_INFO,
        ext::SUPPORTED_GROUPS,
        ext::EC_POINT_FORMATS,
        ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ext::STATUS_REQUEST,
        ext::SIGNATURE_ALGORITHMS,
        ext::SIGNED_CERTIFICATE_TIMESTAMP,
        ext::KEY_SHARE,
        ext::SUPPORTED_VERSIONS,
        ext::PSK_KEY_EXCHANGE_MODES,
    ];
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_string_parsing_is_case_insensitive() {
        assert_eq!(
            Fingerprint::from_str_or_chrome("Chrome120"),
            Fingerprint::Chrome120
        );
        assert_eq!(
            Fingerprint::from_str_or_chrome("FIREFOX"),
            Fingerprint::Firefox120
        );
        assert_eq!(
            Fingerprint::from_str_or_chrome("safari-17"),
            Fingerprint::Safari17
        );
        // Unknown string falls back to Chrome 120, which is the safest
        // default on the open Internet.
        assert_eq!(
            Fingerprint::from_str_or_chrome("brave-99"),
            Fingerprint::Chrome120
        );
    }

    #[test]
    fn chrome_profile_starts_with_x25519() {
        let p = Profile::for_fingerprint(Fingerprint::Chrome120);
        assert_eq!(p.supported_groups[0], group::X25519);
    }

    #[test]
    fn chrome_profile_advertises_tls13_aeads() {
        let p = Profile::for_fingerprint(Fingerprint::Chrome120);
        assert!(p.cipher_suites.contains(&cipher::TLS_AES_128_GCM_SHA256));
        assert!(p
            .cipher_suites
            .contains(&cipher::TLS_CHACHA20_POLY1305_SHA256));
    }

    #[test]
    fn grease_index_wraps() {
        // Same `seed % 16` maps to the same value.
        assert_eq!(grease_for(0), grease_for(16));
        assert_eq!(grease_for(7), grease_for(23));
        // And every 16 distinct seeds touch every value at least once.
        let mut seen: std::collections::HashSet<u16> = (0..16).map(grease_for).collect();
        assert_eq!(seen.len(), 16);
        for v in &GREASE_VALUES {
            assert!(seen.remove(v));
        }
    }
}
