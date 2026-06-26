use crate::parse::ParsedClientHello;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

// Extension types whose raw data is included in the NPF string.
// All others appear only as their 4-char hex type code.
const INCLUDE_DATA: &[u16] = &[
    0x0000, // server_name
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x000d, // signature_algorithms
    0x0010, // ALPN
    0x001b, // compress_certificate
    0x002b, // supported_versions
    0x002d, // psk_key_exchange_modes
    0x0033, // key_share
    0x0012, // signed_certificate_timestamp
    0x0015, // padding
];

/// Returns the Mercury NPF string for this ClientHello.
/// Format: `(recordVer)(helloVer)[(cs1)(cs2)...][(ext_type)(ext_data)...]`
/// Use this string as a database key for application identification.
pub(crate) fn npf(ch: &ParsedClientHello) -> String {
    let mut s = String::new();
    write!(s, "({:04x})({:04x})", ch.record_version, ch.hello_version).unwrap();
    s.push('[');
    for cs in &ch.ciphers {
        write!(s, "({cs:04x})").unwrap();
    }
    s.push(']');
    s.push('[');
    for ext in &ch.extensions {
        write!(s, "({:04x})", ext.typ).unwrap();
        if INCLUDE_DATA.contains(&ext.typ) && !ext.data.is_empty() {
            s.push('(');
            for b in &ext.data {
                write!(s, "{b:02x}").unwrap();
            }
            s.push(')');
        }
    }
    s.push(']');
    s
}

/// Returns the Mercury fingerprint: SHA-256 hex of the NPF string.
pub(crate) fn fingerprint(ch: &ParsedClientHello) -> String {
    let raw = npf(ch);
    let hash = Sha256::digest(raw.as_bytes());
    hash.iter().fold(String::with_capacity(64), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}
