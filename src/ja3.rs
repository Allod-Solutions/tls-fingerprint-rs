use crate::parse::ParsedClientHello;
use std::fmt::Write as _;

/// Returns the JA3 bare string (before hashing).
/// Format: `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// where each list is dash-separated decimal values.
pub(crate) fn bare(ch: &ParsedClientHello) -> String {
    let mut s = String::new();
    write!(s, "{}", ch.hello_version).unwrap();
    s.push(',');
    append_u16_list(&mut s, &ch.ciphers);
    s.push(',');
    append_u16_list(&mut s, &ch.extensions.iter().map(|e| e.typ).collect::<Vec<_>>());
    s.push(',');
    append_u16_list(&mut s, &ch.groups);
    s.push(',');
    append_u8_list(&mut s, &ch.points);
    s
}

/// Returns the JA3 fingerprint: MD5 hex of the bare string.
pub(crate) fn fingerprint(ch: &ParsedClientHello) -> String {
    let b = bare(ch);
    format!("{:x}", md5::compute(b.as_bytes()))
}

fn append_u16_list(s: &mut String, vals: &[u16]) {
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        write!(s, "{v}").unwrap();
    }
}

fn append_u8_list(s: &mut String, vals: &[u8]) {
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        write!(s, "{v}").unwrap();
    }
}
