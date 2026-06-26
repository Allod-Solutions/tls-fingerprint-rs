// Passive TLS client fingerprinting from raw ClientHello bytes.
//
// All functions accept a raw TLS record starting at the ContentType byte
// (0x16 for handshake). Returns None / empty fields when the input is not
// a valid TLS ClientHello.

mod ja3;
mod mercury;
mod parse;

/// All passive fingerprints computed from a single ClientHello parse.
pub struct Fingerprints {
    /// JA3 fingerprint: MD5 hex of the bare JA3 string.
    pub ja3: Option<String>,
    /// Mercury fingerprint: SHA-256 hex of the NPF string.
    /// Use [`mercury_npf`] when you need the raw string for database lookup.
    pub mercury: Option<String>,
}

/// Compute all fingerprints from a raw TLS record, parsing the ClientHello once.
pub fn fingerprint(client_hello: &[u8]) -> Fingerprints {
    match parse::parse(client_hello) {
        None => Fingerprints {
            ja3: None,
            mercury: None,
        },
        Some(ch) => Fingerprints {
            ja3: Some(ja3::fingerprint(&ch)),
            mercury: Some(mercury::fingerprint(&ch)),
        },
    }
}

/// Returns the JA3 fingerprint (MD5 hex).
pub fn ja3(client_hello: &[u8]) -> Option<String> {
    parse::parse(client_hello).map(|ch| ja3::fingerprint(&ch))
}

/// Returns the JA3 bare string (before hashing), e.g. `"771,47-53,0-10-11,23-24,0"`.
pub fn ja3_bare(client_hello: &[u8]) -> Option<String> {
    parse::parse(client_hello).map(|ch| ja3::bare(&ch))
}

/// Returns the Mercury NPF string, e.g. `"(0303)(0303)[(c02b)][(0000)(…)]"`.
/// This is the database key used for application identification.
pub fn mercury_npf(client_hello: &[u8]) -> Option<String> {
    parse::parse(client_hello).map(|ch| mercury::npf(&ch))
}

/// Returns the Mercury fingerprint: SHA-256 hex of the NPF string.
pub fn mercury(client_hello: &[u8]) -> Option<String> {
    parse::parse(client_hello).map(|ch| mercury::fingerprint(&ch))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Builds a minimal TLS ClientHello record for testing.
    fn build_client_hello(
        record_ver: u16,
        hello_ver: u16,
        ciphers: &[u16],
        ext_types: &[u16],
        groups: Option<&[u16]>,
        points: Option<&[u8]>,
    ) -> Vec<u8> {
        let put16 = |v: u16| [((v >> 8) as u8), (v as u8)];

        let mut exts = Vec::new();
        for &t in ext_types {
            exts.extend_from_slice(&put16(t));
            exts.extend_from_slice(&put16(0));
        }
        if let Some(gs) = groups {
            let body_len = gs.len() * 2;
            let mut body = Vec::new();
            body.extend_from_slice(&put16(body_len as u16));
            for &g in gs {
                body.extend_from_slice(&put16(g));
            }
            exts.extend_from_slice(&put16(0x000a));
            exts.extend_from_slice(&put16(body.len() as u16));
            exts.extend_from_slice(&body);
        }
        if let Some(ps) = points {
            let mut body = vec![ps.len() as u8];
            body.extend_from_slice(ps);
            exts.extend_from_slice(&put16(0x000b));
            exts.extend_from_slice(&put16(body.len() as u16));
            exts.extend_from_slice(&body);
        }

        let mut ch = Vec::new();
        ch.extend_from_slice(&put16(hello_ver));
        ch.extend_from_slice(&[0u8; 32]);
        ch.push(0);
        ch.extend_from_slice(&put16((ciphers.len() * 2) as u16));
        for &c in ciphers {
            ch.extend_from_slice(&put16(c));
        }
        ch.extend_from_slice(&[1, 0]); // compression: len=1, null

        if !exts.is_empty() {
            ch.extend_from_slice(&put16(exts.len() as u16));
            ch.extend_from_slice(&exts);
        }

        let hs_len = ch.len();
        let mut hs = vec![0x01, (hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8];
        hs.extend_from_slice(&ch);

        let rec_len = hs.len();
        let mut rec = vec![
            0x16,
            (record_ver >> 8) as u8,
            record_ver as u8,
            (rec_len >> 8) as u8,
            rec_len as u8,
        ];
        rec.extend_from_slice(&hs);
        rec
    }

    // Builds a ClientHello with explicit extension type+data pairs.
    fn build_client_hello_with_raw_exts(
        record_ver: u16,
        hello_ver: u16,
        ciphers: &[u16],
        exts: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let put16 = |v: u16| [((v >> 8) as u8), (v as u8)];

        let mut ext_bytes = Vec::new();
        for &(typ, data) in exts {
            ext_bytes.extend_from_slice(&put16(typ));
            ext_bytes.extend_from_slice(&put16(data.len() as u16));
            ext_bytes.extend_from_slice(data);
        }

        let mut ch = Vec::new();
        ch.extend_from_slice(&put16(hello_ver));
        ch.extend_from_slice(&[0u8; 32]);
        ch.push(0);
        ch.extend_from_slice(&put16((ciphers.len() * 2) as u16));
        for &c in ciphers {
            ch.extend_from_slice(&put16(c));
        }
        ch.extend_from_slice(&[1, 0]);
        if !ext_bytes.is_empty() {
            ch.extend_from_slice(&put16(ext_bytes.len() as u16));
            ch.extend_from_slice(&ext_bytes);
        }

        let hs_len = ch.len();
        let mut hs = vec![0x01, (hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8];
        hs.extend_from_slice(&ch);

        let rec_len = hs.len();
        let mut rec = vec![
            0x16,
            (record_ver >> 8) as u8,
            record_ver as u8,
            (rec_len >> 8) as u8,
            rec_len as u8,
        ];
        rec.extend_from_slice(&hs);
        rec
    }

    // ── JA3 ──────────────────────────────────────────────────────────────────────

    #[test]
    fn ja3_bare_full() {
        let buf = build_client_hello(
            0x0301,
            0x0303,
            &[0x002f, 0x0035],
            &[0x0000],
            Some(&[0x0017, 0x0018]),
            Some(&[0x00]),
        );
        assert_eq!(ja3_bare(&buf).as_deref(), Some("771,47-53,0-10-11,23-24,0"));
    }

    #[test]
    fn ja3_bare_no_extensions() {
        let buf = build_client_hello(0x0301, 0x0303, &[0x002f], &[], None, None);
        assert_eq!(ja3_bare(&buf).as_deref(), Some("771,47,,,"));
    }

    #[test]
    fn ja3_bare_groups_no_points() {
        let buf =
            build_client_hello(0x0301, 0x0303, &[0x002f], &[0x0000], Some(&[0x0017]), None);
        assert_eq!(ja3_bare(&buf).as_deref(), Some("771,47,0-10,23,"));
    }

    #[test]
    fn ja3_bare_points_no_groups() {
        let buf =
            build_client_hello(0x0301, 0x0303, &[0x002f], &[0x0000], None, Some(&[0x00]));
        assert_eq!(ja3_bare(&buf).as_deref(), Some("771,47,0-11,,0"));
    }

    #[test]
    fn ja3_grease_filtered() {
        let buf = build_client_hello(
            0x0301,
            0x0303,
            &[0x0a0a, 0x002f, 0x1a1a],
            &[0x2a2a, 0x0000],
            None,
            None,
        );
        assert_eq!(ja3_bare(&buf).as_deref(), Some("771,47,0,,"));
    }

    #[test]
    fn ja3_known_fingerprints() {
        let cases = [
            (
                build_client_hello(
                    0x0301,
                    0x0303,
                    &[0x002f, 0x0035],
                    &[0x0000],
                    Some(&[0x0017, 0x0018]),
                    Some(&[0x00]),
                ),
                "061ee314b448bfff938f848a4ed204c0",
            ),
            (
                build_client_hello(0x0301, 0x0303, &[0x002f], &[], None, None),
                "fde4273625b2ac63bd01d9c500dac91b",
            ),
            (
                build_client_hello(
                    0x0301,
                    0x0303,
                    &[0x0a0a, 0x002f, 0x1a1a],
                    &[0x2a2a, 0x0000],
                    None,
                    None,
                ),
                "6169fabc98e3e6c9690301eaf306d632",
            ),
        ];
        for (buf, want) in &cases {
            assert_eq!(ja3(buf).as_deref(), Some(*want));
        }
    }

    #[test]
    fn ja3_invalid_inputs_return_none() {
        assert!(ja3(&[]).is_none());
        assert!(ja3(b"GET / HTTP/1.1\r\n").is_none());
        assert!(ja3(&[0x16, 0x03, 0x01]).is_none());

        // ServerHello (type 0x02), not ClientHello
        let mut buf = build_client_hello(0x0301, 0x0303, &[0x002f], &[], None, None);
        buf[5] = 0x02;
        assert!(ja3(&buf).is_none());
    }

    #[test]
    fn ja3_distinct_clients() {
        let a = build_client_hello(0x0301, 0x0303, &[0x002f], &[], None, None);
        let b = build_client_hello(0x0301, 0x0303, &[0x0035], &[], None, None);
        assert_ne!(ja3(&a), ja3(&b));
    }

    // ── Mercury ──────────────────────────────────────────────────────────────────

    #[test]
    fn mercury_npf_format() {
        let buf = build_client_hello(
            0x0303,
            0x0303,
            &[0xc02b, 0xc02f, 0x002f, 0x0a0a], // last is GREASE
            &[0x0000, 0x000a, 0xfafa],           // last is GREASE
            None,
            None,
        );
        let npf = mercury_npf(&buf).unwrap();
        assert!(npf.starts_with("(0303)(0303)"));
        assert!(!npf.contains("0a0a"), "GREASE cipher must be filtered");
        assert!(!npf.contains("fafa"), "GREASE extension must be filtered");
    }

    #[test]
    fn mercury_npf_extension_data_included() {
        let sni_data: Vec<u8> = {
            let mut v = vec![0x00, 0x0b, 0x00, 0x00, 0x08];
            v.extend_from_slice(b"test.com");
            v
        };
        let groups_data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x1d, 0x00, 0x17];
        // heartbeat (0x000f) is NOT in INCLUDE_DATA — data must be omitted
        let heartbeat_data: Vec<u8> = vec![0x01];

        let buf = build_client_hello_with_raw_exts(
            0x0303,
            0x0303,
            &[0xc02b],
            &[
                (0x0000, &sni_data),
                (0x000a, &groups_data),
                (0x000f, &heartbeat_data),
            ],
        );
        let npf = mercury_npf(&buf).unwrap();

        let sni_hex = to_hex(&sni_data);
        assert!(npf.contains(&format!("(0000)({sni_hex})")), "npf={npf}");

        let groups_hex = to_hex(&groups_data);
        assert!(npf.contains(&format!("(000a)({groups_hex})")), "npf={npf}");

        assert!(npf.contains("(000f)"), "heartbeat type must appear");
        let hb_hex = to_hex(&heartbeat_data);
        assert!(
            !npf.contains(&format!("(000f)({hb_hex})")),
            "heartbeat data must not be included"
        );
    }

    #[test]
    fn mercury_fingerprint_is_64_char_hex() {
        let buf = build_client_hello(0x0303, 0x0303, &[0xc02b], &[0x0000], None, None);
        let fp = mercury(&buf).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn mercury_distinct_clients() {
        let a = build_client_hello(0x0303, 0x0303, &[0xc02b], &[0x0000], None, None);
        let b = build_client_hello(0x0303, 0x0303, &[0xc02f], &[0x0000], None, None);
        assert_ne!(mercury(&a), mercury(&b));
    }

    // ── fingerprint() ────────────────────────────────────────────────────────────

    #[test]
    fn fingerprint_returns_both() {
        let buf = build_client_hello(0x0303, 0x0303, &[0xc02b], &[0x0000], None, None);
        let fp = fingerprint(&buf);
        assert!(fp.ja3.is_some());
        assert!(fp.mercury.is_some());
    }

    #[test]
    fn fingerprint_invalid_returns_none_fields() {
        let fp = fingerprint(b"not tls");
        assert!(fp.ja3.is_none());
        assert!(fp.mercury.is_none());
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut s, byte| {
            use std::fmt::Write as _;
            write!(s, "{byte:02x}").unwrap();
            s
        })
    }
}
