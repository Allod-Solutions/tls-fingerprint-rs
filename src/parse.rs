// Shared TLS ClientHello parser used by all fingerprint algorithms.

pub(crate) struct ParsedClientHello {
    pub record_version: u16,
    pub hello_version: u16,
    pub ciphers: Vec<u16>,
    /// All non-GREASE extensions, in order, with raw data.
    pub extensions: Vec<Extension>,
    /// Decoded supported_groups (extension 0x000a), GREASE filtered.
    pub groups: Vec<u16>,
    /// Decoded ec_point_formats (extension 0x000b).
    pub points: Vec<u8>,
}

pub(crate) struct Extension {
    pub typ: u16,
    pub data: Vec<u8>,
}

/// Returns true for GREASE values (RFC 8701): 0xXAXA pattern.
#[inline]
pub(crate) fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

pub(crate) fn parse(buf: &[u8]) -> Option<ParsedClientHello> {
    // TLS record header: ContentType(1) + Version(2) + Length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let record_version = u16::from_be_bytes([buf[1], buf[2]]);
    let rec_len = (u16::from_be_bytes([buf[3], buf[4]]) as usize).min(buf.len() - 5);
    let mut data = &buf[5..5 + rec_len];

    // Handshake header: Type(1) + Length(3)
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    data = &data[4..];

    // ClientHello: Version(2) + Random(32)
    if data.len() < 34 {
        return None;
    }
    let hello_version = u16::from_be_bytes([data[0], data[1]]);
    data = &data[34..];

    // SessionID: Length(1) + ID
    if data.is_empty() {
        return None;
    }
    let sid_len = data[0] as usize;
    data = &data[1..];
    if data.len() < sid_len {
        return None;
    }
    data = &data[sid_len..];

    // CipherSuites: Length(2) + suites
    if data.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    data = &data[2..];
    if data.len() < cs_len || cs_len % 2 != 0 {
        return None;
    }
    let ciphers = data[..cs_len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&v| !is_grease(v))
        .collect();
    data = &data[cs_len..];

    // CompressionMethods: Length(1) + methods
    if data.is_empty() {
        return None;
    }
    let cm_len = data[0] as usize;
    data = &data[1..];
    if data.len() < cm_len {
        return None;
    }
    data = &data[cm_len..];

    // Extensions block (optional)
    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut points = Vec::new();

    if data.len() >= 2 {
        let ext_block_len = (u16::from_be_bytes([data[0], data[1]]) as usize).min(data.len() - 2);
        data = &data[2..2 + ext_block_len];

        while data.len() >= 4 {
            let ext_type = u16::from_be_bytes([data[0], data[1]]);
            let ext_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            data = &data[4..];
            if data.len() < ext_len {
                break;
            }
            let ext_data = &data[..ext_len];
            data = &data[ext_len..];

            if is_grease(ext_type) {
                continue;
            }

            match ext_type {
                0x000a => groups = parse_supported_groups(ext_data),
                0x000b => points = parse_point_formats(ext_data),
                _ => {}
            }

            extensions.push(Extension {
                typ: ext_type,
                data: ext_data.to_vec(),
            });
        }
    }

    Some(ParsedClientHello {
        record_version,
        hello_version,
        ciphers,
        extensions,
        groups,
        points,
    })
}

fn parse_supported_groups(b: &[u8]) -> Vec<u16> {
    if b.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([b[0], b[1]]) as usize;
    let b = &b[2..];
    if b.len() < list_len || list_len % 2 != 0 {
        return Vec::new();
    }
    b[..list_len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&v| !is_grease(v))
        .collect()
}

fn parse_point_formats(b: &[u8]) -> Vec<u8> {
    if b.is_empty() {
        return Vec::new();
    }
    let list_len = b[0] as usize;
    if b.len() < 1 + list_len {
        return Vec::new();
    }
    b[1..1 + list_len].to_vec()
}
