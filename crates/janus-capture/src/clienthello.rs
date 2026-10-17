use openssl::hash::{MessageDigest, hash};

/**
 * Parsed TLS ClientHello with the views the profile builder and the fingerprints need.
 */
#[derive(Clone, Debug)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    /// (type, body) in wire order, GREASE included
    pub extensions: Vec<(u16, Vec<u8>)>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub supported_groups: Vec<u16>,
    /// groups that carry a key share, in order
    pub key_shares: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub cert_compression: Vec<u16>,
    pub alps_protocols: Vec<String>,
}

/**
 * Bounds-checked big-endian cursor over a byte slice.
 */
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8], String> {
        if size > self.remaining() {
            return Err(format!(
                "truncated TLS structure: need {size} bytes, have {}",
                self.remaining()
            ));
        }
        let chunk = &self.data[self.pos..self.pos + size];
        self.pos += size;
        Ok(chunk)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], String> {
        let length = self.u8()? as usize;
        self.take(length)
    }

    fn vec16(&mut self) -> Result<&'a [u8], String> {
        let length = self.u16()? as usize;
        self.take(length)
    }
}

/**
 * Whether value is an RFC 8701 GREASE codepoint.
 */
pub fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff)
}

/**
 * Parse a ClientHello from buffered TLS records; Ok(None) means more bytes are needed.
 */
pub fn read_client_hello(data: &[u8]) -> Result<Option<ClientHello>, String> {
    if data.is_empty() {
        return Ok(None);
    }
    if data[0] != 0x16 {
        return Err(format!("not a TLS handshake record: first byte is 0x{:02x}", data[0]));
    }
    if data.len() >= 6 && data[5] != 0x01 {
        return Err(format!("expected ClientHello (0x01), got handshake type 0x{:02x}", data[5]));
    }

    let mut handshake = Vec::new();
    let mut pos = 0;
    let mut message_length: Option<usize> = None;

    loop {
        if data.len() < pos + 5 {
            return Ok(None);
        }
        if data[pos] != 0x16 {
            return Err(format!("record type 0x{:02x} inside ClientHello, expected 0x16", data[pos]));
        }
        let record_length = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let record_end = pos + 5 + record_length;
        if data.len() < record_end {
            return Ok(None);
        }
        handshake.extend_from_slice(&data[pos + 5..record_end]);
        pos = record_end;

        if message_length.is_none() && handshake.len() >= 4 {
            let length = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            message_length = Some(4 + length);
        }
        if let Some(length) = message_length {
            if handshake.len() >= length {
                return parse_client_hello(&handshake[..length]).map(Some);
            }
        }
    }
}

fn parse_client_hello(message: &[u8]) -> Result<ClientHello, String> {
    let mut body = Reader::new(message);
    body.take(4)?;
    let legacy_version = body.u16()?;
    body.take(32)?;
    body.vec8()?;
    let cipher_suites = split_u16(body.vec16()?)?;
    body.vec8()?;

    let mut extensions = Vec::new();
    if body.remaining() > 0 {
        let mut ext_reader = Reader::new(body.vec16()?);
        while ext_reader.remaining() > 0 {
            let ext_type = ext_reader.u16()?;
            let ext_length = ext_reader.u16()? as usize;
            extensions.push((ext_type, ext_reader.take(ext_length)?.to_vec()));
        }
    }

    let find = |ext_type: u16| extensions.iter().find(|(t, _)| *t == ext_type).map(|(_, b)| b.as_slice());
    let alps_protocols = match extensions.iter().find(|(t, _)| *t == 0x44cd || *t == 0x4469) {
        Some((_, b)) => parse_string_list(b)?,
        None => Vec::new(),
    };

    Ok(ClientHello {
        legacy_version,
        server_name: find(0x0000).map(parse_server_name).transpose()?.flatten(),
        alpn: find(0x0010).map(parse_string_list).transpose()?.unwrap_or_default(),
        supported_groups: find(0x000a).map(parse_u16_list).transpose()?.unwrap_or_default(),
        key_shares: find(0x0033).map(parse_key_shares).transpose()?.unwrap_or_default(),
        signature_algorithms: find(0x000d).map(parse_u16_list).transpose()?.unwrap_or_default(),
        supported_versions: find(0x002b).map(parse_u8_u16_list).transpose()?.unwrap_or_default(),
        ec_point_formats: find(0x000b).map(parse_u8_list).transpose()?.unwrap_or_default(),
        cert_compression: find(0x001b).map(parse_u8_u16_list).transpose()?.unwrap_or_default(),
        alps_protocols,
        cipher_suites,
        extensions,
    })
}

impl ClientHello {
    /**
     * Extension types in wire order, GREASE included.
     */
    pub fn extension_types(&self) -> Vec<u16> {
        self.extensions.iter().map(|(t, _)| *t).collect()
    }

    /**
     * Full JA3 string with GREASE removed.
     */
    pub fn ja3(&self) -> String {
        let points: Vec<u16> = self.ec_point_formats.iter().map(|p| *p as u16).collect();

        [
            self.legacy_version.to_string(),
            join_decimal(&self.cipher_suites),
            join_decimal(&self.extension_types()),
            join_decimal(&self.supported_groups),
            join_decimal(&points),
        ]
        .join(",")
    }

    /**
     * Hashed JA4 fingerprint (TCP).
     */
    pub fn ja4(&self) -> String {
        let ciphers = self.ja4_ciphers();
        let extensions = self.ja4_extensions();
        let sigalgs = self.ja4_sigalgs();

        let part_b = if ciphers.is_empty() {
            "000000000000".to_string()
        } else {
            truncated_sha256(&ciphers.join(","))
        };
        let part_c = if extensions.is_empty() {
            "000000000000".to_string()
        } else {
            let mut input = extensions.join(",");
            if !sigalgs.is_empty() {
                input.push('_');
                input.push_str(&sigalgs.join(","));
            }
            truncated_sha256(&input)
        };

        format!("{}_{part_b}_{part_c}", self.ja4_prefix())
    }

    fn ja4_prefix(&self) -> String {
        let version = self
            .supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version);
        let version_text = match version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            _ => "00",
        };
        let sni_flag = if self.server_name.is_some() { "d" } else { "i" };
        let cipher_count = self.cipher_suites.iter().filter(|c| !is_grease(**c)).count().min(99);
        let ext_count = self.extensions.iter().filter(|(t, _)| !is_grease(*t)).count().min(99);

        format!(
            "t{version_text}{sni_flag}{cipher_count:02}{ext_count:02}{}",
            alpn_chars(&self.alpn)
        )
    }

    fn ja4_ciphers(&self) -> Vec<String> {
        let mut values: Vec<u16> = self.cipher_suites.iter().copied().filter(|c| !is_grease(*c)).collect();
        values.sort_unstable();
        values.iter().map(|c| format!("{c:04x}")).collect()
    }

    fn ja4_extensions(&self) -> Vec<String> {
        let mut values: Vec<u16> = self
            .extension_types()
            .into_iter()
            .filter(|t| !is_grease(*t) && *t != 0x0000 && *t != 0x0010)
            .collect();
        values.sort_unstable();
        values.iter().map(|t| format!("{t:04x}")).collect()
    }

    fn ja4_sigalgs(&self) -> Vec<String> {
        self.signature_algorithms
            .iter()
            .filter(|s| !is_grease(**s))
            .map(|s| format!("{s:04x}"))
            .collect()
    }
}

fn parse_server_name(body: &[u8]) -> Result<Option<String>, String> {
    let mut outer = Reader::new(body);
    let mut reader = Reader::new(outer.vec16()?);

    while reader.remaining() > 0 {
        let name_type = reader.u8()?;
        let name_length = reader.u16()? as usize;
        let name = reader.take(name_length)?;
        if name_type == 0 {
            return Ok(Some(name.iter().map(|b| *b as char).collect()));
        }
    }
    Ok(None)
}

fn parse_key_shares(body: &[u8]) -> Result<Vec<u16>, String> {
    let mut outer = Reader::new(body);
    let mut reader = Reader::new(outer.vec16()?);
    let mut groups = Vec::new();

    while reader.remaining() > 0 {
        groups.push(reader.u16()?);
        let key_length = reader.u16()? as usize;
        reader.take(key_length)?;
    }
    Ok(groups)
}

fn parse_string_list(body: &[u8]) -> Result<Vec<String>, String> {
    let mut outer = Reader::new(body);
    let mut reader = Reader::new(outer.vec16()?);
    let mut values = Vec::new();

    while reader.remaining() > 0 {
        let value = reader.vec8()?;
        values.push(value.iter().map(|b| *b as char).collect());
    }
    Ok(values)
}

fn parse_u16_list(body: &[u8]) -> Result<Vec<u16>, String> {
    split_u16(Reader::new(body).vec16()?)
}

fn parse_u8_u16_list(body: &[u8]) -> Result<Vec<u16>, String> {
    split_u16(Reader::new(body).vec8()?)
}

fn parse_u8_list(body: &[u8]) -> Result<Vec<u8>, String> {
    Ok(Reader::new(body).vec8()?.to_vec())
}

fn split_u16(data: &[u8]) -> Result<Vec<u16>, String> {
    if data.len() % 2 != 0 {
        return Err(format!("u16 list has odd length {}", data.len()));
    }
    Ok(data.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
}

fn join_decimal(values: &[u16]) -> String {
    let kept: Vec<String> = values.iter().filter(|v| !is_grease(**v)).map(|v| v.to_string()).collect();
    kept.join("-")
}

fn alpn_chars(alpn: &[String]) -> String {
    let Some(value) = alpn.first().filter(|v| !v.is_empty()) else {
        return "00".to_string();
    };

    let first = value.chars().next().unwrap_or('0');
    let last = value.chars().last().unwrap_or('0');
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return format!("{first}{last}");
    }

    let hexed: String = value.chars().map(|c| format!("{:02x}", c as u32 as u8)).collect();
    let h = hexed.as_bytes();
    format!("{}{}", h[0] as char, h[h.len() - 1] as char)
}

fn truncated_sha256(text: &str) -> String {
    let digest = hash(MessageDigest::sha256(), text.as_bytes()).expect("sha256 is available");
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}
