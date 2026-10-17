use janus::{EchGrease, GREASE, HpackPolicy, HpackStyle, Http2Profile, Huffman, Indexing, PriorityMode, Profile, StreamPriority, TlsProfile};

use crate::clienthello::{ClientHello, is_grease};
use crate::h2frames::{ClientConnection, HeaderField, Representation, huffman_length, pseudo_letter};

/**
 * A profile with the header values the captured request carried.
 */
#[derive(Clone, Debug)]
pub struct Built {
    pub profile: Profile,
    pub headers: Vec<(String, String)>,
}

/**
 * Turns what one browser sent into Janus profiles; every inference is recorded in `notes`.
 */
pub struct ProfileBuilder<'a> {
    hellos: &'a [ClientHello],
    name: String,
    pub notes: Vec<String>,
    /// extensions the Janus kernel builds itself from the profile lists and flags
    native_extensions: [u16; 16],
    /// bodies the kernel produces for the fixed-content native extensions; anything else is sent raw
    native_bodies: [(u16, &'static [u8]); 6],
    /// Chromium Spdy3PriorityToHttp2Weight, indexed by urgency
    chromium_weights: [u16; 8],
}

impl<'a> ProfileBuilder<'a> {
    pub fn new(hellos: &'a [ClientHello], name: &str) -> ProfileBuilder<'a> {
        ProfileBuilder {
            hellos,
            name: name.to_string(),
            notes: Vec::new(),
            native_extensions: [
                0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0015, 0x0017, 0x001b, 0x0023, 0x0029, 0x002b,
                0x002d, 0x0033, 0xfe0d, 0xff01,
            ],
            native_bodies: [
                (0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]),
                (0x000b, &[0x01, 0x00]),
                (0x0017, &[]),
                (0x0023, &[]),
                (0x002d, &[0x01, 0x01]),
                (0xff01, &[0x00]),
            ],
            chromium_weights: [256, 220, 183, 147, 110, 74, 37, 1],
        }
    }

    /**
     * Profile of the page request, with the header values it carried.
     */
    pub fn build(&mut self, document: &[(String, String)], connection: &ClientConnection) -> Result<Built, String> {
        if connection.headers.is_empty() {
            return Err("no HTTP/2 request was captured: the browser did not negotiate h2".into());
        }

        let tls = self.tls()?;
        let http2 = self.http2(connection)?;

        let (headers, order) = self.template(document);
        Ok(Built {
            profile: Profile {
                name: self.name.clone(),
                tls,
                http2,
                header_order: order,
            },
            headers,
        })
    }

    /**
     * The first ClientHello of a full handshake (no pre_shared_key), else the first one.
     */
    fn base_hello(&mut self) -> &'a ClientHello {
        let hellos = self.hellos;
        for hello in hellos {
            if !hello.extension_types().contains(&0x0029) {
                return hello;
            }
        }
        self.notes
            .push("every captured handshake was a resumption; extension bodies come from a resumed hello".into());
        &hellos[0]
    }

    fn grease(value: u16) -> u16 {
        if is_grease(value) { GREASE } else { value }
    }

    fn tls(&mut self) -> Result<TlsProfile, String> {
        let hello = self.base_hello();
        let types = hello.extension_types();
        let mut extensions: Vec<u16> = types.iter().map(|t| Self::grease(*t)).collect();

        if !types.contains(&0x0000) {
            let position = if extensions.first() == Some(&GREASE) { 1 } else { 0 };
            extensions.insert(position, 0x0000);
            self.notes.push(
                "no server_name was sent (page opened by IP address): server_name inserted near the front; \
                 open https://localhost:PORT/ to capture its real position"
                    .into(),
            );
        }
        if !types.contains(&0x0029) && self.hellos.iter().any(|h| h.extension_types().contains(&0x0029)) {
            extensions.push(0x0029);
        }
        if !extensions.contains(&0x0029) {
            self.notes.push(
                "no resumed handshake seen, so pre_shared_key (0x0029) is not in extensions: \
                 let the page finish its rounds to capture one"
                    .into(),
            );
        }

        let ech_grease = match self.ech_grease() {
            Ok(grease) => grease,
            Err(reason) => {
                self.notes
                    .push(format!("encrypted_client_hello sent as the captured body: {reason}"));
                None
            }
        };

        let mut raw_extensions = Vec::new();
        for (ext_type, body) in &hello.extensions {
            if is_grease(*ext_type) || *ext_type == 0x0029 {
                continue;
            }
            if *ext_type == 0xfe0d && ech_grease.is_some() {
                continue;
            }
            if *ext_type != 0xfe0d && self.native_extensions.contains(ext_type) && self.native_body_matches(*ext_type, body) {
                continue;
            }
            raw_extensions.push((*ext_type, body.clone()));
        }

        let mut alps = Vec::new();
        if !hello.alps_protocols.is_empty() {
            for proto in &hello.alps_protocols {
                alps.push((proto.clone(), Vec::new()));
            }
            self.notes.push(
                "client ALPS settings set to empty (what Chrome 155 sends); this server cannot negotiate ALPS to observe them"
                    .into(),
            );
        }

        Ok(TlsProfile {
            ciphers: hello.cipher_suites.iter().map(|c| Self::grease(*c)).collect(),
            extensions,
            groups: hello.supported_groups.iter().map(|g| Self::grease(*g)).collect(),
            key_shares: hello.key_shares.iter().map(|k| Self::grease(*k)).collect(),
            sigalgs: hello.signature_algorithms.iter().map(|s| Self::grease(*s)).collect(),
            versions: hello.supported_versions.iter().map(|v| Self::grease(*v)).collect(),
            raw_extensions,
            alpn: hello.alpn.clone(),
            alps,
            cert_compression: hello.cert_compression.clone(),
            ocsp: types.contains(&0x0005),
            ech_grease,
            permute_extensions: self.permuted(),
        })
    }

    /**
     * HPKE suite and payload lengths of the GREASE encrypted_client_hello in every captured hello.
     */
    fn ech_grease(&mut self) -> Result<Option<EchGrease>, String> {
        let mut grease: Option<EchGrease> = None;
        let mut seen = 0;

        for hello in self.hellos {
            let Some((_, body)) = hello.extensions.iter().find(|(t, _)| *t == 0xfe0d) else {
                continue;
            };
            let (kem, kdf, aead, payload_len) = Self::outer_ech(body)?;
            seen += 1;

            match &mut grease {
                None => {
                    grease = Some(EchGrease {
                        kem,
                        kdf,
                        aead,
                        payload_lengths: vec![payload_len],
                    })
                }
                Some(g) => {
                    if (g.kem, g.kdf, g.aead) != (kem, kdf, aead) {
                        return Err(format!(
                            "the HPKE suite changed between handshakes ({:04x}/{:04x}/{:04x} then {kem:04x}/{kdf:04x}/{aead:04x})",
                            g.kem, g.kdf, g.aead
                        ));
                    }
                    if !g.payload_lengths.contains(&payload_len) {
                        g.payload_lengths.push(payload_len);
                    }
                }
            }
        }

        let Some(mut grease) = grease else {
            return Ok(None);
        };
        grease.payload_lengths.sort_unstable();
        self.notes.push(format!(
            "ECH GREASE kem {:04x} kdf {:04x} aead {:04x}, payload lengths {:?} seen over {seen} handshakes",
            grease.kem, grease.kdf, grease.aead, grease.payload_lengths
        ));
        Ok(Some(grease))
    }

    /**
     * (kem, kdf, aead, payload length) of an outer encrypted_client_hello body; the KEM is told by the enc length.
     */
    fn outer_ech(body: &[u8]) -> Result<(u16, u16, u16, u16), String> {
        let u16_at = |at: usize| -> Result<u16, String> {
            match body.get(at..at + 2) {
                Some(b) => Ok(u16::from_be_bytes([b[0], b[1]])),
                None => Err("truncated encrypted_client_hello".into()),
            }
        };

        if body.first() != Some(&0) {
            return Err("not an outer encrypted_client_hello".into());
        }
        let kdf = u16_at(1)?;
        let aead = u16_at(3)?;
        let enc_len = u16_at(6)? as usize;
        let payload_len = u16_at(8 + enc_len)?;
        if body.len() != 10 + enc_len + payload_len as usize {
            return Err("encrypted_client_hello length does not add up".into());
        }

        // RFC 9180 Npk of the DHKEMs
        let kem = match enc_len {
            32 => 0x0020,
            56 => 0x0021,
            65 => 0x0010,
            97 => 0x0011,
            133 => 0x0012,
            other => return Err(format!("no HPKE KEM has a {other} byte enc")),
        };
        Ok((kem, kdf, aead, payload_len))
    }

    /**
     * Whether a native extension's captured body is what the kernel would send anyway.
     */
    fn native_body_matches(&self, ext_type: u16, body: &[u8]) -> bool {
        match self.native_bodies.iter().find(|(t, _)| *t == ext_type) {
            Some((_, native)) => *native == body,
            None => true,
        }
    }

    /**
     * Whether the extension order changed between captured ClientHellos.
     */
    fn permuted(&mut self) -> bool {
        let mut orders: Vec<Vec<u16>> = Vec::new();
        for hello in self.hellos {
            let order: Vec<u16> = hello
                .extension_types()
                .into_iter()
                .filter(|t| !is_grease(*t) && *t != 0x0015 && *t != 0x0029)
                .collect();
            if !orders.contains(&order) {
                orders.push(order);
            }
        }

        if orders.len() > 1 {
            self.notes.push(format!(
                "extension order differed across {} handshakes: permute_extensions on",
                self.hellos.len()
            ));
            return true;
        }
        if self.hellos.len() == 1 {
            self.notes
                .push("only one handshake captured: cannot tell whether the browser permutes extensions (off)".into());
        }
        false
    }

    fn http2(&mut self, connection: &ClientConnection) -> Result<Http2Profile, String> {
        let first = &connection.headers[0];
        let pseudo_order: String = first.fields.iter().filter_map(|f| pseudo_letter(&f.name)).collect();
        let headers_priority = first.priority.map(|p| StreamPriority {
            depends_on: p.depends_on,
            weight: p.weight,
            exclusive: p.exclusive,
        });

        let http2 = Http2Profile {
            settings: connection.settings.clone(),
            window_update: connection.window_update,
            priority_frames: connection
                .priority_frames
                .iter()
                .map(|(sid, p)| {
                    (
                        *sid,
                        StreamPriority {
                            depends_on: p.depends_on,
                            weight: p.weight,
                            exclusive: p.exclusive,
                        },
                    )
                })
                .collect(),
            pseudo_order,
            headers_priority,
            priority_mode: self.priority_mode(&first.fields, headers_priority),
            hpack: HpackStyle::Custom(self.hpack(connection)),
        };

        http2.validate().map_err(|e| format!("captured HTTP/2 settings are not usable: {e}"))?;
        Ok(http2)
    }

    /**
     * chrome when the HEADERS priority matches Chromium's weight for the request's urgency.
     */
    fn priority_mode(&mut self, fields: &[HeaderField], priority: Option<StreamPriority>) -> PriorityMode {
        let Some(priority) = priority.filter(|p| p.exclusive) else {
            return PriorityMode::Fixed;
        };

        let mut urgency = 3;
        for f in fields.iter().filter(|f| f.name == "priority") {
            for item in f.value.split(',') {
                let item = item.trim();
                if let Some(level) = item.strip_prefix("u=").and_then(|u| u.parse::<usize>().ok()) {
                    urgency = level.min(7);
                }
            }
        }

        if priority.weight == self.chromium_weights[urgency] {
            self.notes.push(format!(
                "HEADERS weight {} matches Chromium for u={urgency}: priority_mode chrome",
                priority.weight
            ));
            return PriorityMode::ChromeTree;
        }
        PriorityMode::Fixed
    }

    /**
     * HPACK policy that reproduces how the captured header blocks were encoded.
     */
    fn hpack(&mut self, connection: &ClientConnection) -> HpackPolicy {
        let mut literals: Vec<(&str, bool)> = Vec::new();
        let mut representations: Vec<(&str, Representation)> = Vec::new();
        let mut crumble = false;

        for block in &connection.headers {
            if block.fields.iter().filter(|f| f.name == "cookie").count() > 1 {
                crumble = true;
            }
            for f in &block.fields {
                if f.representation == Representation::Indexed {
                    continue;
                }
                if !representations.iter().any(|(n, _)| *n == f.name) {
                    representations.push((&f.name, f.representation));
                }
                if let Some(used) = f.value_huffman {
                    literals.push((&f.value, used));
                }
                if let Some(used) = f.name_huffman {
                    literals.push((&f.name, used));
                }
            }
        }

        let default = most_common(&representations).unwrap_or(Representation::Incremental);
        let mut policy = HpackPolicy::new(self.huffman_mode(&literals), indexing(default)).crumble_cookies(crumble);
        for (name, representation) in &representations {
            if *representation != default {
                policy = policy.rule(name, indexing(*representation));
            }
        }
        policy
    }

    /**
     * Huffman mode consistent with every captured literal string.
     */
    fn huffman_mode(&mut self, literals: &[(&str, bool)]) -> Huffman {
        if literals.is_empty() {
            return Huffman::IfShorter;
        }
        if literals
            .iter()
            .all(|(text, used)| *used == (huffman_length(text) < text.chars().count()))
        {
            return Huffman::IfShorter;
        }
        if literals.iter().all(|(_, used)| *used) {
            return Huffman::Always;
        }
        if literals.iter().all(|(_, used)| !*used) {
            return Huffman::Never;
        }

        self.notes
            .push("Huffman use fits none of always/never/if_shorter exactly; using if_shorter".into());
        Huffman::IfShorter
    }

    /**
     * Headers worth sending on every such request and the wire order of one request.
     */
    fn template(&mut self, headers: &[(String, String)]) -> (Vec<(String, String)>, Vec<String>) {
        let per_request = [
            "host",
            "connection",
            "content-length",
            "content-type",
            "cookie",
            "origin",
            "referer",
            "authorization",
        ];
        let template: Vec<(String, String)> = headers
            .iter()
            .filter(|(n, _)| !per_request.contains(&n.to_ascii_lowercase().as_str()))
            .cloned()
            .collect();
        let mut order: Vec<String> = headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        let value = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        };

        if value("user-agent").contains("HeadlessChrome") {
            self.notes
                .push("captured from headless Chrome, the user-agent says HeadlessChrome".into());
        }

        if !order.iter().any(|n| n == "host") {
            order.splice(0..0, ["host".to_string(), "connection".to_string()]);
            self.notes
                .push("HTTP/2 carries no Host/Connection; they lead header_order for HTTP/1.1".into());
        }
        if !order.iter().any(|n| n == "content-length") {
            let position = match order.iter().position(|n| n == "connection") {
                Some(i) => i + 1,
                None => 0,
            };
            order.insert(position, "content-length".to_string());
            self.notes
                .push("no request body, content-length placed after connection".into());
        }
        if !order.iter().any(|n| n == "cookie") {
            self.notes
                .push("no cookies were sent, cookie goes after the listed headers".into());
        }
        (template, order)
    }
}

/**
 * Representation used by the most names; ties go to the one seen first.
 */
fn most_common(representations: &[(&str, Representation)]) -> Option<Representation> {
    let mut counts: Vec<(Representation, usize)> = Vec::new();
    for (_, r) in representations {
        match counts.iter_mut().find(|(seen, _)| seen == r) {
            Some((_, n)) => *n += 1,
            None => counts.push((*r, 1)),
        }
    }

    let mut best: Option<(Representation, usize)> = None;
    for (r, n) in counts {
        if best.is_none_or(|(_, top)| n > top) {
            best = Some((r, n));
        }
    }
    best.map(|(r, _)| r)
}

fn indexing(representation: Representation) -> Indexing {
    match representation {
        Representation::Incremental | Representation::Indexed => Indexing::Incremental,
        Representation::WithoutIndexing => Indexing::WithoutIndexing,
        Representation::NeverIndexed => Indexing::NeverIndexed,
    }
}
