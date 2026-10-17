use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};
use crate::http2::{HpackStyle, Http2Profile, PriorityMode, StreamPriority};
use crate::profile::Profile;
use crate::tls::{EchGrease, TlsProfile};
use janus_h2::{HpackPolicy, Huffman, Indexing};

/**
 * Profile JSON document, the same shape janus_requests JanusProfile.to_json() writes.
 */
#[derive(Serialize, Deserialize)]
struct ProfileDoc {
    name: String,
    tls: TlsDoc,
    http2: Http2Doc,
    header_order: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct TlsDoc {
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    key_shares: Vec<u16>,
    signature_algorithms: Vec<u16>,
    versions: Vec<u16>,
    alpn: Vec<String>,
    /// (protocol, settings as hex)
    alps: Vec<(String, String)>,
    cert_compression: Vec<u16>,
    /// (extension type, body as hex)
    raw_extensions: Vec<(u16, String)>,
    ocsp: bool,
    #[serde(deserialize_with = "ech_grease_field")]
    ech_grease: Option<EchGreaseDoc>,
    permute_extensions: bool,
}

#[derive(Serialize, Deserialize)]
struct EchGreaseDoc {
    kem: u16,
    kdf: u16,
    aead: u16,
    payload_lengths: Vec<u16>,
}

/**
 * ech_grease as written now (null or an object) or by profiles before the shape was configurable (a bool).
 */
#[derive(Deserialize)]
#[serde(untagged)]
enum EchGreaseField {
    Flag(bool),
    Shape(EchGreaseDoc),
}

fn ech_grease_field<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Option<EchGreaseDoc>, D::Error> {
    let field: Option<EchGreaseField> = Option::deserialize(deserializer)?;

    Ok(match field {
        None | Some(EchGreaseField::Flag(false)) => None,
        // a `true` from before meant OpenSSL's own GREASE, which is what the default spells out
        Some(EchGreaseField::Flag(true)) => Some(ech_grease_doc(&EchGrease::default())),
        Some(EchGreaseField::Shape(doc)) => Some(doc),
    })
}

fn ech_grease_doc(grease: &EchGrease) -> EchGreaseDoc {
    EchGreaseDoc {
        kem: grease.kem,
        kdf: grease.kdf,
        aead: grease.aead,
        payload_lengths: grease.payload_lengths.clone(),
    }
}

#[derive(Serialize, Deserialize)]
struct Http2Doc {
    settings: Vec<(u16, u32)>,
    window_update: u32,
    /// (stream id, depends on, weight, exclusive)
    priority_frames: Vec<(u32, u32, u16, bool)>,
    pseudo_order: String,
    /// (depends on, weight, exclusive)
    headers_priority: Option<(u32, u16, bool)>,
    priority_mode: String,
    hpack: Option<HpackDoc>,
}

#[derive(Serialize, Deserialize)]
struct HpackDoc {
    huffman: String,
    indexing: String,
    rules: Vec<(String, String)>,
    crumble_cookies: bool,
}

impl Profile {
    /**
     * Profile as pretty-printed JSON, readable by janus_requests JanusProfile.from_json().
     */
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_json_value()).expect("profile document serializes")
    }

    /**
     * Profile as a JSON value, for embedding in other documents.
     */
    pub fn to_json_value(&self) -> serde_json::Value {
        let doc = ProfileDoc {
            name: self.name.clone(),
            tls: tls_doc(&self.tls),
            http2: http2_doc(&self.http2),
            header_order: self.header_order.clone(),
        };

        serde_json::to_value(&doc).expect("profile document serializes")
    }

    /**
     * Parse and validate a profile written by to_json() or JanusProfile.to_json().
     */
    pub fn from_json(text: &str) -> Result<Profile> {
        let doc: ProfileDoc =
            serde_json::from_str(text).map_err(|e| Error::Profile(format!("profile json: {e}")))?;
        profile_from_doc(doc)
    }

    /**
     * Same as from_json() for an already parsed JSON value.
     */
    pub fn from_json_value(value: serde_json::Value) -> Result<Profile> {
        let doc: ProfileDoc =
            serde_json::from_value(value).map_err(|e| Error::Profile(format!("profile json: {e}")))?;
        profile_from_doc(doc)
    }
}

fn profile_from_doc(doc: ProfileDoc) -> Result<Profile> {
    let http2 = http2_from_doc(doc.http2)?;
    http2.validate()?;

    Ok(Profile {
        name: doc.name,
        tls: tls_from_doc(doc.tls)?,
        http2,
        header_order: doc.header_order.iter().map(|n| n.to_ascii_lowercase()).collect(),
    })
}

fn tls_doc(tls: &TlsProfile) -> TlsDoc {
    TlsDoc {
        ciphers: tls.ciphers.clone(),
        extensions: tls.extensions.clone(),
        groups: tls.groups.clone(),
        key_shares: tls.key_shares.clone(),
        signature_algorithms: tls.sigalgs.clone(),
        versions: tls.versions.clone(),
        alpn: tls.alpn.clone(),
        alps: tls.alps.iter().map(|(p, s)| (p.clone(), hex(s))).collect(),
        cert_compression: tls.cert_compression.clone(),
        raw_extensions: tls.raw_extensions.iter().map(|(t, b)| (*t, hex(b))).collect(),
        ocsp: tls.ocsp,
        ech_grease: tls.ech_grease.as_ref().map(ech_grease_doc),
        permute_extensions: tls.permute_extensions,
    }
}

fn tls_from_doc(doc: TlsDoc) -> Result<TlsProfile> {
    let mut alps = Vec::with_capacity(doc.alps.len());
    for (proto, settings) in doc.alps {
        alps.push((proto, unhex(&settings)?));
    }
    let mut raw_extensions = Vec::with_capacity(doc.raw_extensions.len());
    for (ext_type, body) in doc.raw_extensions {
        raw_extensions.push((ext_type, unhex(&body)?));
    }

    Ok(TlsProfile {
        ciphers: doc.ciphers,
        extensions: doc.extensions,
        groups: doc.groups,
        key_shares: doc.key_shares,
        sigalgs: doc.signature_algorithms,
        versions: doc.versions,
        raw_extensions,
        alpn: doc.alpn,
        alps,
        cert_compression: doc.cert_compression,
        ocsp: doc.ocsp,
        ech_grease: doc.ech_grease.map(|g| EchGrease {
            kem: g.kem,
            kdf: g.kdf,
            aead: g.aead,
            payload_lengths: g.payload_lengths,
        }),
        permute_extensions: doc.permute_extensions,
    })
}

fn http2_doc(http2: &Http2Profile) -> Http2Doc {
    let priority_mode = match http2.priority_mode {
        PriorityMode::Fixed => "fixed",
        PriorityMode::ChromeTree => "chrome",
    };
    let hpack = match &http2.hpack {
        HpackStyle::Legacy => None,
        HpackStyle::Chrome => Some(hpack_doc(&HpackPolicy::chrome())),
        HpackStyle::Custom(policy) => Some(hpack_doc(policy)),
    };

    Http2Doc {
        settings: http2.settings.clone(),
        window_update: http2.window_update,
        priority_frames: http2
            .priority_frames
            .iter()
            .map(|(id, p)| (*id, p.depends_on, p.weight, p.exclusive))
            .collect(),
        pseudo_order: http2.pseudo_order.clone(),
        headers_priority: http2.headers_priority.map(|p| (p.depends_on, p.weight, p.exclusive)),
        priority_mode: priority_mode.to_string(),
        hpack,
    }
}

fn http2_from_doc(doc: Http2Doc) -> Result<Http2Profile> {
    let priority_mode = match doc.priority_mode.as_str() {
        "fixed" => PriorityMode::Fixed,
        "chrome" => PriorityMode::ChromeTree,
        other => return Err(Error::Profile(format!("unknown priority mode {other}"))),
    };
    let hpack = match doc.hpack {
        None => HpackStyle::Legacy,
        Some(h) => HpackStyle::Custom(policy_from_doc(h)?),
    };

    let mut priority_frames = Vec::with_capacity(doc.priority_frames.len());
    for (stream_id, depends_on, weight, exclusive) in doc.priority_frames {
        priority_frames.push((stream_id, priority(depends_on, weight, exclusive)?));
    }
    let headers_priority = match doc.headers_priority {
        Some((depends_on, weight, exclusive)) => Some(priority(depends_on, weight, exclusive)?),
        None => None,
    };

    Ok(Http2Profile {
        settings: doc.settings,
        window_update: doc.window_update,
        priority_frames,
        pseudo_order: doc.pseudo_order,
        headers_priority,
        priority_mode,
        hpack,
    })
}

fn priority(depends_on: u32, weight: u16, exclusive: bool) -> Result<StreamPriority> {
    if !(1..=256).contains(&weight) {
        return Err(Error::Profile(format!("priority weight {weight} is outside 1..=256")));
    }
    Ok(StreamPriority {
        depends_on,
        weight,
        exclusive,
    })
}

fn hpack_doc(policy: &HpackPolicy) -> HpackDoc {
    let huffman = match policy.huffman() {
        Huffman::Always => "always",
        Huffman::Never => "never",
        Huffman::IfShorter => "if_shorter",
    };

    HpackDoc {
        huffman: huffman.to_string(),
        indexing: indexing_name(policy.default_indexing()).to_string(),
        rules: policy
            .rules()
            .map(|(name, indexing)| (String::from_utf8_lossy(name).into_owned(), indexing_name(indexing).to_string()))
            .collect(),
        crumble_cookies: policy.crumbles_cookies(),
    }
}

fn policy_from_doc(doc: HpackDoc) -> Result<HpackPolicy> {
    let huffman = match doc.huffman.as_str() {
        "always" => Huffman::Always,
        "never" => Huffman::Never,
        "if_shorter" => Huffman::IfShorter,
        other => return Err(Error::Profile(format!("unknown huffman mode {other}"))),
    };

    let mut policy = HpackPolicy::new(huffman, indexing_from(&doc.indexing)?).crumble_cookies(doc.crumble_cookies);
    for (name, indexing) in &doc.rules {
        policy = policy.rule(name, indexing_from(indexing)?);
    }
    Ok(policy)
}

/**
 * Indexing mode by its profile name (incremental, without_indexing, never_indexed).
 */
pub fn indexing_from(name: &str) -> Result<Indexing> {
    match name {
        "incremental" => Ok(Indexing::Incremental),
        "without_indexing" => Ok(Indexing::WithoutIndexing),
        "never_indexed" => Ok(Indexing::NeverIndexed),
        other => Err(Error::Profile(format!("unknown hpack indexing {other}"))),
    }
}

/**
 * Profile name of an indexing mode.
 */
pub fn indexing_name(indexing: Indexing) -> &'static str {
    match indexing {
        Indexing::Incremental => "incremental",
        Indexing::WithoutIndexing => "without_indexing",
        Indexing::NeverIndexed => "never_indexed",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(Error::Profile(format!("hex string {text:?} has odd length")));
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| Error::Profile(format!("bad hex string {text:?}")))?;
        out.push(u8::from_str_radix(pair, 16).map_err(|_| Error::Profile(format!("bad hex string {text:?}")))?);
    }
    Ok(out)
}
