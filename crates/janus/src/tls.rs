use std::collections::HashMap;
use std::ffi::c_int;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslOptions, SslSession, SslSessionCacheMode,
    SslVerifyMode, SslVersion, StatusType,
};
use openssl::x509::X509;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;

use crate::error::{Error, Result};

/// Placeholder replaced by a per-connection GREASE value inside any list.
pub const GREASE: u16 = 0xFFFF;

mod ffi {
    use openssl_sys::{SSL, SSL_CTX};
    use std::ffi::c_int;

    pub const LIST_EXTENSIONS: c_int = 0;
    pub const LIST_CIPHERS: c_int = 1;
    pub const LIST_GROUPS: c_int = 2;
    pub const LIST_KEY_SHARES: c_int = 3;
    pub const LIST_SIGALGS: c_int = 4;
    pub const LIST_VERSIONS: c_int = 5;
    pub const FLAG_PERMUTE_EXTENSIONS: u32 = 0x1;

    unsafe extern "C" {
        pub fn SSL_CTX_janus_set_list(ctx: *mut SSL_CTX, which: c_int, values: *const u16, n: usize) -> c_int;
        pub fn SSL_CTX_janus_set_raw_extension(ctx: *mut SSL_CTX, ext_type: u16, data: *const u8, len: usize) -> c_int;
        pub fn SSL_CTX_janus_set_flags(ctx: *mut SSL_CTX, flags: u32) -> c_int;
        pub fn SSL_CTX_janus_sync_internal(ctx: *mut SSL_CTX) -> c_int;
        pub fn SSL_janus_get_grease_value(s: *const SSL, which: c_int, occurrence: usize) -> u16;
        pub fn SSL_CTX_janus_set_alps(
            ctx: *mut SSL_CTX,
            proto: *const u8,
            proto_len: usize,
            settings: *const u8,
            settings_len: usize,
        ) -> c_int;
        pub fn SSL_janus_alps_negotiated(s: *const SSL) -> c_int;
        pub fn SSL_CTX_janus_set_ech_grease(
            ctx: *mut SSL_CTX,
            kem: u16,
            kdf: u16,
            aead: u16,
            payload_lengths: *const u16,
            n: usize,
        ) -> c_int;
        pub fn SSL_CTX_set1_cert_comp_preference(ctx: *mut SSL_CTX, algs: *mut c_int, len: usize) -> c_int;
    }
}

/**
 * Everything that shapes the ClientHello, as wire-level values.
 */
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsProfile {
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub key_shares: Vec<u16>,
    pub sigalgs: Vec<u16>,
    pub versions: Vec<u16>,
    pub raw_extensions: Vec<(u16, Vec<u8>)>,
    pub alpn: Vec<String>,
    /// client ALPS settings per protocol, sent when the server negotiates application_settings
    pub alps: Vec<(String, Vec<u8>)>,
    pub cert_compression: Vec<u16>,
    pub ocsp: bool,
    pub ech_grease: Option<EchGrease>,
    pub permute_extensions: bool,
}

/**
 * GREASE encrypted_client_hello: HPKE suite and the payload lengths one is drawn from per connection.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchGrease {
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
    pub payload_lengths: Vec<u16>,
}

impl Default for EchGrease {
    /**
     * What OpenSSL sends on its own: X25519, HKDF-SHA256, AES-128-GCM, 144/176/208/240.
     */
    fn default() -> EchGrease {
        EchGrease {
            kem: 0x0020,
            kdf: 0x0001,
            aead: 0x0001,
            payload_lengths: vec![144, 176, 208, 240],
        }
    }
}

impl EchGrease {
    /**
     * Parse the spec arguments `kem=0020 kdf=0001 aead=0001 lengths=144,176,208,240`; none means the default.
     */
    fn from_spec(args: &[&str]) -> std::result::Result<EchGrease, String> {
        if args.is_empty() {
            return Ok(EchGrease::default());
        }

        let mut kem = None;
        let mut kdf = None;
        let mut aead = None;
        let mut lengths = None;
        for arg in args {
            let Some((key, value)) = arg.split_once('=') else {
                return Err(format!("ech_grease argument {arg} is not key=value"));
            };
            match key {
                "kem" => kem = Some(parse_u16(value)?),
                "kdf" => kdf = Some(parse_u16(value)?),
                "aead" => aead = Some(parse_u16(value)?),
                "lengths" => {
                    let parsed: std::result::Result<Vec<u16>, _> = value.split(',').map(|v| v.parse::<u16>()).collect();
                    lengths = Some(parsed.map_err(|_| format!("bad ech_grease lengths {value}"))?);
                }
                _ => return Err(format!("unknown ech_grease key {key}")),
            }
        }

        match (kem, kdf, aead, lengths) {
            (Some(kem), Some(kdf), Some(aead), Some(payload_lengths)) => Ok(EchGrease {
                kem,
                kdf,
                aead,
                payload_lengths,
            }),
            _ => Err("ech_grease needs kem, kdf, aead and lengths together".into()),
        }
    }

    fn to_spec(&self) -> String {
        let lengths: Vec<String> = self.payload_lengths.iter().map(|l| l.to_string()).collect();
        format!(
            "ech_grease kem={:04x} kdf={:04x} aead={:04x} lengths={}",
            self.kem,
            self.kdf,
            self.aead,
            lengths.join(",")
        )
    }
}

impl TlsProfile {
    /**
     * Chrome 155 on Windows.
     */
    pub fn chrome155() -> TlsProfile {
        TlsProfile::from_spec(include_str!("profiles/chrome155.tls")).expect("built-in chrome155 profile parses")
    }

    /**
     * Parse the line-based spec format (`ciphers grease 1301 ...`, `raw 44cd 0003026832`, ...).
     */
    pub fn from_spec(text: &str) -> Result<TlsProfile> {
        let mut profile = TlsProfile::default();

        for (lineno, line) in text.lines().enumerate() {
            let mut tokens = line.split_whitespace();
            let Some(key) = tokens.next() else {
                continue;
            };
            if key.starts_with('#') {
                continue;
            }

            let rest: Vec<&str> = tokens.collect();
            let bad = |what: &str| Error::Profile(format!("line {}: {what}: {line}", lineno + 1));

            match key {
                "ciphers" => profile.ciphers = parse_u16_list(&rest).map_err(|e| bad(&e))?,
                "extensions" => profile.extensions = parse_u16_list(&rest).map_err(|e| bad(&e))?,
                "groups" => profile.groups = parse_u16_list(&rest).map_err(|e| bad(&e))?,
                "key_shares" => profile.key_shares = parse_u16_list(&rest).map_err(|e| bad(&e))?,
                "sigalgs" => profile.sigalgs = parse_u16_list(&rest).map_err(|e| bad(&e))?,
                "versions" => profile.versions = parse_u16_list(&rest).map_err(|e| bad(&e))?,
                "alpn" => profile.alpn = rest.iter().map(|s| s.to_string()).collect(),
                "alps" => {
                    let proto = rest.first().ok_or_else(|| bad("alps needs a protocol"))?;
                    let settings = match rest.get(1) {
                        Some(hex) => decode_hex(hex).map_err(|e| bad(&e))?,
                        None => Vec::new(),
                    };
                    profile.alps.retain(|(p, _)| p != proto);
                    profile.alps.push((proto.to_string(), settings));
                }
                "cert_comp" => {
                    for tok in &rest {
                        profile.cert_compression.push(tok.parse().map_err(|_| bad("bad cert_comp id"))?);
                    }
                }
                "raw" => {
                    let ext_type = rest.first().ok_or_else(|| bad("raw needs a type"))?;
                    let ext_type = parse_u16(ext_type).map_err(|e| bad(&e))?;
                    let body = match rest.get(1) {
                        Some(hex) => decode_hex(hex).map_err(|e| bad(&e))?,
                        None => Vec::new(),
                    };
                    profile.raw_extensions.retain(|(t, _)| *t != ext_type);
                    profile.raw_extensions.push((ext_type, body));
                }
                "ocsp" => profile.ocsp = true,
                "ech_grease" => profile.ech_grease = Some(EchGrease::from_spec(&rest).map_err(|e| bad(&e))?),
                "flag" => match rest.first() {
                    Some(&"permute") => profile.permute_extensions = true,
                    _ => return Err(bad("unknown flag")),
                },
                _ => return Err(bad("unknown key")),
            }
        }
        Ok(profile)
    }

    /**
     * Render the profile back into the spec format.
     */
    pub fn to_spec(&self) -> String {
        let mut out = Vec::new();
        let lists = [
            ("ciphers", &self.ciphers),
            ("extensions", &self.extensions),
            ("groups", &self.groups),
            ("key_shares", &self.key_shares),
            ("sigalgs", &self.sigalgs),
            ("versions", &self.versions),
        ];
        for (key, values) in lists {
            if !values.is_empty() {
                out.push(format!("{key} {}", format_u16_list(values)));
            }
        }
        if !self.alpn.is_empty() {
            out.push(format!("alpn {}", self.alpn.join(" ")));
        }
        for (proto, settings) in &self.alps {
            out.push(format!("alps {proto} {}", encode_hex(settings)).trim_end().to_string());
        }
        if !self.cert_compression.is_empty() {
            let ids: Vec<String> = self.cert_compression.iter().map(|v| v.to_string()).collect();
            out.push(format!("cert_comp {}", ids.join(" ")));
        }
        for (ext_type, body) in &self.raw_extensions {
            out.push(format!("raw {ext_type:04x} {}", encode_hex(body)).trim_end().to_string());
        }
        if let Some(grease) = &self.ech_grease {
            out.push(grease.to_spec());
        }
        if self.ocsp {
            out.push("ocsp".to_string());
        }
        if self.permute_extensions {
            out.push("flag permute".to_string());
        }
        out.join("\n")
    }

    /**
     * Build an OpenSSL context carrying this profile; new session tickets land in `sessions`.
     */
    fn build_context(&self, mode: &TlsMode, sessions: SessionCache) -> Result<SslContext> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client())?;

        match &mode.verify {
            Verify::System => {
                builder.set_verify(SslVerifyMode::PEER);
                builder.set_cert_store(native_roots()?);
            }
            Verify::Off => builder.set_verify(SslVerifyMode::NONE),
            Verify::CaBundle(path) => {
                builder.set_verify(SslVerifyMode::PEER);
                if path.is_dir() {
                    builder.load_verify_locations(None, Some(path))?;
                } else {
                    builder.set_ca_file(path)?;
                }
            }
        }
        if let Some(cert) = &mode.client_cert {
            builder.set_certificate_chain_file(&cert.cert)?;
            builder.set_private_key_file(cert.key.as_ref().unwrap_or(&cert.cert), SslFiletype::PEM)?;
            builder.check_private_key()?;
        }

        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        builder.set_new_session_callback(move |ssl, session| {
            if let Some(key) = ssl.ex_data(session_key_index()) {
                sessions.lock().expect("session cache lock").insert(key.clone(), session);
            }
        });

        if self.ech_grease.is_some() {
            // SSL_OP_ECH_GREASE
            builder.set_options(SslOptions::from_bits_retain(1 << 37));
        }
        if !self.alpn.is_empty() {
            builder.set_alpn_protos(&alpn_wire(&self.alpn))?;
        }

        let ctx = builder.as_ptr();
        let lists = [
            (ffi::LIST_EXTENSIONS, &self.extensions),
            (ffi::LIST_CIPHERS, &self.ciphers),
            (ffi::LIST_GROUPS, &self.groups),
            (ffi::LIST_KEY_SHARES, &self.key_shares),
            (ffi::LIST_SIGALGS, &self.sigalgs),
            (ffi::LIST_VERSIONS, &self.versions),
        ];

        unsafe {
            for (which, values) in lists {
                if values.is_empty() {
                    continue;
                }
                check(ffi::SSL_CTX_janus_set_list(ctx, which, values.as_ptr(), values.len()))?;
            }
            for (ext_type, body) in &self.raw_extensions {
                check(ffi::SSL_CTX_janus_set_raw_extension(ctx, *ext_type, body.as_ptr(), body.len()))?;
            }
            for (proto, settings) in &self.alps {
                check(ffi::SSL_CTX_janus_set_alps(
                    ctx,
                    proto.as_ptr(),
                    proto.len(),
                    settings.as_ptr(),
                    settings.len(),
                ))?;
            }
            if let Some(grease) = &self.ech_grease {
                check(ffi::SSL_CTX_janus_set_ech_grease(
                    ctx,
                    grease.kem,
                    grease.kdf,
                    grease.aead,
                    grease.payload_lengths.as_ptr(),
                    grease.payload_lengths.len(),
                ))?;
            }
            if !self.cert_compression.is_empty() {
                let mut algs: Vec<c_int> = self.cert_compression.iter().map(|v| *v as c_int).collect();
                check(ffi::SSL_CTX_set1_cert_comp_preference(ctx, algs.as_mut_ptr(), algs.len()))?;
            }

            let mut flags = 0;
            if self.permute_extensions {
                flags |= ffi::FLAG_PERMUTE_EXTENSIONS;
            }
            check(ffi::SSL_CTX_janus_set_flags(ctx, flags))?;
            check(ffi::SSL_CTX_janus_sync_internal(ctx))?;
        }

        Ok(builder.build())
    }
}

/**
 * How the server certificate is checked.
 */
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Verify {
    /// operating-system trust store
    #[default]
    System,
    Off,
    /// PEM bundle file or c_rehash directory
    CaBundle(PathBuf),
}

/**
 * Client certificate in PEM; the key may live in the certificate file.
 */
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientCert {
    pub cert: PathBuf,
    pub key: Option<PathBuf>,
}

/**
 * Per-request TLS settings that need their own OpenSSL context.
 */
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TlsMode {
    pub verify: Verify,
    pub client_cert: Option<ClientCert>,
}

type SessionCache = Arc<Mutex<HashMap<String, SslSession>>>;

/**
 * Ex-data slot holding the session cache key of a connection.
 */
fn session_key_index() -> Index<Ssl, String> {
    static INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();

    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocate ssl ex index"))
}

/**
 * A finished TLS handshake.
 */
pub struct TlsStream<S> {
    pub stream: SslStream<S>,
    pub resumed: bool,
}

/**
 * Builds TLS client connections for one profile, resuming sessions per host.
 */
#[derive(Clone)]
pub struct TlsConnector {
    profile: Arc<TlsProfile>,
    contexts: Arc<Mutex<HashMap<TlsMode, SslContext>>>,
    sessions: SessionCache,
}

impl TlsConnector {
    pub fn new(profile: &TlsProfile) -> Result<TlsConnector> {
        let connector = TlsConnector {
            profile: Arc::new(profile.clone()),
            contexts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        };

        // surface profile errors at construction time
        connector.context(&TlsMode::default())?;
        Ok(connector)
    }

    pub fn profile(&self) -> &TlsProfile {
        &self.profile
    }

    /**
     * Drop every cached session so the next handshakes are full ones.
     */
    pub fn clear_sessions(&self) {
        self.sessions.lock().expect("session cache lock").clear();
    }

    fn context(&self, mode: &TlsMode) -> Result<SslContext> {
        let mut contexts = self.contexts.lock().expect("tls context lock");

        if let Some(ctx) = contexts.get(mode) {
            return Ok(ctx.clone());
        }
        let ctx = self.profile.build_context(mode, self.sessions.clone())?;
        contexts.insert(mode.clone(), ctx.clone());
        Ok(ctx)
    }

    /**
     * Take the cached session for a key; TLS 1.3 tickets are single-use.
     */
    fn cached_session(&self, key: &str) -> Option<SslSession> {
        let mut sessions = self.sessions.lock().expect("session cache lock");
        let session = sessions.get(key)?;

        if session.protocol_version() == SslVersion::TLS1_3 {
            return sessions.remove(key);
        }
        Some(session.to_owned())
    }

    /**
     * Run the TLS handshake over an established byte stream, offering a cached session when there is one.
     */
    pub async fn connect<S>(&self, host: &str, port: u16, mode: &TlsMode, stream: S) -> Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ctx = self.context(mode)?;
        let mut ssl = Ssl::new(&ctx)?;
        let is_ip = host.parse::<std::net::IpAddr>().is_ok();
        let key = format!("{mode:?}|{host}:{port}");

        if !is_ip {
            ssl.set_hostname(host)?;
        }
        if mode.verify != Verify::Off {
            let param = ssl.param_mut();
            if is_ip {
                param.set_ip(host.parse().expect("checked above"))?;
            } else {
                param.set_host(host)?;
            }
        }
        if self.profile.ocsp {
            ssl.set_status_type(StatusType::OCSP)?;
        }
        if let Some(session) = self.cached_session(&key) {
            // the session was issued by a context built from this same profile and mode
            unsafe { ssl.set_session(&session)? };
        }
        ssl.set_ex_data(session_key_index(), key);

        let mut tls = SslStream::new(ssl, stream)?;

        Pin::new(&mut tls)
            .connect()
            .await
            .map_err(|e| Error::Tls(format!("handshake with {host} failed: {e}")))?;

        let resumed = tls.ssl().session_reused();
        Ok(TlsStream { stream: tls, resumed })
    }
}

/**
 * GREASE value used for one list in the handshake of this connection.
 */
pub fn grease_value<S>(stream: &SslStream<S>, which: c_int, occurrence: usize) -> u16 {
    unsafe { ffi::SSL_janus_get_grease_value(stream.ssl().as_ptr(), which, occurrence) }
}

/**
 * Whether the server negotiated ALPS on this connection.
 */
pub fn alps_negotiated<S>(stream: &SslStream<S>) -> bool {
    unsafe { ffi::SSL_janus_alps_negotiated(stream.ssl().as_ptr()) == 1 }
}

/**
 * Selected ALPN protocol of a finished handshake.
 */
pub fn negotiated_alpn<S>(stream: &SslStream<S>) -> Option<Vec<u8>> {
    stream.ssl().selected_alpn_protocol().map(|p| p.to_vec())
}

fn check(rc: c_int) -> Result<()> {
    if rc == 1 {
        return Ok(());
    }
    Err(Error::Tls(openssl::error::ErrorStack::get().to_string()))
}

/**
 * Operating-system trust anchors, loaded once.
 */
fn native_roots() -> Result<X509Store> {
    static ROOTS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

    let ders = ROOTS.get_or_init(|| {
        let loaded = rustls_native_certs::load_native_certs();
        loaded.certs.into_iter().map(|c| c.as_ref().to_vec()).collect()
    });

    let mut store = X509StoreBuilder::new()?;
    for der in ders {
        if let Ok(cert) = X509::from_der(der) {
            // duplicates across system stores are harmless
            let _ = store.add_cert(cert);
        }
    }
    Ok(store.build())
}

fn alpn_wire(protocols: &[String]) -> Vec<u8> {
    let mut wire = Vec::new();
    for p in protocols {
        wire.push(p.len() as u8);
        wire.extend_from_slice(p.as_bytes());
    }
    wire
}

fn parse_u16(tok: &str) -> std::result::Result<u16, String> {
    if tok == "grease" {
        return Ok(GREASE);
    }
    u16::from_str_radix(tok.trim_start_matches("0x"), 16).map_err(|_| format!("bad u16 {tok}"))
}

fn parse_u16_list(tokens: &[&str]) -> std::result::Result<Vec<u16>, String> {
    tokens.iter().map(|t| parse_u16(t)).collect()
}

fn format_u16_list(values: &[u16]) -> String {
    let parts: Vec<String> = values
        .iter()
        .map(|v| if *v == GREASE { "grease".to_string() } else { format!("{v:04x}") })
        .collect();
    parts.join(" ")
}

fn decode_hex(hex: &str) -> std::result::Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("odd hex length {}", hex.len()));
    }
    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);

    hex.as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(i, pair)| match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => Ok(high << 4 | low),
            _ => Err(format!("bad hex at {}", i * 2)),
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_round_trip() {
        let profile = TlsProfile::chrome155();
        let again = TlsProfile::from_spec(&profile.to_spec()).unwrap();

        assert_eq!(profile, again);
        assert_eq!(profile.extensions.first(), Some(&GREASE));
    }
}
