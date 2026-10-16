use janus::{HpackPolicy, HpackStyle, Http2Profile, Huffman, Indexing, PriorityMode, Profile, StreamPriority, TlsProfile};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::{priority_from_tuple, to_py_err};

/**
 * ClientHello part of a profile dict, as janus_requests.profile.JanusTls.to_native() builds it.
 */
#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub struct TlsArg {
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    key_shares: Vec<u16>,
    signature_algorithms: Vec<u16>,
    versions: Vec<u16>,
    alpn: Vec<String>,
    alps: Vec<(String, Vec<u8>)>,
    cert_compression: Vec<u16>,
    raw_extensions: Vec<(u16, Vec<u8>)>,
    ocsp: bool,
    ech_grease: bool,
    permute_extensions: bool,
}

#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub struct HpackArg {
    huffman: String,
    indexing: String,
    rules: Vec<(String, String)>,
    crumble_cookies: bool,
}

#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub struct Http2Arg {
    settings: Vec<(u16, u32)>,
    window_update: u32,
    priority_frames: Vec<(u32, u32, u16, bool)>,
    pseudo_order: String,
    headers_priority: Option<(u32, u16, bool)>,
    priority_mode: String,
    hpack: Option<HpackArg>,
}

/**
 * Whole profile dict: TLS, HTTP/2 and the request header order.
 */
#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub struct ProfileArg {
    name: String,
    tls: TlsArg,
    http2: Http2Arg,
    header_order: Vec<String>,
}

impl ProfileArg {
    /**
     * Validate and convert into the core Profile.
     */
    pub fn into_profile(self) -> PyResult<Profile> {
        Ok(Profile {
            name: self.name,
            tls: self.tls.into_tls(),
            http2: self.http2.into_http2()?,
            header_order: self.header_order.iter().map(|n| n.to_ascii_lowercase()).collect(),
        })
    }
}

impl TlsArg {
    fn into_tls(self) -> TlsProfile {
        TlsProfile {
            ciphers: self.ciphers,
            extensions: self.extensions,
            groups: self.groups,
            key_shares: self.key_shares,
            sigalgs: self.signature_algorithms,
            versions: self.versions,
            raw_extensions: self.raw_extensions,
            alpn: self.alpn,
            alps: self.alps,
            cert_compression: self.cert_compression,
            ocsp: self.ocsp,
            ech_grease: self.ech_grease,
            permute_extensions: self.permute_extensions,
        }
    }
}

impl Http2Arg {
    fn into_http2(self) -> PyResult<Http2Profile> {

        let mut priority_frames = Vec::with_capacity(self.priority_frames.len());
        for (stream_id, depends_on, weight, exclusive) in self.priority_frames {
            priority_frames.push((stream_id, priority_from_tuple((depends_on, weight, exclusive))?));
        }

        let priority_mode = match self.priority_mode.as_str() {
            "fixed" => PriorityMode::Fixed,
            "chrome" => PriorityMode::ChromeTree,
            other => return Err(PyValueError::new_err(format!("unknown priority mode {other}"))),
        };
        let hpack = match self.hpack {
            None => HpackStyle::Legacy,
            Some(arg) => HpackStyle::Custom(arg.into_policy()?),
        };

        let http2 = Http2Profile {
            settings: self.settings,
            window_update: self.window_update,
            priority_frames,
            pseudo_order: self.pseudo_order,
            headers_priority: self.headers_priority.map(priority_from_tuple).transpose()?,
            priority_mode,
            hpack,
        };

        http2.validate().map_err(to_py_err)?;
        Ok(http2)
    }
}

impl HpackArg {
    fn into_policy(self) -> PyResult<HpackPolicy> {
        let huffman = match self.huffman.as_str() {
            "always" => Huffman::Always,
            "never" => Huffman::Never,
            "if_shorter" => Huffman::IfShorter,
            other => return Err(PyValueError::new_err(format!("unknown huffman mode {other}"))),
        };

        let mut policy = HpackPolicy::new(huffman, indexing_from(&self.indexing)?).crumble_cookies(self.crumble_cookies);
        for (name, indexing) in &self.rules {
            policy = policy.rule(name, indexing_from(indexing)?);
        }
        Ok(policy)
    }
}

fn indexing_from(name: &str) -> PyResult<Indexing> {
    match name {
        "incremental" => Ok(Indexing::Incremental),
        "without_indexing" => Ok(Indexing::WithoutIndexing),
        "never_indexed" => Ok(Indexing::NeverIndexed),
        other => Err(PyValueError::new_err(format!("unknown hpack indexing {other}"))),
    }
}

fn indexing_name(indexing: Indexing) -> &'static str {
    match indexing {
        Indexing::Incremental => "incremental",
        Indexing::WithoutIndexing => "without_indexing",
        Indexing::NeverIndexed => "never_indexed",
    }
}

/**
 * Profile as the dict shape ProfileArg reads, for janus_requests.profile.JanusProfile.from_native().
 */
pub fn profile_dict<'py>(py: Python<'py>, profile: &Profile) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);

    dict.set_item("name", &profile.name)?;
    dict.set_item("tls", tls_dict(py, &profile.tls)?)?;
    dict.set_item("http2", http2_dict(py, &profile.http2)?)?;
    dict.set_item("header_order", profile.header_order.clone())?;
    Ok(dict)
}

pub fn tls_dict<'py>(py: Python<'py>, tls: &TlsProfile) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    let alps = PyList::empty(py);
    let raw_extensions = PyList::empty(py);

    for (proto, settings) in &tls.alps {
        alps.append((proto, PyBytes::new(py, settings)))?;
    }
    for (ext_type, body) in &tls.raw_extensions {
        raw_extensions.append((*ext_type, PyBytes::new(py, body)))?;
    }

    dict.set_item("ciphers", tls.ciphers.clone())?;
    dict.set_item("extensions", tls.extensions.clone())?;
    dict.set_item("groups", tls.groups.clone())?;
    dict.set_item("key_shares", tls.key_shares.clone())?;
    dict.set_item("signature_algorithms", tls.sigalgs.clone())?;
    dict.set_item("versions", tls.versions.clone())?;
    dict.set_item("alpn", tls.alpn.clone())?;
    dict.set_item("alps", alps)?;
    dict.set_item("cert_compression", tls.cert_compression.clone())?;
    dict.set_item("raw_extensions", raw_extensions)?;
    dict.set_item("ocsp", tls.ocsp)?;
    dict.set_item("ech_grease", tls.ech_grease)?;
    dict.set_item("permute_extensions", tls.permute_extensions)?;
    Ok(dict)
}

pub fn http2_dict<'py>(py: Python<'py>, http2: &Http2Profile) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    let priority_frames: Vec<(u32, u32, u16, bool)> = http2
        .priority_frames
        .iter()
        .map(|(id, p)| (*id, p.depends_on, p.weight, p.exclusive))
        .collect();
    let headers_priority = http2.headers_priority.map(|p: StreamPriority| (p.depends_on, p.weight, p.exclusive));
    let priority_mode = match http2.priority_mode {
        PriorityMode::Fixed => "fixed",
        PriorityMode::ChromeTree => "chrome",
    };
    let hpack = match &http2.hpack {
        HpackStyle::Legacy => None,
        HpackStyle::Chrome => Some(hpack_dict(py, &HpackPolicy::chrome())?),
        HpackStyle::Custom(policy) => Some(hpack_dict(py, policy)?),
    };

    dict.set_item("settings", http2.settings.clone())?;
    dict.set_item("window_update", http2.window_update)?;
    dict.set_item("priority_frames", priority_frames)?;
    dict.set_item("pseudo_order", &http2.pseudo_order)?;
    dict.set_item("headers_priority", headers_priority)?;
    dict.set_item("priority_mode", priority_mode)?;
    dict.set_item("hpack", hpack)?;
    Ok(dict)
}

fn hpack_dict<'py>(py: Python<'py>, policy: &HpackPolicy) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    let huffman = match policy.huffman() {
        Huffman::Always => "always",
        Huffman::Never => "never",
        Huffman::IfShorter => "if_shorter",
    };
    let rules: Vec<(String, &str)> = policy
        .rules()
        .map(|(name, indexing)| (String::from_utf8_lossy(name).into_owned(), indexing_name(indexing)))
        .collect();

    dict.set_item("huffman", huffman)?;
    dict.set_item("indexing", indexing_name(policy.default_indexing()))?;
    dict.set_item("rules", rules)?;
    dict.set_item("crumble_cookies", policy.crumbles_cookies())?;
    Ok(dict)
}

/**
 * Built-in profile by name, as a dict.
 */
#[pyfunction]
pub fn builtin_profile<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyDict>> {
    let profile = Profile::named(name).map_err(to_py_err)?;
    profile_dict(py, &profile)
}

/**
 * Parse the line-based TLS spec format into the tls dict.
 */
#[pyfunction]
pub fn tls_from_spec<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    let tls = TlsProfile::from_spec(text).map_err(to_py_err)?;
    tls_dict(py, &tls)
}

/**
 * Parse an Akamai HTTP/2 fingerprint string into the http2 dict (fixed priority, legacy HPACK).
 */
#[pyfunction]
pub fn http2_from_akamai<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    let http2 = Http2Profile::from_akamai(text).map_err(to_py_err)?;
    http2_dict(py, &http2)
}

/**
 * Render a tls dict back into the TLS spec format.
 */
#[pyfunction]
pub fn tls_to_spec(tls: TlsArg) -> String {
    tls.into_tls().to_spec()
}
