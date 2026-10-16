use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Version};
use janus::client::{ClientConfig, HttpVersion, ProxyChoice};
use janus::{
    Body, Client, ClientCert, Error, Proxy, Request, StreamDecoder, StreamPriority, StreamResponse, TlsMode, Upload,
    UploadSender, Verify,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::profile::ProfileArg;

mod profile;

create_exception!(_native, NativeError, PyException);

/**
 * Raise NativeError(kind, message) for the Python layer to translate.
 */
fn to_py_err(e: Error) -> PyErr {
    let kind = match &e {
        Error::Profile(_) => return PyValueError::new_err(e.to_string()),
        Error::Tls(_) => "tls",
        Error::Io(_) => "io",
        Error::Http2(_) => "http2",
        Error::Http(_) => "http",
        Error::Url(_) => "url",
        Error::Protocol(_) => "protocol",
        Error::Proxy(_) => "proxy",
        Error::Timeout(_) => "timeout",
        Error::ConnectTimeout(_) => "connect_timeout",
        Error::ReadTimeout(_) => "read_timeout",
        Error::Connect(_) => "connect",
        Error::Disconnected(_) => "disconnected",
        Error::Body(_) => "body",
        Error::TooManyRedirects(_) => "too_many_redirects",
        Error::Decode(_) => "decode",
    };
    NativeError::new_err((kind, e.to_string()))
}

fn priority_from_tuple(value: (u32, u16, bool)) -> PyResult<StreamPriority> {
    let (depends_on, weight, exclusive) = value;

    if !(1..=256).contains(&weight) {
        return Err(PyValueError::new_err(format!("priority weight {weight} is outside 1..=256")));
    }
    Ok(StreamPriority {
        depends_on,
        weight,
        exclusive,
    })
}

fn seconds(value: Option<f64>) -> PyResult<Option<Duration>> {
    match value {
        None => Ok(None),
        Some(s) => Duration::try_from_secs_f64(s)
            .map(Some)
            .map_err(|_| PyValueError::new_err(format!("invalid timeout {s}"))),
    }
}

/**
 * Body reader state: the wire body plus an optional Content-Encoding decoder.
 */
struct BodyState {
    body: Body,
    content_encoding: String,
    decoder: Option<StreamDecoder>,
    decoder_finished: bool,
}

impl BodyState {
    /**
     * Next non-empty piece of the body, decoded when asked; None at the end.
     */
    async fn next(&mut self, decode: bool) -> janus::Result<Option<Bytes>> {
        loop {
            let raw = self.body.chunk().await?;

            if !decode {
                return Ok(raw);
            }
            if self.decoder.is_none() {
                self.decoder = Some(StreamDecoder::new(&self.content_encoding)?);
            }
            let decoder = self.decoder.as_mut().expect("decoder set above");

            match raw {
                Some(raw) => {
                    let out = decoder.push(&raw)?;
                    if !out.is_empty() {
                        return Ok(Some(Bytes::from(out)));
                    }
                }
                None => {
                    if self.decoder_finished {
                        return Ok(None);
                    }
                    self.decoder_finished = true;

                    let tail = decoder.finish()?;
                    if tail.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(Bytes::from(tail)));
                }
            }
        }
    }

    async fn rest(&mut self, decode: bool) -> janus::Result<Bytes> {
        let mut out = Vec::new();

        while let Some(chunk) = self.next(decode).await? {
            out.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(out))
    }
}

/**
 * Response head plus a body that is read on demand.
 */
#[pyclass(frozen, module = "janus_requests._native")]
pub struct NativeResponse {
    #[pyo3(get)]
    status: u16,
    #[pyo3(get)]
    http_version: &'static str,
    /// urllib3-style integer version: 10, 11 or 20
    #[pyo3(get)]
    version: u16,
    #[pyo3(get)]
    url: String,
    #[pyo3(get)]
    headers: Vec<(String, String)>,
    #[pyo3(get)]
    request_headers: Vec<(String, String)>,
    #[pyo3(get)]
    tls_session_reused: bool,
    state: Arc<Mutex<BodyState>>,
}

impl NativeResponse {
    fn new(response: StreamResponse) -> NativeResponse {
        let (http_version, version) = match response.version {
            Version::HTTP_10 => ("HTTP/1.0", 10),
            Version::HTTP_11 => ("HTTP/1.1", 11),
            Version::HTTP_2 => ("HTTP/2", 20),
            _ => ("HTTP/?", 0),
        };
        let content_encoding = response.header("content-encoding").unwrap_or("").to_string();

        NativeResponse {
            status: response.status,
            http_version,
            version,
            url: response.url.to_string(),
            headers: response.headers,
            request_headers: response.request_headers,
            tls_session_reused: response.tls_resumed,
            state: Arc::new(Mutex::new(BodyState {
                body: response.body,
                content_encoding,
                decoder: None,
                decoder_finished: false,
            })),
        }
    }
}

#[pymethods]
impl NativeResponse {
    /**
     * Next body chunk (blocking, GIL released), or None once the body is complete.
     */
    #[pyo3(signature = (decode = true))]
    fn read_chunk<'py>(&self, py: Python<'py>, decode: bool) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let state = self.state.clone();
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        let chunk = py
            .detach(move || runtime.block_on(async move { state.lock().await.next(decode).await }))
            .map_err(to_py_err)?;
        Ok(chunk.map(|c| PyBytes::new(py, &c)))
    }

    /**
     * The rest of the body (blocking, GIL released).
     */
    #[pyo3(signature = (decode = true))]
    fn read_all<'py>(&self, py: Python<'py>, decode: bool) -> PyResult<Bound<'py, PyBytes>> {
        let state = self.state.clone();
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        let data = py
            .detach(move || runtime.block_on(async move { state.lock().await.rest(decode).await }))
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    /**
     * Awaitable version of read_chunk.
     */
    #[pyo3(signature = (decode = true))]
    fn read_chunk_async<'py>(&self, py: Python<'py>, decode: bool) -> PyResult<Bound<'py, PyAny>> {
        let state = self.state.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let chunk = state.lock().await.next(decode).await.map_err(to_py_err)?;
            Ok(chunk.map(|c| Python::attach(|py| PyBytes::new(py, &c).unbind())))
        })
    }

    /**
     * Awaitable version of read_all.
     */
    #[pyo3(signature = (decode = true))]
    fn read_all_async<'py>(&self, py: Python<'py>, decode: bool) -> PyResult<Bound<'py, PyAny>> {
        let state = self.state.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let data = state.lock().await.rest(decode).await.map_err(to_py_err)?;
            Ok(Python::attach(|py| PyBytes::new(py, &data).unbind()))
        })
    }

    /**
     * Abandon the rest of the body; an unfinished HTTP/1 connection is closed, an h2 stream is reset.
     */
    fn close(&self, py: Python<'_>) {
        let state = self.state.clone();
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        py.detach(move || {
            runtime.block_on(async move {
                let mut state = state.lock().await;
                state.body = Body::empty();
            })
        });
    }

    #[getter]
    fn is_done(&self) -> bool {
        match self.state.try_lock() {
            Ok(state) => state.body.is_done(),
            Err(_) => false,
        }
    }
}

/**
 * Per-request options shared by the blocking and async entry points.
 */
struct Options {
    connect_timeout: Option<f64>,
    read_timeout: Option<f64>,
    verify: VerifyArg,
    cert: Option<CertArg>,
    proxy: Option<String>,
    priority: Option<(u32, u16, bool)>,
    header_order: Option<Vec<String>>,
}

#[derive(FromPyObject)]
enum VerifyArg {
    Flag(bool),
    Path(PathBuf),
}

#[derive(FromPyObject)]
enum CertArg {
    Pair(PathBuf, PathBuf),
    Single(PathBuf),
}

fn build_request(method: &str, url: &str, headers: Vec<(String, String)>, body: Option<Vec<u8>>, opts: Options) -> PyResult<Request> {
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|_| PyValueError::new_err(format!("bad http method {method}")))?;
    let mut request = Request::new(method, url).map_err(to_py_err)?;

    let verify = match opts.verify {
        VerifyArg::Flag(true) => Verify::System,
        VerifyArg::Flag(false) => Verify::Off,
        VerifyArg::Path(path) => Verify::CaBundle(path),
    };
    let client_cert = opts.cert.map(|cert| match cert {
        CertArg::Pair(cert, key) => ClientCert { cert, key: Some(key) },
        CertArg::Single(cert) => ClientCert { cert, key: None },
    });

    request.headers = headers.into_iter().map(|(n, v)| (n, Some(v))).collect();
    request.body = body.map(Bytes::from);
    request.connect_timeout = seconds(opts.connect_timeout)?;
    request.read_timeout = seconds(opts.read_timeout)?;
    request.tls = Some(TlsMode { verify, client_cert });
    request.proxy = match opts.proxy {
        Some(url) => ProxyChoice::Via(Proxy::parse(&url).map_err(to_py_err)?),
        None => ProxyChoice::Direct,
    };
    request.priority = opts.priority.map(priority_from_tuple).transpose()?;
    request.header_order = opts
        .header_order
        .map(|order| order.iter().map(|n| n.to_ascii_lowercase()).collect());
    Ok(request)
}

/**
 * Connection pool and TLS session cache for one identity profile; sends single exchanges.
 */
#[pyclass(frozen, module = "janus_requests._native")]
pub struct NativeClient {
    client: Client,
}

#[pymethods]
impl NativeClient {
    #[new]
    #[pyo3(signature = (profile, *, http_version = "auto"))]
    fn new(profile: ProfileArg, http_version: &str) -> PyResult<NativeClient> {
        let profile = profile.into_profile()?;

        let mut config = ClientConfig::new(profile);
        config.timeout = None;
        config.connect_timeout = None;
        config.read_timeout = None;
        config.follow_redirects = false;
        config.cookies = false;
        config.http_version = match http_version {
            "auto" => HttpVersion::Auto,
            "1.1" | "http1" => HttpVersion::Http1,
            "2" | "http2" => HttpVersion::Http2,
            other => return Err(PyValueError::new_err(format!("unknown http_version {other}"))),
        };

        let client = Client::new(config).map_err(to_py_err)?;
        Ok(NativeClient { client })
    }

    /**
     * Send one request and block until the response head arrives; the GIL is released meanwhile.
     */
    #[pyo3(signature = (
        method,
        url,
        headers,
        body = None,
        *,
        connect_timeout = None,
        read_timeout = None,
        verify = VerifyArg::Flag(true),
        cert = None,
        proxy = None,
        priority = None,
        header_order = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        connect_timeout: Option<f64>,
        read_timeout: Option<f64>,
        verify: VerifyArg,
        cert: Option<CertArg>,
        proxy: Option<String>,
        priority: Option<(u32, u16, bool)>,
        header_order: Option<Vec<String>>,
    ) -> PyResult<NativeResponse> {
        let opts = Options {
            connect_timeout,
            read_timeout,
            verify,
            cert,
            proxy,
            priority,
            header_order,
        };
        let request = build_request(method, url, headers, body, opts)?;
        let client = self.client.clone();
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        let response = py.detach(move || runtime.block_on(async move { client.send(&request).await }));

        response.map(NativeResponse::new).map_err(to_py_err)
    }

    /**
     * Same as `request`, returning an awaitable for asyncio.
     */
    #[pyo3(signature = (
        method,
        url,
        headers,
        body = None,
        *,
        connect_timeout = None,
        read_timeout = None,
        verify = VerifyArg::Flag(true),
        cert = None,
        proxy = None,
        priority = None,
        header_order = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request_async<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        connect_timeout: Option<f64>,
        read_timeout: Option<f64>,
        verify: VerifyArg,
        cert: Option<CertArg>,
        proxy: Option<String>,
        priority: Option<(u32, u16, bool)>,
        header_order: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let opts = Options {
            connect_timeout,
            read_timeout,
            verify,
            cert,
            proxy,
            priority,
            header_order,
        };
        let request = build_request(method, url, headers, body, opts)?;
        let client = self.client.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let response = client.send(&request).await.map_err(to_py_err)?;
            Ok(NativeResponse::new(response))
        })
    }

    /**
     * Drop pooled connections; cached TLS sessions survive.
     */
    fn close(&self) {
        self.client.close();
    }

    fn clear_tls_sessions(&self) {
        self.client.clear_tls_sessions();
    }

    /**
     * Start a request whose body is written piece by piece through the returned NativeUpload.
     */
    #[pyo3(signature = (
        method,
        url,
        headers,
        *,
        body_length = None,
        connect_timeout = None,
        read_timeout = None,
        verify = VerifyArg::Flag(true),
        cert = None,
        proxy = None,
        priority = None,
        header_order = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn start(
        &self,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body_length: Option<u64>,
        connect_timeout: Option<f64>,
        read_timeout: Option<f64>,
        verify: VerifyArg,
        cert: Option<CertArg>,
        proxy: Option<String>,
        priority: Option<(u32, u16, bool)>,
        header_order: Option<Vec<String>>,
    ) -> PyResult<NativeUpload> {
        let opts = Options {
            connect_timeout,
            read_timeout,
            verify,
            cert,
            proxy,
            priority,
            header_order,
        };
        let request = build_request(method, url, headers, None, opts)?;
        let client = self.client.clone();
        let (sender, upload) = Upload::channel(body_length);
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        let task = runtime.spawn(async move { client.send_upload(&request, upload).await });

        Ok(NativeUpload {
            sender: std::sync::Mutex::new(Some(sender)),
            task: std::sync::Mutex::new(Some(task)),
        })
    }
}

/**
 * A request in flight whose body the caller is still writing; dropping it unfinished aborts the request.
 */
#[pyclass(frozen, module = "janus_requests._native")]
pub struct NativeUpload {
    sender: std::sync::Mutex<Option<UploadSender>>,
    task: std::sync::Mutex<Option<JoinHandle<janus::Result<StreamResponse>>>>,
}

impl NativeUpload {
    fn sender(&self) -> Option<UploadSender> {
        self.sender.lock().expect("upload sender lock").clone()
    }

    fn take_task(&self) -> PyResult<JoinHandle<janus::Result<StreamResponse>>> {
        self.task
            .lock()
            .expect("upload task lock")
            .take()
            .ok_or_else(|| PyValueError::new_err("response was already taken"))
    }
}

/**
 * Turn the finished request task into a NativeResponse.
 */
fn joined(result: Result<janus::Result<StreamResponse>, tokio::task::JoinError>) -> PyResult<NativeResponse> {
    let response = result.map_err(|e| to_py_err(Error::Body(format!("request task failed: {e}"))))?;
    response.map(NativeResponse::new).map_err(to_py_err)
}

#[pymethods]
impl NativeUpload {
    /**
     * Send one body chunk (blocking, GIL released); False once the request stopped reading the body.
     */
    fn write(&self, py: Python<'_>, chunk: Vec<u8>) -> bool {
        let Some(sender) = self.sender() else {
            return false;
        };
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        py.detach(move || runtime.block_on(sender.send(Bytes::from(chunk))))
    }

    /**
     * Awaitable version of write.
     */
    fn write_async<'py>(&self, py: Python<'py>, chunk: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let sender = self.sender();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match sender {
                Some(sender) => Ok(sender.send(Bytes::from(chunk)).await),
                None => Ok(false),
            }
        })
    }

    /**
     * End the body normally.
     */
    fn finish(&self) {
        if let Some(sender) = self.sender.lock().expect("upload sender lock").take() {
            sender.finish();
        }
    }

    /**
     * Abandon the request: the body is cut off and the connection is not reused.
     */
    fn abort(&self) {
        self.sender.lock().expect("upload sender lock").take();
        if let Some(task) = self.task.lock().expect("upload task lock").take() {
            task.abort();
        }
    }

    /**
     * Wait for the response head (blocking, GIL released); ends the body first if it is still open.
     */
    fn response(&self, py: Python<'_>) -> PyResult<NativeResponse> {
        self.finish();
        let task = self.take_task()?;
        let runtime = pyo3_async_runtimes::tokio::get_runtime();

        joined(py.detach(move || runtime.block_on(task)))
    }

    /**
     * Awaitable version of response.
     */
    fn response_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.finish();
        let task = self.take_task()?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move { joined(task.await) })
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeClient>()?;
    m.add_class::<NativeResponse>()?;
    m.add_class::<NativeUpload>()?;
    m.add_function(wrap_pyfunction!(profile::builtin_profile, m)?)?;
    m.add_function(wrap_pyfunction!(profile::tls_from_spec, m)?)?;
    m.add_function(wrap_pyfunction!(profile::tls_to_spec, m)?)?;
    m.add_function(wrap_pyfunction!(profile::http2_from_akamai, m)?)?;
    m.add("NativeError", m.py().get_type::<NativeError>())?;
    m.add("GREASE", janus::GREASE)?;
    Ok(())
}
