//! C ABI over the Janus client and the capture server, for hosts that must not link OpenSSL themselves.
//!
//! Every JSON in and out is UTF-8. Buffers returned by this library are released with `janus_buffer_free`.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use janus::{Client, ClientConfig, Error, Profile, Proxy, Request, TlsMode, Verify};
use janus_capture::{CaptureConfig, CaptureServer, CaptureView};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/**
 * Bytes owned by this library.
 */
#[repr(C)]
pub struct JanusBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/**
 * Completion callback of janus_send; the pointers are only valid during the call.
 *
 * `ok` is 1 with the response head JSON and the body, or 0 with an error JSON and an empty body.
 */
pub type JanusDone =
    extern "C" fn(ctx: *mut c_void, ok: i32, head: *const u8, head_len: usize, body: *const u8, body_len: usize);

/**
 * A client bound to one profile, with its connection pool and in-flight requests.
 */
pub struct JanusClient {
    client: Client,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<()>>>>,
    next_id: AtomicU64,
}

/**
 * A running capture server.
 */
pub struct JanusCapture {
    view: CaptureView,
    task: JoinHandle<()>,
}

#[derive(Deserialize)]
struct ClientArgs {
    profile: Value,
    proxy: Option<String>,
    timeout_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
    #[serde(default = "verify_default")]
    verify: bool,
}

fn verify_default() -> bool {
    true
}

#[derive(Deserialize)]
struct RequestArgs {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    header_order: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct CaptureArgs {
    listen: String,
    name: String,
    cert_pem: String,
    key_pem: String,
    rounds: u32,
}

/// raw context pointer carried to the runtime thread that calls back
struct Ctx(*mut c_void);

unsafe impl Send for Ctx {}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();

    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("janus")
            .build()
            .expect("start the janus runtime")
    })
}

fn buffer(data: Vec<u8>) -> JanusBuffer {
    let mut data = data.into_boxed_slice();
    let out = JanusBuffer {
        ptr: data.as_mut_ptr(),
        len: data.len(),
    };
    std::mem::forget(data);
    out
}

fn empty() -> JanusBuffer {
    JanusBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

fn error_json(kind: &str, message: &str) -> Vec<u8> {
    json!({"kind": kind, "message": message}).to_string().into_bytes()
}

/**
 * Stable name of a client error, for the host to decide on retries.
 */
fn error_kind(e: &Error) -> &'static str {
    match e {
        Error::Profile(_) => "profile",
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
    }
}

/// # Safety
/// `ptr` must point at `len` readable bytes (or be null with `len` 0).
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// # Safety
/// `out` must be null or point at a writable JanusBuffer.
unsafe fn set_error(out: *mut JanusBuffer, kind: &str, message: &str) {
    if !out.is_null() {
        unsafe { *out = buffer(error_json(kind, message)) };
    }
}

/**
 * ABI revision; a host refuses a library whose revision it was not built for.
 */
#[unsafe(no_mangle)]
pub extern "C" fn janus_abi_version() -> u32 {
    1
}

/**
 * Release a buffer returned by this library.
 */
#[unsafe(no_mangle)]
pub extern "C" fn janus_buffer_free(buf: JanusBuffer) {
    if buf.ptr.is_null() {
        return;
    }
    // SAFETY: ptr/len came from buffer(), which leaked a boxed slice of exactly this size
    unsafe { drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len))) };
}

/**
 * Built-in profiles as JSON: [{"name": ..., "profile": {...}}].
 */
#[unsafe(no_mangle)]
pub extern "C" fn janus_builtin_profiles() -> JanusBuffer {
    let list: Vec<Value> = ["chrome155"]
        .iter()
        .map(|name| {
            let profile = Profile::named(name).expect("built-in profile exists");
            json!({"name": name, "profile": profile.to_json_value()})
        })
        .collect();

    buffer(Value::Array(list).to_string().into_bytes())
}

/**
 * Validate a profile JSON; returns {"name", "akamai"} or {"kind": "profile", "message"} in `out`, 0 when valid.
 *
 * # Safety
 * `json`/`len` must describe readable bytes; `out` must point at a writable JanusBuffer.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_profile_check(json: *const u8, len: usize, out: *mut JanusBuffer) -> i32 {
    let text = String::from_utf8_lossy(unsafe { slice(json, len) }).into_owned();

    match Profile::from_json(&text) {
        Ok(profile) => {
            let summary = json!({"name": profile.name, "akamai": profile.http2.akamai()});
            unsafe { *out = buffer(summary.to_string().into_bytes()) };
            0
        }
        Err(e) => {
            unsafe { set_error(out, "profile", &e.to_string()) };
            1
        }
    }
}

/**
 * Create a client from {"profile", "proxy", "timeout_ms", "connect_timeout_ms", "verify"}; 0 on success.
 *
 * # Safety
 * `config`/`len` must describe readable bytes; `client_out` and `error_out` must be writable.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_client_new(
    config: *const u8,
    len: usize,
    client_out: *mut *mut JanusClient,
    error_out: *mut JanusBuffer,
) -> i32 {
    let bytes = unsafe { slice(config, len) };

    match catch_unwind(|| build_client(bytes)) {
        Ok(Ok(client)) => {
            unsafe { *client_out = Box::into_raw(Box::new(client)) };
            0
        }
        Ok(Err((kind, message))) => {
            unsafe { set_error(error_out, kind, &message) };
            1
        }
        Err(_) => {
            unsafe { set_error(error_out, "panic", "janus_client_new panicked") };
            1
        }
    }
}

fn build_client(bytes: &[u8]) -> Result<JanusClient, (&'static str, String)> {
    let args: ClientArgs =
        serde_json::from_slice(bytes).map_err(|e| ("invalid_argument", format!("client config: {e}")))?;
    let profile = Profile::from_json_value(args.profile).map_err(|e| ("profile", e.to_string()))?;

    let mut config = ClientConfig::new(profile);
    config.timeout = args.timeout_ms.map(Duration::from_millis);
    config.connect_timeout = args.connect_timeout_ms.map(Duration::from_millis);
    // a forwarding host relays redirects, cookies and encoded bodies unchanged
    config.follow_redirects = false;
    config.cookies = false;
    config.decompress = false;
    config.tls = TlsMode {
        verify: if args.verify { Verify::System } else { Verify::Off },
        client_cert: None,
    };
    if let Some(url) = args.proxy.filter(|p| !p.is_empty()) {
        config.proxy = Some(Proxy::parse(&url).map_err(|e| ("proxy", e.to_string()))?);
    }

    let client = Client::new(config).map_err(|e| (error_kind(&e), e.to_string()))?;

    Ok(JanusClient {
        client,
        pending: Arc::new(Mutex::new(HashMap::new())),
        next_id: AtomicU64::new(1),
    })
}

/**
 * Release a client; requests still in flight finish on their own.
 *
 * # Safety
 * `client` must come from janus_client_new and not be used afterwards.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_client_free(client: *mut JanusClient) {
    if !client.is_null() {
        unsafe { drop(Box::from_raw(client)) };
    }
}

/**
 * Send {"method", "url", "headers", "header_order"} with `body`; `done` is called exactly once. Returns the request id.
 *
 * # Safety
 * `client` must be live; the request and body buffers are copied before this returns.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_send(
    client: *const JanusClient,
    request: *const u8,
    request_len: usize,
    body: *const u8,
    body_len: usize,
    done: JanusDone,
    ctx: *mut c_void,
) -> u64 {
    let handle = unsafe { &*client };
    let request = unsafe { slice(request, request_len) }.to_vec();
    let body = Bytes::copy_from_slice(unsafe { slice(body, body_len) });
    let ctx = Ctx(ctx);

    let id = handle.next_id.fetch_add(1, Ordering::Relaxed);
    let (cancel_tx, cancel_rx) = oneshot::channel();
    handle.pending.lock().expect("pending lock").insert(id, cancel_tx);

    let pending = handle.pending.clone();
    let janus = handle.client.clone();
    runtime().spawn(async move {
        let work = tokio::spawn(exchange(janus, request, body));
        let outcome = tokio::select! {
            joined = work => match joined {
                Ok(result) => result,
                Err(e) => Err(error_json("panic", &format!("request task failed: {e}"))),
            },
            _ = cancel_rx => Err(error_json("cancelled", "cancelled by the host")),
        };
        pending.lock().expect("pending lock").remove(&id);

        let ctx = ctx;
        match outcome {
            Ok((head, body)) => done(ctx.0, 1, head.as_ptr(), head.len(), body.as_ptr(), body.len()),
            Err(error) => done(ctx.0, 0, error.as_ptr(), error.len(), std::ptr::null(), 0),
        }
    });
    id
}

async fn exchange(client: Client, request: Vec<u8>, body: Bytes) -> Result<(Vec<u8>, Bytes), Vec<u8>> {
    let args: RequestArgs =
        serde_json::from_slice(&request).map_err(|e| error_json("invalid_argument", &format!("request: {e}")))?;
    let method = http::Method::from_bytes(args.method.as_bytes())
        .map_err(|e| error_json("invalid_argument", &format!("method {}: {e}", args.method)))?;
    let mut req = Request::new(method, &args.url).map_err(|e| error_json(error_kind(&e), &e.to_string()))?;

    req.headers = args.headers.into_iter().map(|(n, v)| (n, Some(v))).collect();
    req.header_order = args.header_order;
    if !body.is_empty() {
        req.body = Some(body);
    }

    let started = Instant::now();
    let response = client
        .execute(req)
        .await
        .map_err(|e| error_json(error_kind(&e), &e.to_string()))?;

    let head = json!({
        "status": response.status,
        "version": format!("{:?}", response.version),
        "url": response.url.as_str(),
        "headers": response.headers,
        "request_headers": response.request_headers,
        "tls_resumed": response.tls_resumed,
        "elapsed_ms": started.elapsed().as_millis() as u64,
    });
    Ok((head.to_string().into_bytes(), response.body))
}

/**
 * Cancel an in-flight request; its callback reports kind "cancelled". Unknown ids are ignored.
 *
 * # Safety
 * `client` must be live.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_cancel(client: *const JanusClient, id: u64) {
    let handle = unsafe { &*client };
    let sender = handle.pending.lock().expect("pending lock").remove(&id);

    if let Some(sender) = sender {
        let _ = sender.send(());
    }
}

/**
 * Start a capture server from {"listen", "name", "cert_pem", "key_pem", "rounds"}; 0 on success.
 *
 * # Safety
 * `config`/`len` must describe readable bytes; `capture_out` and `error_out` must be writable.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_capture_start(
    config: *const u8,
    len: usize,
    capture_out: *mut *mut JanusCapture,
    error_out: *mut JanusBuffer,
) -> i32 {
    let bytes = unsafe { slice(config, len) };

    match catch_unwind(AssertUnwindSafe(|| start_capture(bytes))) {
        Ok(Ok(capture)) => {
            unsafe { *capture_out = Box::into_raw(Box::new(capture)) };
            0
        }
        Ok(Err(message)) => {
            unsafe { set_error(error_out, "capture", &message) };
            1
        }
        Err(_) => {
            unsafe { set_error(error_out, "panic", "janus_capture_start panicked") };
            1
        }
    }
}

fn start_capture(bytes: &[u8]) -> Result<JanusCapture, String> {
    let args: CaptureArgs = serde_json::from_slice(bytes).map_err(|e| format!("capture config: {e}"))?;
    let listen: SocketAddr = args.listen.parse().map_err(|e| format!("listen {}: {e}", args.listen))?;
    let config = CaptureConfig {
        listen,
        name: args.name,
        cert_pem: args.cert_pem.into_bytes(),
        key_pem: args.key_pem.into_bytes(),
        rounds: args.rounds,
    };

    let server = runtime().block_on(CaptureServer::bind(config))?;
    let view = server.view();
    let task = runtime().spawn(server.run());
    Ok(JanusCapture { view, task })
}

/**
 * Current state of a capture server as JSON: {"listen", "name", "captures": [...], "log": [...]}.
 *
 * # Safety
 * `capture` must be live.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_capture_snapshot(capture: *const JanusCapture) -> JanusBuffer {
    let handle = unsafe { &*capture };

    match serde_json::to_vec(&handle.view.snapshot()) {
        Ok(data) => buffer(data),
        Err(_) => empty(),
    }
}

/**
 * Stop a capture server, close its connections and release it.
 *
 * # Safety
 * `capture` must come from janus_capture_start and not be used afterwards.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn janus_capture_stop(capture: *mut JanusCapture) {
    if capture.is_null() {
        return;
    }
    let handle = unsafe { Box::from_raw(capture) };
    handle.task.abort();
}
