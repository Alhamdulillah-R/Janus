use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cookie_store::CookieStore;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, Version};
use janus_h2::client::ResponseFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::Url;

use crate::body::Body;
use crate::decode::decode_body;
use crate::error::{Error, Result};
use crate::http1::H1Connection;
use crate::http2::{H2Connection, StreamPriority};
use crate::profile::{Profile, assemble_headers};
use crate::proxy::{Proxy, ProxyKind};
use crate::tls::{TlsConnector, TlsMode, negotiated_alpn};
use crate::upload::{Outgoing, Upload};

/**
 * Byte stream the client can speak HTTP over.
 */
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

pub(crate) type BoxIo = Box<dyn Io>;

/**
 * Which HTTP version the client may use.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpVersion {
    /// whatever ALPN negotiates from the profile's offer
    Auto,
    /// offer only http/1.1 in ALPN
    Http1,
    /// require h2
    Http2,
}

/**
 * Client-wide settings; each one can be overridden per request where Request has a matching field.
 */
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub profile: Profile,
    pub tls: TlsMode,
    pub proxy: Option<Proxy>,
    /// whole exchange including redirects, `execute` only
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    /// longest wait for the response head or for the next body chunk
    pub read_timeout: Option<Duration>,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub http_version: HttpVersion,
    pub cookies: bool,
    pub decompress: bool,
}

impl ClientConfig {
    pub fn new(profile: Profile) -> ClientConfig {
        ClientConfig {
            profile,
            tls: TlsMode::default(),
            proxy: None,
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: None,
            follow_redirects: true,
            max_redirects: 30,
            http_version: HttpVersion::Auto,
            cookies: true,
            decompress: true,
        }
    }
}

/**
 * Proxy selection for one request.
 */
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxyChoice {
    /// the client's configured proxy
    #[default]
    Default,
    Direct,
    Via(Proxy),
}

/**
 * One request; `None` header values delete automatic headers (Host, Content-Length, Cookie).
 */
#[derive(Clone, Debug)]
pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(String, Option<String>)>,
    pub body: Option<Bytes>,
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub priority: Option<StreamPriority>,
    pub header_order: Option<Vec<String>>,
    pub follow_redirects: Option<bool>,
    /// cookies sent with this request only, after the jar's
    pub extra_cookies: Vec<(String, String)>,
    pub proxy: ProxyChoice,
    pub tls: Option<TlsMode>,
}

impl Request {
    pub fn new(method: Method, url: &str) -> Result<Request> {
        let url = Url::parse(url).map_err(|e| Error::Url(format!("{url}: {e}")))?;

        Ok(Request {
            method,
            url,
            headers: Vec::new(),
            body: None,
            timeout: None,
            connect_timeout: None,
            read_timeout: None,
            priority: None,
            header_order: None,
            follow_redirects: None,
            extra_cookies: Vec::new(),
            proxy: ProxyChoice::Default,
            tls: None,
        })
    }
}

/**
 * Response head with a body still to be read.
 */
pub struct StreamResponse {
    pub status: u16,
    pub version: Version,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    /// headers as they went on the wire, in order
    pub request_headers: Vec<(String, String)>,
    pub tls_resumed: bool,
    pub body: Body,
}

impl StreamResponse {
    /**
     * First value of a header, case-insensitive.
     */
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

/**
 * A fully read and decoded response.
 */
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub version: Version,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub request_headers: Vec<(String, String)>,
    pub tls_resumed: bool,
    pub body: Bytes,
    pub history: Vec<(u16, String)>,
    pub elapsed: Duration,
}

impl Response {
    /**
     * First value of a header, case-insensitive.
     */
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

enum Conn {
    H1(H1Connection<BoxIo>),
    H2(H2Connection),
}

#[derive(Default)]
pub(crate) struct Pool {
    h2: HashMap<String, H2Connection>,
    h1: HashMap<String, Vec<H1Connection<BoxIo>>>,
}

/**
 * Where a finished HTTP/1 connection goes back to.
 */
pub(crate) struct PoolReturn {
    pool: Arc<Mutex<Pool>>,
    key: String,
}

impl PoolReturn {
    pub(crate) fn put(self, conn: H1Connection<BoxIo>) {
        self.pool
            .lock()
            .expect("pool lock")
            .h1
            .entry(self.key)
            .or_default()
            .push(conn);
    }
}

struct ClientInner {
    config: ClientConfig,
    tls: TlsConnector,
    pool: Arc<Mutex<Pool>>,
    jar: Mutex<CookieStore>,
}

/**
 * HTTP client with a fixed identity profile, connection pool, TLS session cache and cookie jar.
 */
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

/**
 * Where one request goes and over which kind of connection.
 */
struct Route {
    scheme: String,
    host: String,
    port: u16,
    proxy: Option<Proxy>,
    tls: TlsMode,
    key: String,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Client> {
        config.profile.http2.validate()?;
        let mut tls_profile = config.profile.tls.clone();

        match config.http_version {
            HttpVersion::Auto => {}
            HttpVersion::Http1 => tls_profile.alpn = vec!["http/1.1".into()],
            HttpVersion::Http2 => tls_profile.alpn = vec!["h2".into()],
        }
        let tls = TlsConnector::new(&tls_profile)?;

        Ok(Client {
            inner: Arc::new(ClientInner {
                config,
                tls,
                pool: Arc::new(Mutex::new(Pool::default())),
                jar: Mutex::new(CookieStore::new()),
            }),
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.inner.config
    }

    /**
     * Cookies currently stored for a URL as (name, value) pairs.
     */
    pub fn cookies_for(&self, url: &str) -> Result<Vec<(String, String)>> {
        let url = Url::parse(url).map_err(|e| Error::Url(format!("{url}: {e}")))?;
        let jar = self.inner.jar.lock().expect("cookie jar lock");

        Ok(jar
            .get_request_values(&url)
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect())
    }

    /**
     * Store a Set-Cookie style string as if `url` had sent it.
     */
    pub fn set_cookie(&self, url: &str, set_cookie: &str) -> Result<()> {
        let url = Url::parse(url).map_err(|e| Error::Url(format!("{url}: {e}")))?;
        let mut jar = self.inner.jar.lock().expect("cookie jar lock");

        jar.parse(set_cookie, &url)
            .map_err(|e| Error::Protocol(format!("bad cookie {set_cookie:?}: {e}")))?;
        Ok(())
    }

    pub fn clear_cookies(&self) {
        self.inner.jar.lock().expect("cookie jar lock").clear();
    }

    /**
     * Drop every pooled connection; cached TLS sessions are kept.
     */
    pub fn close(&self) {
        let mut pool = self.inner.pool.lock().expect("pool lock");
        pool.h1.clear();
        pool.h2.clear();
    }

    /**
     * Forget cached TLS sessions so the next connections do full handshakes.
     */
    pub fn clear_tls_sessions(&self) {
        self.inner.tls.clear_sessions();
    }

    /**
     * Send a request, follow redirects as configured and read the whole decoded body.
     */
    pub async fn execute(&self, request: Request) -> Result<Response> {
        let timeout = request.timeout.or(self.inner.config.timeout);
        let label = format!("{} {}", request.method, request.url);
        let run = self.execute_inner(request);

        match timeout {
            Some(limit) => tokio::time::timeout(limit, run)
                .await
                .map_err(|_| Error::Timeout(format!("{label} after {limit:?}")))?,
            None => run.await,
        }
    }

    async fn execute_inner(&self, request: Request) -> Result<Response> {
        let started = Instant::now();
        let follow = request.follow_redirects.unwrap_or(self.inner.config.follow_redirects);
        let mut request = request;
        let mut history = Vec::new();

        loop {
            let response = self.send(&request).await?;

            if follow && matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                if let Some(location) = response.header("location").map(str::to_string) {
                    if history.len() >= self.inner.config.max_redirects {
                        return Err(Error::TooManyRedirects(history.len()));
                    }
                    // drained so an HTTP/1 connection can be reused
                    response.body.collect().await?;
                    history.push((response.status, request.url.to_string()));
                    request = redirect_request(request, response.status, &location)?;
                    continue;
                }
            }

            let encoding = response.header("content-encoding").map(str::to_string);
            let raw = response.body.collect().await?;
            let body = match encoding {
                Some(coding) if self.inner.config.decompress => decode_body(&coding, raw)?,
                _ => raw,
            };

            return Ok(Response {
                status: response.status,
                version: response.version,
                url: request.url,
                headers: response.headers,
                request_headers: response.request_headers,
                tls_resumed: response.tls_resumed,
                body,
                history,
                elapsed: started.elapsed(),
            });
        }
    }

    /**
     * One request/response exchange; returns once the response head is in.
     */
    pub async fn send(&self, request: &Request) -> Result<StreamResponse> {
        self.send_with(request, None).await
    }

    /**
     * Like `send`, with the body streamed from `upload` instead of `request.body`.
     */
    pub async fn send_upload(&self, request: &Request, upload: Upload) -> Result<StreamResponse> {
        self.send_with(request, Some(upload)).await
    }

    async fn send_with(&self, request: &Request, upload: Option<Upload>) -> Result<StreamResponse> {
        let config = &self.inner.config;
        let route = self.route(request)?;
        let connect_timeout = request.connect_timeout.or(config.connect_timeout);
        let read_timeout = request.read_timeout.or(config.read_timeout);

        let conn = match self.pooled(&route) {
            Some(conn) => conn,
            None => {
                let connect = self.connect(&route);
                match connect_timeout {
                    Some(limit) => tokio::time::timeout(limit, connect)
                        .await
                        .map_err(|_| Error::ConnectTimeout(format!("{}:{} after {limit:?}", route.host, route.port)))??,
                    None => connect.await?,
                }
            }
        };

        let outgoing = match (upload, &request.body) {
            (Some(upload), _) => Outgoing::Stream(upload),
            (None, Some(data)) if !data.is_empty() => Outgoing::Bytes(data.clone()),
            (None, _) => Outgoing::Empty,
        };

        let response = match conn {
            Conn::H2(h2) => {
                self.inner
                    .pool
                    .lock()
                    .expect("pool lock")
                    .h2
                    .insert(route.key.clone(), h2.clone());
                self.send_h2(&h2, request, outgoing, read_timeout).await?
            }
            Conn::H1(h1) => self.send_h1(h1, request, outgoing, &route, read_timeout).await?,
        };

        if config.cookies {
            self.store_cookies(&request.url, &response.headers);
        }
        Ok(response)
    }

    fn route(&self, request: &Request) -> Result<Route> {
        let url = &request.url;
        let scheme = url.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(Error::Url(format!("unsupported scheme {scheme}")));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::Url(format!("{url} has no host")))?
            .trim_matches(['[', ']'])
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::Url(format!("{url} has no port")))?;
        let proxy = match &request.proxy {
            ProxyChoice::Default => self.inner.config.proxy.clone(),
            ProxyChoice::Direct => None,
            ProxyChoice::Via(proxy) => Some(proxy.clone()),
        };
        let tls = request.tls.clone().unwrap_or_else(|| self.inner.config.tls.clone());
        let key = format!("{scheme}://{host}:{port}|{proxy:?}|{tls:?}");

        Ok(Route {
            scheme,
            host,
            port,
            proxy,
            tls,
            key,
        })
    }

    fn pooled(&self, route: &Route) -> Option<Conn> {
        let mut pool = self.inner.pool.lock().expect("pool lock");

        pool.h2.retain(|_, c| c.is_open());
        if let Some(h2) = pool.h2.get(&route.key) {
            return Some(Conn::H2(h2.clone()));
        }

        let idle = pool.h1.get_mut(&route.key)?;
        while let Some(mut conn) = idle.pop() {
            if conn.is_reusable() {
                return Some(Conn::H1(conn));
            }
        }
        None
    }

    /**
     * Open a new connection (direct or via proxy), run TLS for https and pick the protocol from ALPN.
     */
    async fn connect(&self, route: &Route) -> Result<Conn> {
        let config = &self.inner.config;
        let tcp = match &route.proxy {
            Some(proxy) if route.scheme == "http" && proxy.kind == ProxyKind::Http => proxy.connect_direct().await?,
            Some(proxy) => proxy.tunnel(&route.host, route.port).await?,
            None => {
                let stream = TcpStream::connect((route.host.as_str(), route.port))
                    .await
                    .map_err(|e| Error::Connect(format!("{}:{}: {e}", route.host, route.port)))?;
                stream.set_nodelay(true)?;
                stream
            }
        };

        if route.scheme == "http" {
            return Ok(Conn::H1(H1Connection::new(Box::new(tcp), false)));
        }

        let tls = self.inner.tls.connect(&route.host, route.port, &route.tls, tcp).await?;
        let alpn = negotiated_alpn(&tls.stream);

        if alpn.as_deref() == Some(b"h2".as_slice()) {
            let h2 = H2Connection::handshake(tls.stream, &config.profile.http2, tls.resumed).await?;
            return Ok(Conn::H2(h2));
        }
        if config.http_version == HttpVersion::Http2 {
            return Err(Error::Protocol(format!("{} did not negotiate h2", route.host)));
        }
        Ok(Conn::H1(H1Connection::new(Box::new(tls.stream), tls.resumed)))
    }

    fn store_cookies(&self, url: &Url, headers: &[(String, String)]) {
        let mut jar = self.inner.jar.lock().expect("cookie jar lock");

        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            if let Err(e) = jar.parse(value, url) {
                log::debug!("ignored set-cookie {value:?} from {url}: {e}");
            }
        }
    }

    /**
     * Final header list for a request, before protocol-specific shaping.
     */
    fn request_headers(&self, request: &Request, outgoing: &Outgoing, for_h1: bool) -> Vec<(String, String)> {
        let config = &self.inner.config;
        let profile = &config.profile;
        let url = &request.url;
        let mut automatic = Vec::new();

        if for_h1 {
            automatic.push(("Host".to_string(), host_header(url)));
        }

        let needs_length = matches!(request.method, Method::POST | Method::PUT | Method::PATCH);
        match outgoing {
            Outgoing::Bytes(data) => automatic.push(("Content-Length".to_string(), data.len().to_string())),
            Outgoing::Stream(upload) => match upload.length() {
                Some(len) => automatic.push(("Content-Length".to_string(), len.to_string())),
                None if for_h1 => automatic.push(("Transfer-Encoding".to_string(), "chunked".to_string())),
                None => {}
            },
            Outgoing::Empty if needs_length => automatic.push(("Content-Length".to_string(), "0".to_string())),
            Outgoing::Empty => {}
        }

        let mut pairs: Vec<String> = Vec::new();
        if config.cookies {
            let jar = self.inner.jar.lock().expect("cookie jar lock");
            pairs.extend(jar.get_request_values(url).map(|(n, v)| format!("{n}={v}")));
        }
        pairs.extend(request.extra_cookies.iter().map(|(n, v)| format!("{n}={v}")));
        if !pairs.is_empty() {
            automatic.push(("Cookie".to_string(), pairs.join("; ")));
        }

        let order = request.header_order.as_ref().unwrap_or(&profile.header_order);

        assemble_headers(&automatic, &request.headers, order)
    }

    async fn send_h1(
        &self,
        mut conn: H1Connection<BoxIo>,
        request: &Request,
        outgoing: Outgoing,
        route: &Route,
        read_timeout: Option<Duration>,
    ) -> Result<StreamResponse> {
        let mut headers = self.request_headers(request, &outgoing, true);
        let url = &request.url;
        let via_http_proxy = route.scheme == "http" && route.proxy.as_ref().is_some_and(|p| p.kind == ProxyKind::Http);

        let target = if via_http_proxy {
            if let Some(auth) = route.proxy.as_ref().and_then(|p| p.authorization()) {
                headers.push(("Proxy-Authorization".to_string(), auth));
            }
            url.as_str().to_string()
        } else {
            match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            }
        };

        match outgoing {
            Outgoing::Empty => conn.write_request(&request.method, &target, &headers, None).await?,
            Outgoing::Bytes(data) => {
                conn.write_request(&request.method, &target, &headers, Some(&data))
                    .await?
            }
            Outgoing::Stream(mut upload) => {
                let chunked = upload.length().is_none();

                conn.write_request(&request.method, &target, &headers, None).await?;
                while let Some(chunk) = upload.next().await? {
                    conn.write_body_chunk(&chunk, chunked).await?;
                }
                if chunked {
                    conn.finish_chunked().await?;
                }
            }
        }

        let head = match read_timeout {
            Some(limit) => tokio::time::timeout(limit, conn.read_head(&request.method))
                .await
                .map_err(|_| Error::ReadTimeout(format!("no response head from {} within {limit:?}", route.host)))??,
            None => conn.read_head(&request.method).await?,
        };

        let closes = headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
        let tls_resumed = conn.tls_resumed;
        let pool = PoolReturn {
            pool: self.inner.pool.clone(),
            key: route.key.clone(),
        };
        let body = Body::h1(conn, head.framing, head.keep_alive && !closes, pool, read_timeout);

        Ok(StreamResponse {
            status: head.status,
            version: head.version,
            url: request.url.clone(),
            headers: head.headers,
            request_headers: headers,
            tls_resumed,
            body,
        })
    }

    async fn send_h2(
        &self,
        conn: &H2Connection,
        request: &Request,
        outgoing: Outgoing,
        read_timeout: Option<Duration>,
    ) -> Result<StreamResponse> {
        let headers = self.request_headers(request, &outgoing, false);
        let mut map = HeaderMap::with_capacity(headers.len());
        let mut authority: Option<String> = None;
        let mut sent = Vec::with_capacity(headers.len());

        for (name, value) in &headers {
            let lower = name.to_ascii_lowercase();
            if lower == "host" {
                authority = Some(value.clone());
                continue;
            }
            if matches!(
                lower.as_str(),
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
            ) {
                continue;
            }
            let header_name = HeaderName::from_bytes(lower.as_bytes())
                .map_err(|e| Error::Protocol(format!("bad header name {name:?}: {e}")))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|e| Error::Protocol(format!("bad header value for {name}: {e}")))?;
            map.append(header_name, header_value);
            sent.push((lower, value.clone()));
        }

        let uri = h2_uri(&request.url, authority.as_deref())?;
        let start = conn.start(
            request.method.clone(),
            uri,
            map,
            outgoing,
            request.priority,
        );
        let exchange = match read_timeout {
            Some(limit) => tokio::time::timeout(limit, start)
                .await
                .map_err(|_| Error::ReadTimeout(format!("request body for {} stalled for {limit:?}", request.url)))??,
            None => start.await?,
        };

        let guard = exchange.guard;
        let mut response = exchange.response;
        let wait_head = |limit: Option<Duration>, response: ResponseFuture| async move {
            match limit {
                Some(limit) => tokio::time::timeout(limit, response)
                    .await
                    .map_err(|_| Error::ReadTimeout(format!("no response head for {} within {limit:?}", request.url)))?
                    .map_err(Error::from),
                None => response.await.map_err(Error::from),
            }
        };

        let response = match exchange.upload {
            None => wait_head(read_timeout, response).await?,
            Some(mut upload) => {
                // a server may answer before the body is complete (RFC 9113 8.1); that answer wins
                tokio::select! {
                    biased;
                    head = &mut response => head?,
                    sent = &mut upload => {
                        let sent = sent.map_err(|e| Error::Body(format!("upload task failed: {e}")))?;
                        match (sent, wait_head(read_timeout, response).await) {
                            (_, Ok(head)) => head,
                            (Err(upload_error), Err(_)) => return Err(upload_error),
                            (Ok(()), Err(head_error)) => return Err(head_error),
                        }
                    }
                }
            }
        };

        let status = response.status().as_u16();
        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect();
        let body = Body::h2(response.into_body(), guard, read_timeout);

        Ok(StreamResponse {
            status,
            version: Version::HTTP_2,
            url: request.url.clone(),
            headers: response_headers,
            request_headers: sent,
            tls_resumed: conn.tls_resumed,
            body,
        })
    }
}

/**
 * Request URI for HTTP/2, with `:authority` taken from an explicit Host header when one was given.
 */
fn h2_uri(url: &Url, authority: Option<&str>) -> Result<Uri> {
    let Some(authority) = authority else {
        return url.as_str().parse().map_err(|e| Error::Url(format!("{url}: {e}")));
    };

    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    Uri::builder()
        .scheme(url.scheme())
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|e| Error::Url(format!("{url} with authority {authority}: {e}")))
}

/**
 * Host header value: host plus port when it is not the scheme default.
 */
fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/**
 * Next request after a redirect response.
 */
fn redirect_request(mut request: Request, status: u16, location: &str) -> Result<Request> {
    let next = request
        .url
        .join(location)
        .map_err(|e| Error::Url(format!("bad redirect location {location:?}: {e}")))?;

    let to_get = status == 303 || ((status == 301 || status == 302) && request.method == Method::POST);
    if to_get && request.method != Method::HEAD {
        request.method = Method::GET;
        request.body = None;
        request
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("content-type") && !n.eq_ignore_ascii_case("content-length"));
    }

    // credentials given for one origin are not sent to another; the jar still applies its own cookies
    let same_origin = next.origin() == request.url.origin();
    if !same_origin {
        request
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("authorization") && !n.eq_ignore_ascii_case("cookie"));
        request.extra_cookies.clear();
    }

    request.url = next;
    Ok(request)
}

/**
 * Build a request header list from (name, value) pairs.
 */
pub fn user_headers(pairs: &[(&str, &str)]) -> Vec<(String, Option<String>)> {
    pairs
        .iter()
        .map(|(n, v)| (n.to_string(), Some(v.to_string())))
        .collect()
}
