use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::pkey::PKey;
use openssl::ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, select_next_proto};
use openssl::x509::X509;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_openssl::SslStream;

use crate::builder::ProfileBuilder;
use crate::clienthello::{ClientHello, is_grease, read_client_hello};
use crate::h2frames::{ClientConnection, ClientStream};

/**
 * Where the capture server listens and what it presents.
 */
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub listen: SocketAddr,
    pub name: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// requests the page sends after loading, each on a fresh connection
    pub rounds: u32,
}

/**
 * Latest capture of one browser configuration.
 */
#[derive(Clone, Debug, Serialize)]
pub struct Capture {
    /// grows with every publish, across browsers
    pub seq: u64,
    pub at_ms: u64,
    pub name: String,
    pub protocol: String,
    pub handshakes: usize,
    pub user_agent: String,
    pub ja3: String,
    pub ja4: String,
    pub akamai: String,
    pub notes: Vec<String>,
    pub profile: serde_json::Value,
    /// header values the page request carried
    pub headers: Vec<(String, String)>,
}

/**
 * What the server has seen so far.
 */
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub listen: String,
    pub name: String,
    pub captures: Vec<Capture>,
    pub log: Vec<String>,
}

/// sorted non-GREASE ciphers and extension types: one browser configuration
type Group = (Vec<u16>, Vec<u16>);

/**
 * The page request of one browser configuration and the HTTP/2 connection it came on.
 */
#[derive(Clone)]
struct Document {
    headers: Vec<(String, String)>,
    connection: Option<ClientConnection>,
    protocol: String,
}

#[derive(Default)]
struct Inner {
    hellos: HashMap<Group, Vec<ClientHello>>,
    documents: HashMap<Group, Document>,
    captures: Vec<(Group, Capture)>,
    seq: u64,
    log: VecDeque<String>,
}

struct Shared {
    config: CaptureConfig,
    acceptor: SslAcceptor,
    inner: Mutex<Inner>,
    log_limit: usize,
    peek_timeout: Duration,
    idle_timeout: Duration,
    max_data_frame: usize,
}

/**
 * Local HTTPS server that turns a browser visit into Janus profiles.
 */
pub struct CaptureServer {
    listener: TcpListener,
    shared: Arc<Shared>,
}

/**
 * Read handle on a running capture server.
 */
#[derive(Clone)]
pub struct CaptureView {
    shared: Arc<Shared>,
}

impl CaptureServer {
    /**
     * Bind the listener and load the certificate; nothing is served until run().
     */
    pub async fn bind(config: CaptureConfig) -> Result<CaptureServer, String> {
        if config.name.is_empty() || !config.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "capture name {:?} may only use letters, digits, '_' and '-'",
                config.name
            ));
        }

        let acceptor = acceptor(&config.cert_pem, &config.key_pem)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|e| format!("bind {}: {e}", config.listen))?;

        let shared = Arc::new(Shared {
            config,
            acceptor,
            inner: Mutex::new(Inner::default()),
            log_limit: 200,
            peek_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(5),
            max_data_frame: 16_384,
        });
        Ok(CaptureServer { listener, shared })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn view(&self) -> CaptureView {
        CaptureView {
            shared: self.shared.clone(),
        }
    }

    /**
     * Accept connections until the future is dropped; dropping it also ends every open connection.
     */
    pub async fn run(self) {
        let mut connections = JoinSet::new();
        let shown = format!("https://localhost:{}/", self.shared.config.listen.port());
        self.shared.note(format!("listening on {}, open {shown} in the browser", self.shared.config.listen));

        loop {
            tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok((tcp, peer)) => {
                        let shared = self.shared.clone();
                        connections.spawn(async move { shared.handle(tcp, peer).await });
                    }
                    Err(e) => {
                        self.shared.note(format!("accept failed: {e}"));
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }
}

impl CaptureView {
    pub fn snapshot(&self) -> Snapshot {
        let inner = self.shared.inner.lock().expect("capture state lock");

        Snapshot {
            listen: self.shared.config.listen.to_string(),
            name: self.shared.config.name.clone(),
            captures: inner.captures.iter().map(|(_, c)| c.clone()).collect(),
            log: inner.log.iter().cloned().collect(),
        }
    }
}

fn acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<SslAcceptor, String> {
    let chain = X509::stack_from_pem(cert_pem).map_err(|e| format!("capture certificate: {e}"))?;
    let key = PKey::private_key_from_pem(key_pem).map_err(|e| format!("capture key: {e}"))?;
    let Some((leaf, rest)) = chain.split_first() else {
        return Err("capture certificate PEM holds no certificate".into());
    };

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(|e| format!("tls server context: {e}"))?;
    builder.set_certificate(leaf).map_err(|e| format!("capture certificate: {e}"))?;
    for extra in rest {
        builder
            .add_extra_chain_cert(extra.clone())
            .map_err(|e| format!("capture certificate chain: {e}"))?;
    }
    builder.set_private_key(&key).map_err(|e| format!("capture key: {e}"))?;
    builder.check_private_key().map_err(|e| format!("capture key does not match the certificate: {e}"))?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2\x08http/1.1", offered).ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
}

impl Shared {
    fn note(&self, line: String) {
        log::info!("{line}");
        let stamp = clock();
        let mut inner = self.inner.lock().expect("capture state lock");

        if inner.log.len() == self.log_limit {
            inner.log.pop_front();
        }
        inner.log.push_back(format!("{stamp} {line}"));
    }

    /**
     * One TCP connection: read the ClientHello, finish TLS, answer requests.
     */
    async fn handle(self: Arc<Self>, mut tcp: TcpStream, peer: SocketAddr) {
        let (hello, prefix) = match self.read_hello(&mut tcp).await {
            Ok(Some(found)) => found,
            Ok(None) => return,
            Err(e) => {
                self.note(format!("no ClientHello from {peer}: {e}"));
                return;
            }
        };
        let (group, hellos) = self.remember(hello);
        self.note(format!("ClientHello #{} from {peer} ({})", hellos.len(), hellos[hellos.len() - 1].ja4()));

        let ssl = match Ssl::new(self.acceptor.context()) {
            Ok(ssl) => ssl,
            Err(e) => {
                self.note(format!("tls session for {peer}: {e}"));
                return;
            }
        };
        let stream = Replay { prefix, pos: 0, inner: tcp };
        let mut tls = match SslStream::new(ssl, stream) {
            Ok(tls) => tls,
            Err(e) => {
                self.note(format!("tls session for {peer}: {e}"));
                return;
            }
        };
        if let Err(e) = Pin::new(&mut tls).accept().await {
            // the hello is already recorded; a browser that rejects the certificate ends here
            self.note(format!("handshake from {peer} ended: {e}"));
            return;
        }

        let h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2".as_slice());
        let served = if h2 {
            self.serve_h2(&mut tls, &group).await
        } else {
            self.serve_h1(&mut tls, &group).await
        };
        if let Err(e) = served {
            self.note(format!("connection from {peer} closed: {e}"));
        }
        let _ = tls.shutdown().await;
    }

    /**
     * Read until a complete ClientHello is buffered; returns it with the bytes read so far.
     */
    async fn read_hello(&self, tcp: &mut TcpStream) -> Result<Option<(ClientHello, Vec<u8>)>, String> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 16_384];
        let deadline = tokio::time::Instant::now() + self.peek_timeout;

        loop {
            let read = tokio::time::timeout_at(deadline, tcp.read(&mut chunk))
                .await
                .map_err(|_| "incomplete ClientHello".to_string())?
                .map_err(|e| e.to_string())?;
            if read == 0 {
                return Ok(None);
            }
            buffer.extend_from_slice(&chunk[..read]);

            if let Some(hello) = read_client_hello(&buffer)? {
                return Ok(Some((hello, buffer)));
            }
        }
    }

    /**
     * Store a ClientHello; returns its browser configuration and every hello seen for it.
     */
    fn remember(&self, hello: ClientHello) -> (Group, Vec<ClientHello>) {
        let mut ciphers: Vec<u16> = hello.cipher_suites.iter().copied().filter(|c| !is_grease(*c)).collect();
        let mut types: Vec<u16> = hello
            .extension_types()
            .into_iter()
            .filter(|t| !is_grease(*t) && *t != 0x0015 && *t != 0x0029)
            .collect();
        ciphers.sort_unstable();
        types.sort_unstable();

        let group = (ciphers, types);
        let mut inner = self.inner.lock().expect("capture state lock");
        let hellos = inner.hellos.entry(group.clone()).or_default();
        hellos.push(hello);
        let all = hellos.clone();
        (group, all)
    }

    async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(&self, tls: &mut S, group: &Group) -> Result<(), String> {
        let mut stream = ClientStream::new();
        let mut seen = 0;
        let mut settings_acked = false;
        // request blocks whose body has not ended yet, by stream id
        let mut pending: HashMap<u32, usize> = HashMap::new();
        let mut buffer = vec![0u8; 65_536];

        write(tls, &frame(4, 0, 0, &[])).await?;

        let mut closing = false;
        while !closing {
            let read = match tokio::time::timeout(self.idle_timeout, tls.read(&mut buffer)).await {
                Ok(read) => read.map_err(|e| e.to_string())?,
                Err(_) => break,
            };
            if read == 0 {
                break;
            }

            let frames = stream.feed(&buffer[..read])?;
            if !stream.connection().settings.is_empty() && !settings_acked {
                write(tls, &frame(4, 1, 0, &[])).await?;
                settings_acked = true;
            }

            let mut ready = Vec::new();
            let blocks = &stream.connection().headers;
            for (index, block) in blocks.iter().enumerate().skip(seen) {
                if block.end_stream {
                    ready.push(index);
                } else {
                    pending.insert(block.stream_id, index);
                }
            }
            seen = blocks.len();
            for f in &frames {
                if f.frame_type == 0 && f.flags & 0x1 != 0 {
                    if let Some(index) = pending.remove(&f.stream_id) {
                        ready.push(index);
                    }
                }
            }

            for index in ready {
                let connection = stream.connection();
                let block = &connection.headers[index];
                let path = block.field(":path").unwrap_or("/").to_string();
                let (status, body) = self.respond(group, &path, block.headers(), Some(connection), "h2");

                self.respond_h2(tls, block.stream_id, status, &body).await?;
                // every round after the page starts a new TLS connection
                if path.starts_with("/janus-capture/") {
                    closing = true;
                }
            }
        }

        let last = stream.connection().headers.last().map(|b| b.stream_id).unwrap_or(0);
        let mut payload = last.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0, 0, 0, 0]);
        write(tls, &frame(7, 0, 0, &payload)).await
    }

    async fn respond_h2<S: AsyncWrite + Unpin>(
        &self,
        tls: &mut S,
        stream_id: u32,
        status: u16,
        body: &[u8],
    ) -> Result<(), String> {
        let mut block = hpack_literal(":status", &status.to_string());
        block.extend(hpack_literal("content-type", "text/html; charset=utf-8"));
        block.extend(hpack_literal("content-length", &body.len().to_string()));
        block.extend(hpack_literal("cache-control", "no-store"));

        if body.is_empty() {
            return write(tls, &frame(1, 0x4 | 0x1, stream_id, &block)).await;
        }

        write(tls, &frame(1, 0x4, stream_id, &block)).await?;
        let pieces: Vec<&[u8]> = body.chunks(self.max_data_frame).collect();
        for (i, piece) in pieces.iter().enumerate() {
            let flags = if i + 1 == pieces.len() { 0x1 } else { 0 };
            write(tls, &frame(0, flags, stream_id, piece)).await?;
        }
        Ok(())
    }

    async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(&self, tls: &mut S, group: &Group) -> Result<(), String> {
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 65_536];

        let head_end = loop {
            if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            let read = tokio::time::timeout(self.idle_timeout, tls.read(&mut chunk))
                .await
                .map_err(|_| "idle".to_string())?
                .map_err(|e| e.to_string())?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        };

        let head: String = buffer[..head_end].iter().map(|b| *b as char).collect();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let target = request_line.split(' ').nth(1).unwrap_or("/").to_string();
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            headers.push((name.to_string(), value.trim().to_string()));
        }

        let length: usize = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        while buffer.len() < head_end + 4 + length {
            let read = tls.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        let (status, body) = self.respond(group, &target, headers, None, "http/1.1");
        let reason = if status == 200 { "OK" } else { "Not Found" };
        let mut response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        write(tls, &response).await
    }

    /**
     * Status and body for one request.
     */
    fn respond(
        &self,
        group: &Group,
        path: &str,
        headers: Vec<(String, String)>,
        connection: Option<&ClientConnection>,
        protocol: &str,
    ) -> (u16, Vec<u8>) {
        if path == "/" {
            let user_agent = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            let document = Document {
                headers,
                connection: connection.cloned(),
                protocol: protocol.to_string(),
            };
            self.inner
                .lock()
                .expect("capture state lock")
                .documents
                .insert(group.clone(), document);
            self.note(format!("page request over {protocol} ({user_agent})"));

            let report = self.publish(group);
            return (200, self.page(&report));
        }
        if path.starts_with("/janus-capture/round") {
            return (200, self.publish(group).into_bytes());
        }
        (404, Vec::new())
    }

    /**
     * Capture page: the report of the page request, then fetch() rounds that each land on a new connection.
     */
    fn page(&self, report: &str) -> Vec<u8> {
        format!(
            r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Janus capture</title>
<style>body{{font-family:system-ui,sans-serif;margin:2em;line-height:1.5}}code,pre{{background:#f4f4f4;padding:.1em .3em}}</style>
</head><body><div id="out">{report}</div><p id="round">more handshakes need JavaScript; without it this capture is final</p>
<script>
var rounds = {rounds};
function next(round) {{
  if (round > rounds) return;
  setTimeout(function () {{
    fetch("/janus-capture/round?n=" + round + "&t=" + Date.now())
      .then(function (r) {{ return r.text(); }})
      .then(function (t) {{
        document.getElementById("out").innerHTML = t;
        document.getElementById("round").textContent = "round " + round + " / " + rounds + (round < rounds ? ", next in a moment" : ", done");
        next(round + 1);
      }});
  }}, 1500);
}}
next(1);
</script>
</body></html>
"#,
            rounds = self.config.rounds + 1
        )
        .into_bytes()
    }

    /**
     * Build the profile from the recorded page request and every handshake seen so far; returns the HTML report.
     */
    fn publish(&self, group: &Group) -> String {
        let (document, hellos) = {
            let inner = self.inner.lock().expect("capture state lock");
            (inner.documents.get(group).cloned(), inner.hellos.get(group).cloned().unwrap_or_default())
        };
        let Some(document) = document else {
            self.note("round request before any page request from the same TLS configuration; open / first".to_string());
            return "<p>open / first: the page request was not captured for this browser</p>".to_string();
        };
        let Some(connection) = &document.connection else {
            self.note(format!("page request over {}: only HTTP/2 can be captured", document.protocol));
            return "<p>the browser did not negotiate HTTP/2, nothing to capture</p>".to_string();
        };

        let mut builder = ProfileBuilder::new(&hellos, &self.config.name);
        let built = match builder.build(&document.headers, connection) {
            Ok(built) => built,
            Err(e) => {
                self.note(format!("capture failed: {e}"));
                return format!("<p>capture failed: {}</p>", escape(&e));
            }
        };

        let latest = &hellos[hellos.len() - 1];
        let user_agent = document
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "(none)".to_string());
        let akamai = built.profile.http2.akamai();

        let mut inner = self.inner.lock().expect("capture state lock");
        inner.seq += 1;
        let capture = Capture {
            seq: inner.seq,
            at_ms: now_ms(),
            name: self.config.name.clone(),
            protocol: document.protocol.clone(),
            handshakes: hellos.len(),
            user_agent: user_agent.clone(),
            ja3: latest.ja3(),
            ja4: latest.ja4(),
            akamai,
            notes: builder.notes.clone(),
            profile: built.profile.to_json_value(),
            headers: built.headers,
        };
        let report = report(&capture);
        match inner.captures.iter_mut().find(|(g, _)| g == group) {
            Some((_, slot)) => *slot = capture,
            None => inner.captures.push((group.clone(), capture)),
        }
        drop(inner);

        self.note(format!(
            "captured {} over {}: {} handshake(s), {user_agent}",
            self.config.name,
            document.protocol,
            hellos.len()
        ));
        report
    }
}

fn report(capture: &Capture) -> String {
    let notes: String = capture.notes.iter().map(|n| format!("<li>{}</li>", escape(n))).collect();

    format!(
        "<h1>Janus capture</h1><p>{} TLS handshake(s) over {}<br>browser {}<br>JA4 <code>{}</code><br>Akamai <code>{}</code></p>\
         <p>profile <code>{}</code> is ready: save it in the app that started this capture</p><h2>notes</h2><ul>{notes}</ul>",
        capture.handshakes,
        escape(&capture.protocol),
        escape(&capture.user_agent),
        escape(&capture.ja4),
        escape(&capture.akamai),
        escape(&capture.name),
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

async fn write<S: AsyncWrite + Unpin>(tls: &mut S, data: &[u8]) -> Result<(), String> {
    tls.write_all(data).await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())
}

fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut out = length.to_be_bytes()[1..].to_vec();

    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/**
 * Literal header field without indexing, new name, no Huffman.
 */
fn hpack_literal(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend(hpack_string(name));
    out.extend(hpack_string(value));
    out
}

fn hpack_string(text: &str) -> Vec<u8> {
    let mut out = hpack_integer(text.len(), 7);
    out.extend_from_slice(text.as_bytes());
    out
}

fn hpack_integer(value: usize, prefix_bits: u32) -> Vec<u8> {
    let limit = (1usize << prefix_bits) - 1;
    if value < limit {
        return vec![value as u8];
    }

    let mut out = vec![limit as u8];
    let mut rest = value - limit;
    while rest >= 128 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
    out
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/**
 * Seconds-of-day timestamp (UTC) for log lines.
 */
fn clock() -> String {
    let secs = now_ms() / 1000;
    format!("{:02}:{:02}:{:02}", secs / 3600 % 24, secs / 60 % 60, secs % 60)
}

/**
 * TCP stream that first replays the bytes read while looking for the ClientHello.
 */
struct Replay {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl AsyncRead for Replay {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            let n = (me.prefix.len() - me.pos).min(buf.remaining());
            buf.put_slice(&me.prefix[me.pos..me.pos + n]);
            me.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Replay {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
