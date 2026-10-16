use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, Uri, Version};
use janus_h2::client::{Builder, Connection, ResponseFuture, SendRequest};
use janus_h2::frame::{
    ExperimentalSettings, Priorities, Priority, PseudoId, PseudoOrder, Setting, SettingId, SettingsOrder,
    StreamDependency, StreamId,
};
use janus_h2::{HpackPolicy, Reason, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, BufWriter};
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::upload::{Outgoing, Upload};

/**
 * RFC 7540 priority attached to a HEADERS or PRIORITY frame (weight in 1..=256).
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPriority {
    pub depends_on: u32,
    pub weight: u16,
    pub exclusive: bool,
}

impl StreamPriority {
    fn dependency(&self) -> StreamDependency {
        StreamDependency::new(
            StreamId::from(self.depends_on),
            (self.weight.clamp(1, 256) - 1) as u8,
            self.exclusive,
        )
    }
}

/**
 * HPACK encoding style for request headers.
 */
#[derive(Clone, Debug)]
pub enum HpackStyle {
    /// The h2 crate heuristics: everything Huffman, nghttp2 indexing exceptions
    Legacy,
    /// Chromium (quiche) encoder
    Chrome,
    /// Explicit policy
    Custom(HpackPolicy),
}

/**
 * How HEADERS frames get their priority when the request does not set one.
 */
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PriorityMode {
    /// `headers_priority` for every stream
    #[default]
    Fixed,
    /// Chromium: exclusive dependency on the newest open stream of the same or higher urgency
    ChromeTree,
}

/**
 * Everything that shapes the HTTP/2 connection preface and request HEADERS.
 */
#[derive(Clone, Debug)]
pub struct Http2Profile {
    pub settings: Vec<(u16, u32)>,
    pub window_update: u32,
    pub priority_frames: Vec<(u32, StreamPriority)>,
    pub pseudo_order: String,
    pub headers_priority: Option<StreamPriority>,
    pub priority_mode: PriorityMode,
    pub hpack: HpackStyle,
}

impl Http2Profile {
    /**
     * Chrome 155 on Windows.
     */
    pub fn chrome155() -> Http2Profile {
        let mut profile = Http2Profile::from_akamai("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
            .expect("built-in chrome akamai string parses");

        profile.headers_priority = Some(StreamPriority {
            depends_on: 0,
            weight: 256,
            exclusive: true,
        });
        profile.priority_mode = PriorityMode::ChromeTree;
        profile.hpack = HpackStyle::Chrome;
        profile
    }

    /**
     * Parse an Akamai HTTP/2 fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order.
     */
    pub fn from_akamai(text: &str) -> Result<Http2Profile> {
        let parts: Vec<&str> = text.trim().split('|').collect();
        if parts.len() != 4 {
            return Err(Error::Profile(format!("akamai string needs 4 parts: {text}")));
        }
        let bad = |what: &str| Error::Profile(format!("akamai {what}: {text}"));

        let mut settings = Vec::new();
        for item in parts[0].split([';', ',']).filter(|s| !s.is_empty()) {
            let (id, value) = item.split_once(':').ok_or_else(|| bad("setting"))?;
            settings.push((
                id.parse().map_err(|_| bad("setting id"))?,
                value.parse().map_err(|_| bad("setting value"))?,
            ));
        }

        let window_update = parts[1].parse().map_err(|_| bad("window update"))?;

        let mut priority_frames = Vec::new();
        if parts[2] != "0" {
            for item in parts[2].split(',') {
                let f: Vec<&str> = item.split(':').collect();
                if f.len() != 4 {
                    return Err(bad("priority frame"));
                }
                let stream_id = f[0].parse().map_err(|_| bad("priority stream"))?;
                priority_frames.push((
                    stream_id,
                    StreamPriority {
                        exclusive: f[1] == "1",
                        depends_on: f[2].parse().map_err(|_| bad("priority dependency"))?,
                        weight: f[3].parse().map_err(|_| bad("priority weight"))?,
                    },
                ));
            }
        }

        let pseudo_order: String = parts[3].split(',').map(|s| s.trim()).collect();
        if pseudo_order.chars().any(|c| !"masp".contains(c)) {
            return Err(bad("pseudo-header order"));
        }

        Ok(Http2Profile {
            settings,
            window_update,
            priority_frames,
            pseudo_order,
            headers_priority: None,
            priority_mode: PriorityMode::Fixed,
            hpack: HpackStyle::Legacy,
        })
    }

    /**
     * Akamai fingerprint string of this profile.
     */
    pub fn akamai(&self) -> String {
        let settings: Vec<String> = self.settings.iter().map(|(id, v)| format!("{id}:{v}")).collect();
        let priorities: Vec<String> = self
            .priority_frames
            .iter()
            .map(|(id, p)| format!("{id}:{}:{}:{}", p.exclusive as u8, p.depends_on, p.weight))
            .collect();
        let pseudo: Vec<String> = self.pseudo_order.chars().map(|c| c.to_string()).collect();

        format!(
            "{}|{}|{}|{}",
            settings.join(";"),
            self.window_update,
            if priorities.is_empty() { "0".to_string() } else { priorities.join(",") },
            pseudo.join(",")
        )
    }

    /**
     * Check the values HTTP/2 puts limits on: pseudo-header order, window increment, SETTINGS ranges (RFC 9113 6.5.2).
     */
    pub fn validate(&self) -> Result<()> {
        let mut letters: Vec<char> = self.pseudo_order.chars().collect();
        letters.sort_unstable();
        if letters != ['a', 'm', 'p', 's'] {
            return Err(Error::Profile(format!(
                "pseudo_order {:?} must contain each of m, a, s, p once",
                self.pseudo_order
            )));
        }
        // the connection window starts at 65535 and may not exceed 2^31-1
        if self.window_update > 0x7fff_ffff - 65_535 {
            return Err(Error::Profile(format!("window_update {} is too large", self.window_update)));
        }

        for &(id, value) in &self.settings {
            let valid = match id {
                0x2 | 0x8 | 0x9 => value <= 1,
                0x4 => value <= 0x7fff_ffff,
                0x5 => (16_384..=16_777_215).contains(&value),
                _ => true,
            };
            if !valid {
                return Err(Error::Profile(format!("SETTINGS 0x{id:x} = {value} is out of range")));
            }
        }
        Ok(())
    }

    /**
     * janus-h2 client builder configured with this profile.
     */
    fn builder(&self) -> Builder {
        let mut builder = Builder::new();
        let mut order = SettingsOrder::builder();
        let mut experimental = ExperimentalSettings::builder();

        for (id, value) in &self.settings {
            match SettingId::from(*id) {
                SettingId::HeaderTableSize => builder.header_table_size(*value),
                SettingId::EnablePush => builder.enable_push(*value != 0),
                SettingId::MaxConcurrentStreams => builder.max_concurrent_streams(*value),
                SettingId::InitialWindowSize => builder.initial_window_size(*value),
                SettingId::MaxFrameSize => builder.max_frame_size(*value),
                SettingId::MaxHeaderListSize => builder.max_header_list_size(*value),
                SettingId::EnableConnectProtocol => builder.enable_connect_protocol(*value != 0),
                SettingId::NoRfc7540Priorities => builder.no_rfc7540_priorities(*value != 0),
                SettingId::Unknown(raw) => {
                    experimental = experimental.push(Setting::from_id(raw, *value));
                    &mut builder
                }
            };
            order = order.push(SettingId::from(*id));
        }
        builder.experimental_settings(experimental.build());
        builder.settings_order(order.build());

        if self.window_update > 0 {
            builder.initial_connection_window_size(65_535 + self.window_update);
        }

        let mut pseudo = PseudoOrder::builder();
        for c in self.pseudo_order.chars() {
            let id = match c {
                'm' => PseudoId::Method,
                'a' => PseudoId::Authority,
                's' => PseudoId::Scheme,
                _ => PseudoId::Path,
            };
            pseudo = pseudo.push(id);
        }
        builder.headers_pseudo_order(pseudo.build());

        if let Some(priority) = self.headers_priority {
            builder.headers_stream_dependency(priority.dependency());
        }
        if !self.priority_frames.is_empty() {
            let mut frames = Priorities::builder();
            for (stream_id, priority) in &self.priority_frames {
                frames = frames.push(Priority::new(StreamId::from(*stream_id), priority.dependency()));
            }
            builder.priorities(frames.build());
        }

        match &self.hpack {
            HpackStyle::Legacy => {}
            HpackStyle::Chrome => {
                builder.hpack_policy(HpackPolicy::chrome());
            }
            HpackStyle::Custom(policy) => {
                builder.hpack_policy(policy.clone());
            }
        }
        builder
    }
}

type Driver = Pin<Box<dyn Future<Output = ()> + Send>>;

/**
 * Open streams per urgency in creation order, as Chromium's Http2PriorityDependencies keeps them.
 */
#[derive(Default)]
struct PriorityTree {
    open: [Vec<u32>; 8],
}

impl PriorityTree {
    /**
     * Priority for a new stream of the given urgency (0 most urgent).
     */
    fn priority_for(&self, urgency: u8) -> StreamPriority {
        // Spdy3PriorityToHttp2Weight
        let weights = [256, 220, 183, 147, 110, 74, 37, 1];
        let urgency = usize::from(urgency.min(7));
        let parent = (0..=urgency).rev().find_map(|u| self.open[u].last().copied()).unwrap_or(0);

        StreamPriority {
            depends_on: parent,
            weight: weights[urgency],
            exclusive: true,
        }
    }

    fn insert(&mut self, stream_id: u32, urgency: u8) {
        self.open[usize::from(urgency.min(7))].push(stream_id);
    }

    fn remove(&mut self, stream_id: u32) {
        for list in &mut self.open {
            list.retain(|id| *id != stream_id);
        }
    }
}

/**
 * Keeps a stream in the priority tree until the response is dropped.
 */
pub struct StreamGuard {
    tree: Arc<Mutex<PriorityTree>>,
    stream_id: u32,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.tree.lock().expect("priority tree lock").remove(self.stream_id);
    }
}

/**
 * Urgency from an RFC 9218 Priority header value; 3 when absent.
 */
fn urgency_of(headers: &HeaderMap) -> u8 {
    let Some(value) = headers.get("priority").and_then(|v| v.to_str().ok()) else {
        return 3;
    };

    for item in value.split(',') {
        if let Some(u) = item.trim().strip_prefix("u=") {
            if let Ok(u) = u.trim().parse::<u8>() {
                return u.min(7);
            }
        }
    }
    3
}

/**
 * Shared handle for issuing requests on one HTTP/2 connection.
 */
#[derive(Clone)]
pub struct H2Connection {
    send: SendRequest<Bytes>,
    alive: Arc<AtomicBool>,
    driver: Arc<Mutex<Option<Driver>>>,
    tree: Arc<Mutex<PriorityTree>>,
    priority_mode: PriorityMode,
    pub tls_resumed: bool,
}

impl H2Connection {
    /**
     * Run the HTTP/2 handshake; the connection starts being driven when the first request is queued.
     */
    pub async fn handshake<T>(io: T, profile: &Http2Profile, tls_resumed: bool) -> Result<H2Connection>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // preface, SETTINGS, WINDOW_UPDATE and the first HEADERS share one flush
        let io = BufWriter::with_capacity(16 * 1024, io);
        let (send, conn): (_, Connection<_, Bytes>) = profile.builder().handshake(io).await?;
        let alive = Arc::new(AtomicBool::new(true));
        let flag = alive.clone();

        let driver: Driver = Box::pin(async move {
            if let Err(e) = conn.await {
                log::debug!("h2 connection closed: {e}");
            }
            flag.store(false, Ordering::Release);
        });

        Ok(H2Connection {
            send,
            alive,
            driver: Arc::new(Mutex::new(Some(driver))),
            tree: Arc::new(Mutex::new(PriorityTree::default())),
            priority_mode: profile.priority_mode,
            tls_resumed,
        })
    }

    /**
     * Whether the connection can still take new streams.
     */
    pub fn is_open(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /**
     * Send one request and wait for the response head; the body is streamed by the caller.
     */
    pub async fn send(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Option<Bytes>,
        priority: Option<StreamPriority>,
    ) -> Result<(Response<RecvStream>, StreamGuard)> {
        let outgoing = match body {
            Some(data) if !data.is_empty() => Outgoing::Bytes(data),
            _ => Outgoing::Empty,
        };
        let mut exchange = self.start(method, uri, headers, outgoing, priority).await?;

        exchange.finish_upload().await?;
        Ok((exchange.response.await?, exchange.guard))
    }

    /**
     * Send the HEADERS frame and the body; a streamed body is pumped by a background task.
     */
    pub(crate) async fn start(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Outgoing,
        priority: Option<StreamPriority>,
    ) -> Result<H2Exchange> {
        let urgency = urgency_of(&headers);
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(Version::HTTP_2)
            .body(())?;
        *request.headers_mut() = headers;

        let mut send = self.send.clone().ready().await?;

        let (response, mut stream, guard) = {
            let mut tree = self.tree.lock().expect("priority tree lock");
            let chosen = match (priority, self.priority_mode) {
                (Some(p), _) => Some(p),
                (None, PriorityMode::ChromeTree) => Some(tree.priority_for(urgency)),
                (None, PriorityMode::Fixed) => None,
            };
            if let Some(p) = chosen {
                request.extensions_mut().insert(p.dependency());
            }

            let (response, stream) = send.send_request(request, body.is_empty())?;
            let stream_id = stream.stream_id().as_u32();

            tree.insert(stream_id, urgency);
            let guard = StreamGuard {
                tree: self.tree.clone(),
                stream_id,
            };
            (response, stream, guard)
        };

        let driver = self.driver.lock().expect("driver lock").take();
        if let Some(driver) = driver {
            tokio::spawn(driver);
        }

        // the body goes out in its own task so a response that arrives first is not lost (RFC 9113 8.1)
        let upload = match body {
            Outgoing::Empty => None,
            Outgoing::Bytes(data) => Some(tokio::spawn(async move {
                let result = send_all(&mut stream, data, true).await;
                if result.is_err() {
                    stream.send_reset(Reason::CANCEL);
                }
                result
            })),
            Outgoing::Stream(mut upload) => Some(tokio::spawn(async move {
                let result = pump_upload(&mut stream, &mut upload).await;
                if result.is_err() {
                    stream.send_reset(Reason::CANCEL);
                }
                result
            })),
        };

        Ok(H2Exchange {
            response,
            upload,
            guard,
        })
    }
}

/**
 * A request whose HEADERS went out: the pending response head and the task sending its body.
 */
pub(crate) struct H2Exchange {
    pub response: ResponseFuture,
    pub upload: Option<JoinHandle<Result<()>>>,
    pub guard: StreamGuard,
}

impl H2Exchange {
    /**
     * Wait until the body has been handed to the connection.
     */
    pub async fn finish_upload(&mut self) -> Result<()> {
        let Some(task) = self.upload.take() else {
            return Ok(());
        };
        task.await
            .map_err(|e| Error::Body(format!("upload task failed: {e}")))?
    }
}

/**
 * Send `data` as DATA frames within the stream's flow-control window.
 */
async fn send_all(stream: &mut SendStream<Bytes>, mut data: Bytes, end_stream: bool) -> Result<()> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());

        let granted = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| Error::Disconnected("stream closed while sending the body".into()))??;
        let chunk = data.split_to(granted.min(data.len()));

        stream.send_data(chunk, end_stream && data.is_empty())?;
    }
    Ok(())
}

/**
 * Forward every upload chunk to the stream, then end it.
 */
async fn pump_upload(stream: &mut SendStream<Bytes>, upload: &mut Upload) -> Result<()> {
    while let Some(chunk) = upload.next().await? {
        send_all(stream, chunk, false).await?;
    }
    stream.send_data(Bytes::new(), true)?;
    Ok(())
}
