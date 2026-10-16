use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkState {
    Size,
    Data(u64),
    DataEnd,
    Trailers,
}

/**
 * How the rest of a response body is delimited on the wire.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Done,
    Length(u64),
    Chunked(ChunkState),
    UntilClose,
}

/**
 * Status line and headers of an HTTP/1.x response.
 */
#[derive(Debug)]
pub struct H1Head {
    pub status: u16,
    pub version: Version,
    pub headers: Vec<(String, String)>,
    pub framing: Framing,
    pub keep_alive: bool,
}

/**
 * One HTTP/1.1 connection that writes headers exactly in the given order and case.
 */
pub struct H1Connection<S> {
    io: S,
    buf: BytesMut,
    pub tls_resumed: bool,
}

impl<S> H1Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: S, tls_resumed: bool) -> H1Connection<S> {
        H1Connection {
            io,
            buf: BytesMut::with_capacity(16 * 1024),
            tls_resumed,
        }
    }

    /**
     * Whether an idle connection is still open with nothing unread on it.
     */
    pub fn is_reusable(&mut self) -> bool {
        if !self.buf.is_empty() {
            return false;
        }

        let mut cx = Context::from_waker(Waker::noop());
        let mut probe = [0u8; 1];
        let mut probe = ReadBuf::new(&mut probe);

        matches!(Pin::new(&mut self.io).poll_read(&mut cx, &mut probe), Poll::Pending)
    }

    /**
     * Write the request line, headers and body.
     */
    pub async fn write_request(
        &mut self,
        method: &Method,
        target: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<()> {
        let mut head = Vec::with_capacity(1024);

        head.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method.as_str(), target).as_bytes());
        for (name, value) in headers {
            check_header(name, value)?;
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        if let Some(body) = body {
            head.extend_from_slice(body);
        }

        self.io.write_all(&head).await?;
        self.io.flush().await?;
        Ok(())
    }

    /**
     * Write one piece of a streamed request body, chunk-framed when `chunked`.
     */
    pub async fn write_body_chunk(&mut self, data: &[u8], chunked: bool) -> Result<()> {
        if chunked {
            self.io.write_all(format!("{:x}\r\n", data.len()).as_bytes()).await?;
            self.io.write_all(data).await?;
            self.io.write_all(b"\r\n").await?;
        } else {
            self.io.write_all(data).await?;
        }
        self.io.flush().await?;
        Ok(())
    }

    /**
     * Terminate a chunked request body.
     */
    pub async fn finish_chunked(&mut self) -> Result<()> {
        self.io.write_all(b"0\r\n\r\n").await?;
        self.io.flush().await?;
        Ok(())
    }

    /**
     * Read the final response head, skipping 1xx interim responses.
     */
    pub async fn read_head(&mut self, method: &Method) -> Result<H1Head> {
        loop {
            let (status, version, headers) = self.read_status_and_headers().await?;

            if (100..200).contains(&status) && status != 101 {
                continue;
            }

            let header = |name: &str| {
                headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            };
            let chunked = header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
            let content_length = match header("content-length") {
                Some(v) => Some(
                    v.trim()
                        .parse::<u64>()
                        .map_err(|_| Error::Protocol(format!("bad content-length {v:?}")))?,
                ),
                None => None,
            };
            let connection = header("connection").map(|v| v.to_ascii_lowercase());
            let mut keep_alive = match version {
                Version::HTTP_10 => connection.as_deref() == Some("keep-alive"),
                _ => connection.as_deref() != Some("close"),
            };

            let no_body = *method == Method::HEAD || status == 204 || status == 304;
            let framing = if no_body {
                Framing::Done
            } else if chunked {
                Framing::Chunked(ChunkState::Size)
            } else if let Some(len) = content_length {
                Framing::Length(len)
            } else {
                keep_alive = false;
                Framing::UntilClose
            };

            return Ok(H1Head {
                status,
                version,
                headers,
                framing,
                keep_alive,
            });
        }
    }

    /**
     * Next piece of the response body, or None once it is complete.
     */
    pub async fn read_body_chunk(&mut self, framing: &mut Framing) -> Result<Option<Bytes>> {
        loop {
            match *framing {
                Framing::Done => return Ok(None),
                Framing::Length(0) => {
                    *framing = Framing::Done;
                    return Ok(None);
                }
                Framing::Length(remaining) => {
                    let chunk = self.take_up_to(remaining).await?;
                    *framing = Framing::Length(remaining - chunk.len() as u64);
                    return Ok(Some(chunk));
                }
                Framing::UntilClose => {
                    if self.buf.is_empty() && self.fill().await? == 0 {
                        *framing = Framing::Done;
                        return Ok(None);
                    }
                    return Ok(Some(self.buf.split().freeze()));
                }
                Framing::Chunked(ChunkState::Size) => {
                    let line = self.read_line().await?;
                    let size_text = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size_text, 16)
                        .map_err(|_| Error::Body(format!("bad chunk size line {line:?}")))?;

                    *framing = if size == 0 {
                        Framing::Chunked(ChunkState::Trailers)
                    } else {
                        Framing::Chunked(ChunkState::Data(size))
                    };
                }
                Framing::Chunked(ChunkState::Data(remaining)) => {
                    let chunk = self.take_up_to(remaining).await?;
                    let left = remaining - chunk.len() as u64;

                    *framing = if left == 0 {
                        Framing::Chunked(ChunkState::DataEnd)
                    } else {
                        Framing::Chunked(ChunkState::Data(left))
                    };
                    return Ok(Some(chunk));
                }
                Framing::Chunked(ChunkState::DataEnd) => {
                    if !self.read_line().await?.is_empty() {
                        return Err(Error::Body("missing CRLF after chunk".into()));
                    }
                    *framing = Framing::Chunked(ChunkState::Size);
                }
                Framing::Chunked(ChunkState::Trailers) => {
                    if self.read_line().await?.is_empty() {
                        *framing = Framing::Done;
                    }
                }
            }
        }
    }

    async fn fill(&mut self) -> Result<usize> {
        let n = self.io.read_buf(&mut self.buf).await?;
        Ok(n)
    }

    /**
     * Up to `limit` buffered body bytes, reading more when the buffer is empty.
     */
    async fn take_up_to(&mut self, limit: u64) -> Result<Bytes> {
        if self.buf.is_empty() && self.fill().await? == 0 {
            return Err(Error::Body("connection closed inside response body".into()));
        }
        let n = self.buf.len().min(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(self.buf.split_to(n).freeze())
    }

    async fn read_status_and_headers(&mut self) -> Result<(u16, Version, Vec<(String, String)>)> {
        loop {
            let mut raw = [httparse::EMPTY_HEADER; 128];
            let mut parsed = httparse::Response::new(&mut raw);

            match parsed.parse(&self.buf) {
                Ok(httparse::Status::Complete(len)) => {
                    let status = parsed.code.unwrap_or(0);
                    let version = if parsed.version == Some(0) { Version::HTTP_10 } else { Version::HTTP_11 };
                    let headers = parsed
                        .headers
                        .iter()
                        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
                        .collect();

                    self.buf.advance(len);
                    return Ok((status, version, headers));
                }
                Ok(httparse::Status::Partial) => {}
                Err(e) => return Err(Error::Protocol(format!("bad http/1 response head: {e}"))),
            }

            if self.fill().await? == 0 {
                return Err(Error::Disconnected("before the response head".into()));
            }
        }
    }

    async fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = self.buf.split_to(pos + 2);
                return Ok(String::from_utf8_lossy(&line[..pos]).into_owned());
            }
            if self.fill().await? == 0 {
                return Err(Error::Body("connection closed inside chunked body".into()));
            }
        }
    }
}

/**
 * Reject header names that are not tokens and values containing CR, LF or NUL, which would split the request head.
 */
fn check_header(name: &str, value: &str) -> Result<()> {
    let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);

    if name.is_empty() || !name.bytes().all(token) {
        return Err(Error::Protocol(format!("bad header name {name:?}")));
    }
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(Error::Protocol(format!("bad header value for {name}: contains CR, LF or NUL")));
    }
    Ok(())
}
