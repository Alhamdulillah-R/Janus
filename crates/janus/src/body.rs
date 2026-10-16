use std::time::Duration;

use bytes::{Bytes, BytesMut};
use janus_h2::RecvStream;

use crate::client::{BoxIo, PoolReturn};
use crate::error::{Error, Result};
use crate::http1::{Framing, H1Connection};
use crate::http2::StreamGuard;

enum Source {
    Done,
    H2 {
        stream: RecvStream,
        _guard: StreamGuard,
    },
    H1 {
        conn: H1Connection<BoxIo>,
        framing: Framing,
        keep_alive: bool,
        pool: PoolReturn,
    },
}

/**
 * A response body read from the wire piece by piece, still content-encoded.
 */
pub struct Body {
    source: Source,
    read_timeout: Option<Duration>,
}

impl Body {
    pub fn empty() -> Body {
        Body {
            source: Source::Done,
            read_timeout: None,
        }
    }

    pub(crate) fn h2(stream: RecvStream, guard: StreamGuard, read_timeout: Option<Duration>) -> Body {
        if stream.is_end_stream() {
            return Body::empty();
        }
        Body {
            source: Source::H2 { stream, _guard: guard },
            read_timeout,
        }
    }

    pub(crate) fn h1(
        conn: H1Connection<BoxIo>,
        framing: Framing,
        keep_alive: bool,
        pool: PoolReturn,
        read_timeout: Option<Duration>,
    ) -> Body {
        if framing == Framing::Done {
            if keep_alive {
                pool.put(conn);
            }
            return Body::empty();
        }
        Body {
            source: Source::H1 {
                conn,
                framing,
                keep_alive,
                pool,
            },
            read_timeout,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.source, Source::Done)
    }

    /**
     * Next raw chunk, or None at the end; an H1 connection goes back to the pool once its body is complete.
     */
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        let read_timeout = self.read_timeout;
        let read = self.next_raw();
        let result = match read_timeout {
            Some(limit) => match tokio::time::timeout(limit, read).await {
                Ok(result) => result,
                Err(_) => Err(Error::ReadTimeout(format!("no body data within {limit:?}"))),
            },
            None => read.await,
        };

        match result {
            Ok(Some(chunk)) => Ok(Some(chunk)),
            Ok(None) => {
                self.finish();
                Ok(None)
            }
            Err(e) => {
                // a half-read connection cannot be reused
                self.source = Source::Done;
                Err(e)
            }
        }
    }

    /**
     * Read everything that is left.
     */
    pub async fn collect(mut self) -> Result<Bytes> {
        let mut out = BytesMut::new();

        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    async fn next_raw(&mut self) -> Result<Option<Bytes>> {
        match &mut self.source {
            Source::Done => Ok(None),
            Source::H2 { stream, .. } => loop {
                let chunk = match stream.data().await {
                    None => return Ok(None),
                    Some(Ok(chunk)) => chunk,
                    Some(Err(e)) => return Err(Error::Body(e.to_string())),
                };

                stream
                    .flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|e| Error::Body(e.to_string()))?;
                if !chunk.is_empty() {
                    return Ok(Some(chunk));
                }
            },
            Source::H1 { conn, framing, .. } => conn.read_body_chunk(framing).await,
        }
    }

    fn finish(&mut self) {
        let source = std::mem::replace(&mut self.source, Source::Done);

        if let Source::H1 {
            conn, keep_alive, pool, ..
        } = source
        {
            if keep_alive {
                pool.put(conn);
            }
        }
    }
}
