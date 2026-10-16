use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/**
 * Request body produced by the caller while the request is in flight.
 */
pub struct Upload {
    chunks: mpsc::Receiver<Bytes>,
    length: Option<u64>,
    sent: u64,
    finished: Arc<AtomicBool>,
}

/**
 * Producer side of an Upload; dropping every sender without `finish` aborts the request.
 */
#[derive(Clone)]
pub struct UploadSender {
    chunks: mpsc::Sender<Bytes>,
    finished: Arc<AtomicBool>,
}

impl Upload {
    /**
     * New upload and its sender; `length` is the declared Content-Length, None to send it chunked.
     */
    pub fn channel(length: Option<u64>) -> (UploadSender, Upload) {
        let (tx, rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let upload = Upload {
            chunks: rx,
            length,
            sent: 0,
            finished: finished.clone(),
        };
        (UploadSender { chunks: tx, finished }, upload)
    }

    pub fn length(&self) -> Option<u64> {
        self.length
    }

    /**
     * Next non-empty chunk, None once the body was finished; errors on abort or a Content-Length mismatch.
     */
    pub async fn next(&mut self) -> Result<Option<Bytes>> {
        loop {
            let Some(chunk) = self.chunks.recv().await else {
                if !self.finished.load(Ordering::Acquire) {
                    return Err(Error::Body(format!("upload aborted after {} bytes", self.sent)));
                }
                return match self.length {
                    Some(declared) if declared != self.sent => Err(Error::Body(format!(
                        "upload ended after {} bytes but Content-Length is {declared}",
                        self.sent
                    ))),
                    _ => Ok(None),
                };
            };
            if chunk.is_empty() {
                continue;
            }

            self.sent += chunk.len() as u64;
            if let Some(declared) = self.length
                && self.sent > declared
            {
                return Err(Error::Body(format!(
                    "upload exceeds its Content-Length of {declared} bytes"
                )));
            }
            return Ok(Some(chunk));
        }
    }
}

impl UploadSender {
    /**
     * Queue one chunk; false once the request stopped reading the body.
     */
    pub async fn send(&self, chunk: Bytes) -> bool {
        self.chunks.send(chunk).await.is_ok()
    }

    /**
     * Mark the body complete; it ends once every sender is dropped.
     */
    pub fn finish(&self) {
        self.finished.store(true, Ordering::Release);
    }
}

/**
 * What goes after the request head.
 */
pub(crate) enum Outgoing {
    Empty,
    Bytes(Bytes),
    Stream(Upload),
}

impl Outgoing {
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, Outgoing::Empty)
    }
}
