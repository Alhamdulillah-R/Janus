use std::io::Write;

use bytes::Bytes;

use crate::error::{Error, Result};

/**
 * Undo every Content-Encoding listed on a fully buffered body.
 */
pub fn decode_body(content_encoding: &str, body: Bytes) -> Result<Bytes> {
    let mut decoder = StreamDecoder::new(content_encoding)?;
    if decoder.is_identity() {
        return Ok(body);
    }

    let mut out = decoder.push(&body)?;
    out.extend_from_slice(&decoder.finish()?);
    Ok(Bytes::from(out))
}

enum Stage {
    Gzip(flate2::write::MultiGzDecoder<Vec<u8>>),
    /// zlib-wrapped or raw deflate is only known after the first two bytes
    DeflatePending(Vec<u8>),
    Zlib(flate2::write::ZlibDecoder<Vec<u8>>),
    RawDeflate(flate2::write::DeflateDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Decoder<'static, Vec<u8>>),
}

/**
 * Incremental decoder for a Content-Encoding chain; codings it does not know pass through untouched.
 */
pub struct StreamDecoder {
    stages: Vec<Stage>,
}

impl StreamDecoder {
    pub fn new(content_encoding: &str) -> Result<StreamDecoder> {
        let mut stages = Vec::new();

        // the last listed coding was applied last, so it is undone first
        for coding in content_encoding.rsplit(',').map(|c| c.trim().to_ascii_lowercase()) {
            let stage = match coding.as_str() {
                "gzip" | "x-gzip" => Stage::Gzip(flate2::write::MultiGzDecoder::new(Vec::new())),
                "deflate" => Stage::DeflatePending(Vec::new()),
                "br" => Stage::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 64 * 1024))),
                "zstd" => Stage::Zstd(
                    zstd::stream::write::Decoder::new(Vec::new())
                        .map_err(|e| Error::Decode(format!("zstd init: {e}")))?,
                ),
                _ => continue,
            };
            stages.push(stage);
        }
        Ok(StreamDecoder { stages })
    }

    pub fn is_identity(&self) -> bool {
        self.stages.is_empty()
    }

    /**
     * Feed encoded bytes, returning whatever decoded output is ready.
     */
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut current = data.to_vec();

        for stage in &mut self.stages {
            if current.is_empty() {
                break;
            }
            current = stage.push(&current)?;
        }
        Ok(current)
    }

    /**
     * Signal end of input and return the remaining decoded output.
     */
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut carry: Vec<u8> = Vec::new();

        for stage in &mut self.stages {
            let mut out = if carry.is_empty() { Vec::new() } else { stage.push(&carry)? };
            out.extend_from_slice(&stage.finish()?);
            carry = out;
        }
        Ok(carry)
    }
}

impl Stage {
    fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if let Stage::DeflatePending(buffered) = self {
            buffered.extend_from_slice(data);
            if buffered.len() < 2 {
                return Ok(Vec::new());
            }
            let pending = std::mem::take(buffered);
            *self = deflate_stage(&pending);
            return self.push(&pending);
        }

        let failed = |what: &str, e: std::io::Error| Error::Decode(format!("{what}: {e}"));
        match self {
            Stage::Gzip(d) => {
                d.write_all(data).map_err(|e| failed("gzip", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::Zlib(d) => {
                d.write_all(data).map_err(|e| failed("deflate", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::RawDeflate(d) => {
                d.write_all(data).map_err(|e| failed("deflate", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::Brotli(d) => {
                d.write_all(data).map_err(|e| failed("br", e))?;
                d.flush().map_err(|e| failed("br", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::Zstd(d) => {
                d.write_all(data).map_err(|e| failed("zstd", e))?;
                d.flush().map_err(|e| failed("zstd", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::DeflatePending(_) => unreachable!("handled above"),
        }
    }

    fn finish(&mut self) -> Result<Vec<u8>> {
        if let Stage::DeflatePending(buffered) = self {
            if buffered.is_empty() {
                return Ok(Vec::new());
            }
            let pending = std::mem::take(buffered);
            *self = deflate_stage(&pending);
            let mut out = self.push(&pending)?;
            out.extend_from_slice(&self.finish()?);
            return Ok(out);
        }

        let failed = |what: &str, e: std::io::Error| Error::Decode(format!("{what}: {e}"));
        match self {
            Stage::Gzip(d) => {
                d.try_finish().map_err(|e| failed("gzip", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::Zlib(d) => {
                d.try_finish().map_err(|e| failed("deflate", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::RawDeflate(d) => {
                d.try_finish().map_err(|e| failed("deflate", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::Brotli(d) => {
                d.close().map_err(|e| failed("br", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::Zstd(d) => {
                d.flush().map_err(|e| failed("zstd", e))?;
                Ok(std::mem::take(d.get_mut()))
            }
            Stage::DeflatePending(_) => unreachable!("handled above"),
        }
    }
}

/**
 * Pick zlib or raw deflate from the RFC 1950 header.
 */
fn deflate_stage(head: &[u8]) -> Stage {
    let zlib_wrapped = head[0] & 0x0f == 8 && (u16::from(head[0]) << 8 | u16::from(head[1])) % 31 == 0;

    if zlib_wrapped {
        return Stage::Zlib(flate2::write::ZlibDecoder::new(Vec::new()));
    }
    Stage::RawDeflate(flate2::write::DeflateDecoder::new(Vec::new()))
}
