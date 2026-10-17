use bytes::BytesMut;
use janus_h2::huffman;

/**
 * How one header field was encoded in the HPACK block.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Representation {
    Indexed,
    Incremental,
    WithoutIndexing,
    NeverIndexed,
}

#[derive(Clone, Debug)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
    pub representation: Representation,
    /// None when the name came from the table
    pub name_huffman: Option<bool>,
    /// None for fully indexed fields
    pub value_huffman: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    pub exclusive: bool,
    pub depends_on: u32,
    /// wire value + 1
    pub weight: u16,
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

#[derive(Clone, Debug)]
pub struct HeadersBlock {
    pub stream_id: u32,
    pub priority: Option<Priority>,
    pub fields: Vec<HeaderField>,
    pub end_stream: bool,
}

impl HeadersBlock {
    /**
     * Value of a pseudo-header or header field, first occurrence.
     */
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.name == name).map(|f| f.value.as_str())
    }

    /**
     * Regular (non-pseudo) headers as (name, value) pairs in wire order.
     */
    pub fn headers(&self) -> Vec<(String, String)> {
        self.fields
            .iter()
            .filter(|f| !f.name.starts_with(':'))
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect()
    }
}

/**
 * Everything a client sent on one HTTP/2 connection that shapes its fingerprint.
 */
#[derive(Clone, Debug, Default)]
pub struct ClientConnection {
    /// first non-ACK SETTINGS, wire order
    pub settings: Vec<(u16, u32)>,
    /// connection WINDOW_UPDATE before the first HEADERS, 0 when none
    pub window_update: u32,
    /// PRIORITY frames before the first HEADERS
    pub priority_frames: Vec<(u32, Priority)>,
    pub headers: Vec<HeadersBlock>,
}

/// (name, value) for index 1..=61
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/**
 * Number of octets the Huffman encoding of text takes.
 */
pub fn huffman_length(text: &str) -> usize {
    huffman::encoded_len(&latin1(text))
}

fn latin1(text: &str) -> Vec<u8> {
    text.chars().map(|c| c as u32 as u8).collect()
}

fn from_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

fn decode_integer(data: &[u8], pos: usize, prefix_bits: u32) -> Result<(usize, usize), String> {
    let mask = (1usize << prefix_bits) - 1;
    let Some(first) = data.get(pos) else {
        return Err("truncated HPACK integer".into());
    };

    let mut value = *first as usize & mask;
    let mut pos = pos + 1;
    if value < mask {
        return Ok((value, pos));
    }

    let mut shift = 0;
    loop {
        let Some(byte) = data.get(pos) else {
            return Err("truncated HPACK integer continuation".into());
        };
        pos += 1;
        value += ((*byte & 0x7f) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }
        if shift > 28 {
            return Err("HPACK integer too large".into());
        }
    }
}

fn decode_string(data: &[u8], pos: usize) -> Result<(String, bool, usize), String> {
    let Some(first) = data.get(pos) else {
        return Err("truncated HPACK string".into());
    };
    let is_huffman = first & 0x80 != 0;
    let (length, pos) = decode_integer(data, pos, 7)?;
    let end = pos + length;
    if end > data.len() {
        return Err("truncated HPACK string body".into());
    }

    let raw = &data[pos..end];
    if !is_huffman {
        return Ok((from_latin1(raw), false, end));
    }

    let mut buf = BytesMut::new();
    let decoded = huffman::decode(raw, &mut buf).map_err(|e| format!("bad Huffman string: {e:?}"))?;
    Ok((from_latin1(&decoded), true, end))
}

fn strip_padding(payload: &[u8], flags: u8) -> Result<&[u8], String> {
    if flags & 0x8 == 0 {
        return Ok(payload);
    }
    let Some(pad_length) = payload.first() else {
        return Err("padded frame without pad length".into());
    };
    let pad_length = *pad_length as usize;
    if pad_length >= payload.len() {
        return Err("padding longer than frame payload".into());
    }
    Ok(&payload[1..payload.len() - pad_length])
}

fn parse_priority(data: &[u8]) -> Result<Priority, String> {
    if data.len() < 5 {
        return Err("truncated priority fields".into());
    }
    let dependency = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    Ok(Priority {
        exclusive: dependency >> 31 == 1,
        depends_on: dependency & 0x7fff_ffff,
        weight: data[4] as u16 + 1,
    })
}

/**
 * Stateful HPACK decoder whose dynamic table persists across header blocks.
 */
struct HpackDecoder {
    max_table_size: usize,
    table: Vec<(String, String)>,
    table_size: usize,
}

impl HpackDecoder {
    fn new() -> HpackDecoder {
        HpackDecoder {
            max_table_size: 4096,
            table: Vec::new(),
            table_size: 0,
        }
    }

    fn decode_block(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, String> {
        let mut fields = Vec::new();
        let mut pos = 0;

        while pos < block.len() {
            let octet = block[pos];
            if octet & 0x80 != 0 {
                let (index, next) = decode_integer(block, pos, 7)?;
                if index == 0 {
                    return Err("indexed header field with index 0".into());
                }
                let (name, value) = self.lookup(index)?;
                fields.push(HeaderField {
                    name,
                    value,
                    representation: Representation::Indexed,
                    name_huffman: None,
                    value_huffman: None,
                });
                pos = next;
            } else if octet & 0x40 != 0 {
                pos = self.decode_literal(block, pos, 6, Representation::Incremental, &mut fields)?;
            } else if octet & 0x20 != 0 {
                let (size, next) = decode_integer(block, pos, 5)?;
                self.max_table_size = size;
                self.evict_to(size);
                pos = next;
            } else if octet & 0x10 != 0 {
                pos = self.decode_literal(block, pos, 4, Representation::NeverIndexed, &mut fields)?;
            } else {
                pos = self.decode_literal(block, pos, 4, Representation::WithoutIndexing, &mut fields)?;
            }
        }
        Ok(fields)
    }

    fn decode_literal(
        &mut self,
        block: &[u8],
        pos: usize,
        prefix_bits: u32,
        representation: Representation,
        fields: &mut Vec<HeaderField>,
    ) -> Result<usize, String> {
        let (index, pos) = decode_integer(block, pos, prefix_bits)?;
        let (name, name_huffman, pos) = if index == 0 {
            let (name, huffman, next) = decode_string(block, pos)?;
            (name, Some(huffman), next)
        } else {
            (self.lookup(index)?.0, None, pos)
        };
        let (value, value_huffman, pos) = decode_string(block, pos)?;

        if representation == Representation::Incremental {
            self.insert(&name, &value);
        }
        fields.push(HeaderField {
            name,
            value,
            representation,
            name_huffman,
            value_huffman: Some(value_huffman),
        });
        Ok(pos)
    }

    fn lookup(&self, index: usize) -> Result<(String, String), String> {
        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Ok((name.to_string(), value.to_string()));
        }
        match self.table.get(index - STATIC_TABLE.len() - 1) {
            Some(entry) => Ok(entry.clone()),
            None => Err(format!("HPACK index {index} out of range")),
        }
    }

    fn insert(&mut self, name: &str, value: &str) {
        let size = name.len() + value.len() + 32;
        if size > self.max_table_size {
            self.evict_to(0);
            return;
        }
        self.evict_to(self.max_table_size - size);
        self.table.insert(0, (name.to_string(), value.to_string()));
        self.table_size += size;
    }

    fn evict_to(&mut self, limit: usize) {
        while self.table_size > limit {
            let Some((name, value)) = self.table.pop() else {
                break;
            };
            self.table_size -= name.len() + value.len() + 32;
        }
    }
}

/**
 * Incremental parser of the client side of an HTTP/2 connection.
 */
pub struct ClientStream {
    buffer: Vec<u8>,
    preface_done: bool,
    decoder: HpackDecoder,
    connection: ClientConnection,
    settings_seen: bool,
    window_update_seen: bool,
    headers_seen: bool,
    /// (stream id, end_stream, priority, fragments) of a block waiting for CONTINUATION
    pending: Option<(u32, bool, Option<Priority>, Vec<u8>)>,
}

impl ClientStream {
    pub fn new() -> ClientStream {
        ClientStream {
            buffer: Vec::new(),
            preface_done: false,
            decoder: HpackDecoder::new(),
            connection: ClientConnection::default(),
            settings_seen: false,
            window_update_seen: false,
            headers_seen: false,
            pending: None,
        }
    }

    /**
     * Consume client bytes and return the frames completed by this call.
     */
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Frame>, String> {
        self.buffer.extend_from_slice(data);
        if !self.check_preface()? {
            return Ok(Vec::new());
        }

        let mut frames = Vec::new();
        while self.buffer.len() >= 9 {
            let length = u32::from_be_bytes([0, self.buffer[0], self.buffer[1], self.buffer[2]]) as usize;
            let total = 9 + length;
            if self.buffer.len() < total {
                break;
            }

            let frame = Frame {
                frame_type: self.buffer[3],
                flags: self.buffer[4],
                stream_id: u32::from_be_bytes([self.buffer[5], self.buffer[6], self.buffer[7], self.buffer[8]])
                    & 0x7fff_ffff,
            };
            let payload: Vec<u8> = self.buffer[9..total].to_vec();
            self.buffer.drain(..total);

            self.handle_frame(&frame, &payload)?;
            frames.push(frame);
        }
        Ok(frames)
    }

    /**
     * Everything parsed so far.
     */
    pub fn connection(&self) -> &ClientConnection {
        &self.connection
    }

    fn check_preface(&mut self) -> Result<bool, String> {
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if self.preface_done {
            return Ok(true);
        }

        let seen = self.buffer.len().min(preface.len());
        if self.buffer[..seen] != preface[..seen] {
            return Err("invalid HTTP/2 client connection preface".into());
        }
        if seen < preface.len() {
            return Ok(false);
        }
        self.buffer.drain(..preface.len());
        self.preface_done = true;
        Ok(true)
    }

    fn handle_frame(&mut self, frame: &Frame, payload: &[u8]) -> Result<(), String> {
        let is_continuation = frame.frame_type == 0x9;
        match &self.pending {
            Some((stream_id, ..)) if !is_continuation || frame.stream_id != *stream_id => {
                return Err("expected CONTINUATION frame for pending header block".into());
            }
            None if is_continuation => return Err("CONTINUATION frame without pending header block".into()),
            _ => {}
        }

        match frame.frame_type {
            0x0 => {
                strip_padding(payload, frame.flags)?;
            }
            0x1 => self.handle_headers(frame, payload)?,
            0x2 => self.handle_priority(frame, payload)?,
            0x4 => self.handle_settings(frame, payload)?,
            0x8 => self.handle_window_update(frame, payload)?,
            0x9 => self.handle_continuation(frame, payload)?,
            _ => {}
        }
        Ok(())
    }

    fn handle_settings(&mut self, frame: &Frame, payload: &[u8]) -> Result<(), String> {
        if self.settings_seen || frame.flags & 0x1 != 0 {
            return Ok(());
        }
        if payload.len() % 6 != 0 {
            return Err("SETTINGS payload is not a multiple of 6 octets".into());
        }

        for item in payload.chunks(6) {
            let id = u16::from_be_bytes([item[0], item[1]]);
            let value = u32::from_be_bytes([item[2], item[3], item[4], item[5]]);
            self.connection.settings.push((id, value));
        }
        self.settings_seen = true;
        Ok(())
    }

    fn handle_window_update(&mut self, frame: &Frame, payload: &[u8]) -> Result<(), String> {
        if frame.stream_id != 0 || self.headers_seen || self.window_update_seen {
            return Ok(());
        }
        if payload.len() != 4 {
            return Err("WINDOW_UPDATE payload must be 4 octets".into());
        }

        self.connection.window_update = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
        self.window_update_seen = true;
        Ok(())
    }

    fn handle_priority(&mut self, frame: &Frame, payload: &[u8]) -> Result<(), String> {
        if self.headers_seen {
            return Ok(());
        }
        if payload.len() != 5 {
            return Err("PRIORITY payload must be 5 octets".into());
        }
        self.connection.priority_frames.push((frame.stream_id, parse_priority(payload)?));
        Ok(())
    }

    fn handle_headers(&mut self, frame: &Frame, payload: &[u8]) -> Result<(), String> {
        self.headers_seen = true;
        let mut body = strip_padding(payload, frame.flags)?;
        let mut priority = None;
        if frame.flags & 0x20 != 0 {
            priority = Some(parse_priority(body)?);
            body = &body[5..];
        }

        let end_stream = frame.flags & 0x1 != 0;
        if frame.flags & 0x4 != 0 {
            return self.finish_headers(frame.stream_id, end_stream, priority, body);
        }
        self.pending = Some((frame.stream_id, end_stream, priority, body.to_vec()));
        Ok(())
    }

    fn handle_continuation(&mut self, frame: &Frame, payload: &[u8]) -> Result<(), String> {
        let Some((stream_id, end_stream, priority, mut block)) = self.pending.take() else {
            return Err("CONTINUATION frame without pending header block".into());
        };
        block.extend_from_slice(payload);

        if frame.flags & 0x4 != 0 {
            return self.finish_headers(stream_id, end_stream, priority, &block);
        }
        self.pending = Some((stream_id, end_stream, priority, block));
        Ok(())
    }

    fn finish_headers(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        priority: Option<Priority>,
        block: &[u8],
    ) -> Result<(), String> {
        let fields = self.decoder.decode_block(block)?;

        self.connection.headers.push(HeadersBlock {
            stream_id,
            priority,
            fields,
            end_stream,
        });
        Ok(())
    }
}

impl ClientConnection {
    /**
     * Akamai HTTP/2 fingerprint of what the client sent.
     */
    pub fn akamai(&self) -> String {
        let settings: Vec<String> = self.settings.iter().map(|(id, v)| format!("{id}:{v}")).collect();
        let priorities: Vec<String> = self
            .priority_frames
            .iter()
            .map(|(id, p)| format!("{id}:{}:{}:{}", p.exclusive as u8, p.depends_on, p.weight))
            .collect();
        let pseudo: Vec<&str> = match self.headers.first() {
            Some(block) => block.fields.iter().filter_map(|f| pseudo_letter(&f.name)).collect(),
            None => Vec::new(),
        };
        let priorities = if priorities.is_empty() { "0".to_string() } else { priorities.join(",") };

        format!("{}|{}|{}|{}", settings.join(";"), self.window_update, priorities, pseudo.join(","))
    }
}

/**
 * Akamai letter of a request pseudo-header.
 */
pub fn pseudo_letter(name: &str) -> Option<&'static str> {
    match name {
        ":method" => Some("m"),
        ":authority" => Some("a"),
        ":scheme" => Some("s"),
        ":path" => Some("p"),
        _ => None,
    }
}
