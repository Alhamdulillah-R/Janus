"""
HTTP/2 client-side frame parser with an HPACK decoder that records how each header field was encoded.
"""

from dataclasses import dataclass

default_header_table_size = 4096
entry_overhead = 32
frame_header_len = 9
frame_data = 0
frame_headers = 1
frame_priority = 2
frame_settings = 4
frame_window_update = 8
frame_continuation = 9
flag_ack = 0x1
flag_end_stream = 0x1
flag_end_headers = 0x4
flag_padded = 0x8
flag_priority = 0x20

# (name, value) for index 1..61
static_table: list[tuple[str, str]] = [
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
]

# (code, bit length) indexed by symbol; symbol 256 is EOS
huffman_codes: list[tuple[int, int]] = [
    (0x1FF8, 13),
    (0x7FFFD8, 23),
    (0xFFFFFE2, 28),
    (0xFFFFFE3, 28),
    (0xFFFFFE4, 28),
    (0xFFFFFE5, 28),
    (0xFFFFFE6, 28),
    (0xFFFFFE7, 28),
    (0xFFFFFE8, 28),
    (0xFFFFEA, 24),
    (0x3FFFFFFC, 30),
    (0xFFFFFE9, 28),
    (0xFFFFFEA, 28),
    (0x3FFFFFFD, 30),
    (0xFFFFFEB, 28),
    (0xFFFFFEC, 28),
    (0xFFFFFED, 28),
    (0xFFFFFEE, 28),
    (0xFFFFFEF, 28),
    (0xFFFFFF0, 28),
    (0xFFFFFF1, 28),
    (0xFFFFFF2, 28),
    (0x3FFFFFFE, 30),
    (0xFFFFFF3, 28),
    (0xFFFFFF4, 28),
    (0xFFFFFF5, 28),
    (0xFFFFFF6, 28),
    (0xFFFFFF7, 28),
    (0xFFFFFF8, 28),
    (0xFFFFFF9, 28),
    (0xFFFFFFA, 28),
    (0xFFFFFFB, 28),
    (0x14, 6),
    (0x3F8, 10),
    (0x3F9, 10),
    (0xFFA, 12),
    (0x1FF9, 13),
    (0x15, 6),
    (0xF8, 8),
    (0x7FA, 11),
    (0x3FA, 10),
    (0x3FB, 10),
    (0xF9, 8),
    (0x7FB, 11),
    (0xFA, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1A, 6),
    (0x1B, 6),
    (0x1C, 6),
    (0x1D, 6),
    (0x1E, 6),
    (0x1F, 6),
    (0x5C, 7),
    (0xFB, 8),
    (0x7FFC, 15),
    (0x20, 6),
    (0xFFB, 12),
    (0x3FC, 10),
    (0x1FFA, 13),
    (0x21, 6),
    (0x5D, 7),
    (0x5E, 7),
    (0x5F, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6A, 7),
    (0x6B, 7),
    (0x6C, 7),
    (0x6D, 7),
    (0x6E, 7),
    (0x6F, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xFC, 8),
    (0x73, 7),
    (0xFD, 8),
    (0x1FFB, 13),
    (0x7FFF0, 19),
    (0x1FFC, 13),
    (0x3FFC, 14),
    (0x22, 6),
    (0x7FFD, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2A, 6),
    (0x7, 5),
    (0x2B, 6),
    (0x76, 7),
    (0x2C, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2D, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7A, 7),
    (0x7B, 7),
    (0x7FFE, 15),
    (0x7FC, 11),
    (0x3FFD, 14),
    (0x1FFD, 13),
    (0xFFFFFFC, 28),
    (0xFFFE6, 20),
    (0x3FFFD2, 22),
    (0xFFFE7, 20),
    (0xFFFE8, 20),
    (0x3FFFD3, 22),
    (0x3FFFD4, 22),
    (0x3FFFD5, 22),
    (0x7FFFD9, 23),
    (0x3FFFD6, 22),
    (0x7FFFDA, 23),
    (0x7FFFDB, 23),
    (0x7FFFDC, 23),
    (0x7FFFDD, 23),
    (0x7FFFDE, 23),
    (0xFFFFEB, 24),
    (0x7FFFDF, 23),
    (0xFFFFEC, 24),
    (0xFFFFED, 24),
    (0x3FFFD7, 22),
    (0x7FFFE0, 23),
    (0xFFFFEE, 24),
    (0x7FFFE1, 23),
    (0x7FFFE2, 23),
    (0x7FFFE3, 23),
    (0x7FFFE4, 23),
    (0x1FFFDC, 21),
    (0x3FFFD8, 22),
    (0x7FFFE5, 23),
    (0x3FFFD9, 22),
    (0x7FFFE6, 23),
    (0x7FFFE7, 23),
    (0xFFFFEF, 24),
    (0x3FFFDA, 22),
    (0x1FFFDD, 21),
    (0xFFFE9, 20),
    (0x3FFFDB, 22),
    (0x3FFFDC, 22),
    (0x7FFFE8, 23),
    (0x7FFFE9, 23),
    (0x1FFFDE, 21),
    (0x7FFFEA, 23),
    (0x3FFFDD, 22),
    (0x3FFFDE, 22),
    (0xFFFFF0, 24),
    (0x1FFFDF, 21),
    (0x3FFFDF, 22),
    (0x7FFFEB, 23),
    (0x7FFFEC, 23),
    (0x1FFFE0, 21),
    (0x1FFFE1, 21),
    (0x3FFFE0, 22),
    (0x1FFFE2, 21),
    (0x7FFFED, 23),
    (0x3FFFE1, 22),
    (0x7FFFEE, 23),
    (0x7FFFEF, 23),
    (0xFFFEA, 20),
    (0x3FFFE2, 22),
    (0x3FFFE3, 22),
    (0x3FFFE4, 22),
    (0x7FFFF0, 23),
    (0x3FFFE5, 22),
    (0x3FFFE6, 22),
    (0x7FFFF1, 23),
    (0x3FFFFE0, 26),
    (0x3FFFFE1, 26),
    (0xFFFEB, 20),
    (0x7FFF1, 19),
    (0x3FFFE7, 22),
    (0x7FFFF2, 23),
    (0x3FFFE8, 22),
    (0x1FFFFEC, 25),
    (0x3FFFFE2, 26),
    (0x3FFFFE3, 26),
    (0x3FFFFE4, 26),
    (0x7FFFFDE, 27),
    (0x7FFFFDF, 27),
    (0x3FFFFE5, 26),
    (0xFFFFF1, 24),
    (0x1FFFFED, 25),
    (0x7FFF2, 19),
    (0x1FFFE3, 21),
    (0x3FFFFE6, 26),
    (0x7FFFFE0, 27),
    (0x7FFFFE1, 27),
    (0x3FFFFE7, 26),
    (0x7FFFFE2, 27),
    (0xFFFFF2, 24),
    (0x1FFFE4, 21),
    (0x1FFFE5, 21),
    (0x3FFFFE8, 26),
    (0x3FFFFE9, 26),
    (0xFFFFFFD, 28),
    (0x7FFFFE3, 27),
    (0x7FFFFE4, 27),
    (0x7FFFFE5, 27),
    (0xFFFEC, 20),
    (0xFFFFF3, 24),
    (0xFFFED, 20),
    (0x1FFFE6, 21),
    (0x3FFFE9, 22),
    (0x1FFFE7, 21),
    (0x1FFFE8, 21),
    (0x7FFFF3, 23),
    (0x3FFFEA, 22),
    (0x3FFFEB, 22),
    (0x1FFFFEE, 25),
    (0x1FFFFEF, 25),
    (0xFFFFF4, 24),
    (0xFFFFF5, 24),
    (0x3FFFFEA, 26),
    (0x7FFFF4, 23),
    (0x3FFFFEB, 26),
    (0x7FFFFE6, 27),
    (0x3FFFFEC, 26),
    (0x3FFFFED, 26),
    (0x7FFFFE7, 27),
    (0x7FFFFE8, 27),
    (0x7FFFFE9, 27),
    (0x7FFFFEA, 27),
    (0x7FFFFEB, 27),
    (0xFFFFFFE, 28),
    (0x7FFFFEC, 27),
    (0x7FFFFED, 27),
    (0x7FFFFEE, 27),
    (0x7FFFFEF, 27),
    (0x7FFFFF0, 27),
    (0x3FFFFEE, 26),
    (0x3FFFFFFF, 30),
]

huffman_lookup = {(length, code): sym for sym, (code, length) in enumerate(huffman_codes)}


@dataclass
class HeaderField:
    name: str
    value: str
    representation: str
    name_indexed: bool
    index: int | None
    name_huffman: bool | None
    value_huffman: bool | None


@dataclass
class Priority:
    exclusive: bool
    depends_on: int
    weight: int


@dataclass
class Frame:
    type: int
    flags: int
    stream_id: int
    payload: bytes


@dataclass
class HeadersBlock:
    stream_id: int
    priority: Priority | None
    fields: list[HeaderField]
    end_stream: bool
    table_size_updates: list[int]


@dataclass
class ClientConnection:
    settings: list[tuple[int, int]]
    window_update: int
    priority_frames: list[tuple[int, Priority]]
    headers: list[HeadersBlock]
    frames: list[Frame]

    def akamai(self) -> str:
        """Build the Akamai-style HTTP/2 fingerprint string from settings, window update, priorities and pseudo order."""
        settings = ";".join(f"{sid}:{value}" for sid, value in self.settings)
        priorities = ",".join(
            f"{sid}:{int(prio.exclusive)}:{prio.depends_on}:{prio.weight}" for sid, prio in self.priority_frames
        )
        if not priorities:
            priorities = "0"

        letters = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}
        pseudo = []
        if self.headers:
            for field in self.headers[0].fields:
                if field.name in letters:
                    pseudo.append(letters[field.name])

        return f"{settings}|{self.window_update}|{priorities}|{','.join(pseudo)}"


def decode_integer(data: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    """Decode an HPACK prefixed integer at pos and return (value, next position)."""
    mask = (1 << prefix_bits) - 1
    if pos >= len(data):
        raise ValueError("truncated HPACK integer")

    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos

    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated HPACK integer continuation")
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
        if shift > 28:
            raise ValueError("HPACK integer too large")


def huffman_decode(data: bytes) -> bytes:
    """Decode an HPACK Huffman-coded string, validating the EOS-prefix padding."""
    out = bytearray()
    code = 0
    length = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            length += 1
            sym = huffman_lookup.get((length, code))
            if sym is None:
                continue
            if sym == 256:
                raise ValueError("EOS symbol inside Huffman string")
            out.append(sym)
            code = 0
            length = 0

    if length > 7 or code != (1 << length) - 1:
        raise ValueError("invalid Huffman padding")
    return bytes(out)


def decode_string(data: bytes, pos: int) -> tuple[str, bool, int]:
    """Decode an HPACK string literal at pos and return (latin-1 text, huffman flag, next position)."""
    if pos >= len(data):
        raise ValueError("truncated HPACK string")
    huffman = bool(data[pos] & 0x80)
    length, pos = decode_integer(data, pos, 7)
    end = pos + length
    if end > len(data):
        raise ValueError("truncated HPACK string body")

    raw = data[pos:end]
    if huffman:
        raw = huffman_decode(raw)
    return raw.decode("latin-1"), huffman, end


def strip_padding(payload: bytes, flags: int) -> bytes:
    """Remove the pad length octet and trailing padding when the PADDED flag is set."""
    if not flags & flag_padded:
        return payload
    if not payload:
        raise ValueError("padded frame without pad length")
    pad_length = payload[0]
    if pad_length >= len(payload):
        raise ValueError("padding longer than frame payload")
    return payload[1 : len(payload) - pad_length]


def parse_priority(data: bytes) -> Priority:
    """Parse the 5-byte priority fields into a Priority with weight = wire value + 1."""
    if len(data) < 5:
        raise ValueError("truncated priority fields")
    dependency = int.from_bytes(data[0:4], "big")
    return Priority(
        exclusive=bool(dependency >> 31),
        depends_on=dependency & 0x7FFFFFFF,
        weight=data[4] + 1,
    )


class HpackDecoder:
    """Stateful HPACK decoder whose dynamic table persists across header blocks."""

    def __init__(self) -> None:
        self.max_table_size = default_header_table_size
        self.table: list[tuple[str, str]] = []
        self.table_size = 0

    def decode_block(self, block: bytes) -> tuple[list[HeaderField], list[int]]:
        """Decode one complete header block and return (fields, dynamic table size updates)."""
        fields: list[HeaderField] = []
        size_updates: list[int] = []
        pos = 0
        while pos < len(block):
            octet = block[pos]
            if octet & 0x80:
                header, pos = self.decode_indexed(block, pos)
            elif octet & 0x40:
                header, pos = self.decode_literal(block, pos, 6, "incremental")
            elif octet & 0x20:
                size, pos = decode_integer(block, pos, 5)
                self.set_max_table_size(size)
                size_updates.append(size)
                continue
            elif octet & 0x10:
                header, pos = self.decode_literal(block, pos, 4, "never_indexed")
            else:
                header, pos = self.decode_literal(block, pos, 4, "without_indexing")
            fields.append(header)
        return fields, size_updates

    def decode_indexed(self, block: bytes, pos: int) -> tuple[HeaderField, int]:
        """Decode an indexed header field representation."""
        index, pos = decode_integer(block, pos, 7)
        if index == 0:
            raise ValueError("indexed header field with index 0")
        name, value = self.lookup(index)
        header = HeaderField(
            name=name,
            value=value,
            representation="indexed",
            name_indexed=True,
            index=index,
            name_huffman=None,
            value_huffman=None,
        )
        return header, pos

    def decode_literal(self, block: bytes, pos: int, prefix_bits: int, representation: str) -> tuple[HeaderField, int]:
        """Decode a literal representation, inserting into the dynamic table when it is incremental."""
        index, pos = decode_integer(block, pos, prefix_bits)
        if index == 0:
            name, name_huffman, pos = decode_string(block, pos)
            name_indexed = False
            name_index = None
        else:
            name, _ = self.lookup(index)
            name_huffman = None
            name_indexed = True
            name_index = index

        value, value_huffman, pos = decode_string(block, pos)
        header = HeaderField(
            name=name,
            value=value,
            representation=representation,
            name_indexed=name_indexed,
            index=name_index,
            name_huffman=name_huffman,
            value_huffman=value_huffman,
        )
        if representation == "incremental":
            self.insert(name, value)
        return header, pos

    def lookup(self, index: int) -> tuple[str, str]:
        """Return the (name, value) pair for a combined static and dynamic index."""
        if index <= len(static_table):
            return static_table[index - 1]
        dynamic_index = index - len(static_table) - 1
        if dynamic_index >= len(self.table):
            raise ValueError(f"HPACK index {index} out of range")
        return self.table[dynamic_index]

    def insert(self, name: str, value: str) -> None:
        """Insert an entry at the front of the dynamic table, evicting oldest entries as needed."""
        size = len(name) + len(value) + entry_overhead
        self.evict_to(self.max_table_size - size)
        if size > self.max_table_size:
            return
        self.table.insert(0, (name, value))
        self.table_size += size

    def evict_to(self, limit: int) -> None:
        """Evict oldest dynamic table entries until the table size is at most limit."""
        while self.table and self.table_size > limit:
            name, value = self.table.pop()
            self.table_size -= len(name) + len(value) + entry_overhead

    def set_max_table_size(self, size: int) -> None:
        """Apply a dynamic table size update."""
        self.max_table_size = size
        self.evict_to(size)


class ClientStream:
    """Incremental parser: feed() bytes as they arrive from the client."""

    def __init__(self) -> None:
        self.preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        self.buffer = bytearray()
        self.preface_done = False
        self.decoder = HpackDecoder()
        self.frames: list[Frame] = []
        self.settings: list[tuple[int, int]] = []
        self.settings_seen = False
        self.window_update: int | None = None
        self.priority_frames: list[tuple[int, Priority]] = []
        self.headers: list[HeadersBlock] = []
        self.headers_seen = False
        self.pending_headers: tuple[int, bool, Priority | None, bytearray] | None = None

    def feed(self, data: bytes) -> list[Frame]:
        """Consume client bytes and return the frames completed by this call."""
        self.buffer.extend(data)
        if not self.check_preface():
            return []

        new_frames: list[Frame] = []
        while len(self.buffer) >= frame_header_len:
            length = int.from_bytes(self.buffer[0:3], "big")
            total = frame_header_len + length
            if len(self.buffer) < total:
                break
            frame = Frame(
                type=self.buffer[3],
                flags=self.buffer[4],
                stream_id=int.from_bytes(self.buffer[5:9], "big") & 0x7FFFFFFF,
                payload=bytes(self.buffer[frame_header_len:total]),
            )
            del self.buffer[:total]
            self.frames.append(frame)
            new_frames.append(frame)
            self.handle_frame(frame)
        return new_frames

    def connection(self) -> ClientConnection:
        """Snapshot of everything parsed so far."""
        return ClientConnection(
            settings=list(self.settings),
            window_update=self.window_update if self.window_update is not None else 0,
            priority_frames=list(self.priority_frames),
            headers=list(self.headers),
            frames=list(self.frames),
        )

    def check_preface(self) -> bool:
        """Verify the client connection preface; return True once it is fully consumed."""
        if self.preface_done:
            return True
        head = bytes(self.buffer[: len(self.preface)])
        if head != self.preface[: len(head)]:
            raise ValueError("invalid HTTP/2 client connection preface")
        if len(head) < len(self.preface):
            return False
        del self.buffer[: len(self.preface)]
        self.preface_done = True
        return True

    def handle_frame(self, frame: Frame) -> None:
        """Route one complete frame into the connection state."""
        is_continuation = frame.type == frame_continuation
        if self.pending_headers is not None:
            if not is_continuation or frame.stream_id != self.pending_headers[0]:
                raise ValueError("expected CONTINUATION frame for pending header block")
        elif is_continuation:
            raise ValueError("CONTINUATION frame without pending header block")

        if frame.type == frame_headers:
            self.handle_headers(frame)
        elif is_continuation:
            self.handle_continuation(frame)
        elif frame.type == frame_settings:
            self.handle_settings(frame)
        elif frame.type == frame_priority:
            self.handle_priority(frame)
        elif frame.type == frame_window_update:
            self.handle_window_update(frame)
        elif frame.type == frame_data:
            strip_padding(frame.payload, frame.flags)

    def handle_settings(self, frame: Frame) -> None:
        """Record the first non-ACK SETTINGS frame in wire order."""
        if self.settings_seen or frame.flags & flag_ack:
            return
        if len(frame.payload) % 6:
            raise ValueError("SETTINGS payload is not a multiple of 6 octets")
        for pos in range(0, len(frame.payload), 6):
            setting_id = int.from_bytes(frame.payload[pos : pos + 2], "big")
            value = int.from_bytes(frame.payload[pos + 2 : pos + 6], "big")
            self.settings.append((setting_id, value))
        self.settings_seen = True

    def handle_window_update(self, frame: Frame) -> None:
        """Record the first connection-level WINDOW_UPDATE seen before the first HEADERS."""
        if frame.stream_id != 0 or self.headers_seen or self.window_update is not None:
            return
        if len(frame.payload) != 4:
            raise ValueError("WINDOW_UPDATE payload must be 4 octets")
        self.window_update = int.from_bytes(frame.payload, "big") & 0x7FFFFFFF

    def handle_priority(self, frame: Frame) -> None:
        """Record PRIORITY frames seen before the first HEADERS."""
        if self.headers_seen:
            return
        if len(frame.payload) != 5:
            raise ValueError("PRIORITY payload must be 5 octets")
        self.priority_frames.append((frame.stream_id, parse_priority(frame.payload)))

    def handle_headers(self, frame: Frame) -> None:
        """Start a header block from a HEADERS frame and decode it once END_HEADERS arrives."""
        self.headers_seen = True
        body = strip_padding(frame.payload, frame.flags)
        priority = None
        if frame.flags & flag_priority:
            priority = parse_priority(body)
            body = body[5:]

        end_stream = bool(frame.flags & flag_end_stream)
        block = bytearray(body)
        if frame.flags & flag_end_headers:
            self.finish_headers(frame.stream_id, end_stream, priority, bytes(block))
        else:
            self.pending_headers = (frame.stream_id, end_stream, priority, block)

    def handle_continuation(self, frame: Frame) -> None:
        """Append a CONTINUATION fragment and decode the block when END_HEADERS arrives."""
        stream_id, end_stream, priority, block = self.pending_headers
        block.extend(frame.payload)
        if frame.flags & flag_end_headers:
            self.pending_headers = None
            self.finish_headers(stream_id, end_stream, priority, bytes(block))

    def finish_headers(self, stream_id: int, end_stream: bool, priority: Priority | None, block: bytes) -> None:
        """Decode a complete header block with the connection's HPACK decoder and store it."""
        fields, size_updates = self.decoder.decode_block(block)
        self.headers.append(
            HeadersBlock(
                stream_id=stream_id,
                priority=priority,
                fields=fields,
                end_stream=end_stream,
                table_size_updates=size_updates,
            )
        )
