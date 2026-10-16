"""
TLS ClientHello parser computing JA3 and JA4 fingerprints.
"""

import hashlib
from dataclasses import dataclass

# ==========================================================================
content_type_handshake = 0x16
handshake_client_hello = 0x01

ext_server_name = 0x0000
ext_status_request = 0x0005
ext_supported_groups = 0x000A
ext_ec_point_formats = 0x000B
ext_signature_algorithms = 0x000D
ext_alpn = 0x0010
ext_cert_compression = 0x001B
ext_record_size_limit = 0x001C
ext_supported_versions = 0x002B
ext_psk_key_exchange_modes = 0x002D
ext_key_share = 0x0033
ext_alps_old = 0x4469
ext_alps = 0x44CD
ext_trust_anchors = 0xCA34

ja4_versions = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
}
# ==========================================================================


class _Reader:
    """
    Bounds-checked big-endian cursor over a byte string
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        """
        Count the bytes not consumed yet
        """
        return len(self.data) - self.pos

    def take(self, size: int) -> bytes:
        """
        Consume size bytes, raising ValueError when the buffer is too short
        """
        if size > self.remaining():
            raise ValueError(f"truncated TLS structure: need {size} bytes, have {self.remaining()}")
        chunk = self.data[self.pos : self.pos + size]
        self.pos += size
        return chunk

    def u8(self) -> int:
        """
        Read one unsigned byte
        """
        return self.take(1)[0]

    def u16(self) -> int:
        """
        Read one big-endian unsigned 16-bit value
        """
        return int.from_bytes(self.take(2), "big")

    def vec8(self) -> bytes:
        """
        Read a block prefixed by a 1-byte length
        """
        length = self.u8()
        return self.take(length)

    def vec16(self) -> bytes:
        """
        Read a block prefixed by a 2-byte length
        """
        length = self.u16()
        return self.take(length)


@dataclass
class KeyShareEntry:
    group: int
    key_length: int


@dataclass
class ClientHello:
    record_version: int
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: list[int]
    compression_methods: list[int]
    extensions: list[tuple[int, bytes]]
    server_name: str | None
    alpn: list[str]
    supported_groups: list[int]
    key_shares: list[KeyShareEntry]
    signature_algorithms: list[int]
    supported_versions: list[int]
    psk_key_exchange_modes: list[int]
    ec_point_formats: list[int]
    cert_compression: list[int]
    alps_protocols: list[str]
    alps_type: int | None
    record_size_limit: int | None
    status_request: bool
    trust_anchor_ids: list[bytes]
    raw: bytes

    def extension_types(self) -> list[int]:
        """
        List extension types in wire order, GREASE included
        """
        return [ext_type for ext_type, _ in self.extensions]

    def extension_body(self, ext_type: int) -> bytes | None:
        """
        Return the body of the first extension with the given type, or None
        """
        for current_type, body in self.extensions:
            if current_type == ext_type:
                return body
        return None

    def ja3(self) -> str:
        """
        Build the full JA3 string with GREASE removed
        """
        fields = [
            str(self.legacy_version),
            _join_decimal(self.cipher_suites),
            _join_decimal(self.extension_types()),
            _join_decimal(self.supported_groups),
            _join_decimal(self.ec_point_formats),
        ]
        return ",".join(fields)

    def ja3_hash(self) -> str:
        """
        Return the md5 hex digest of the JA3 string
        """
        return hashlib.md5(self.ja3().encode("ascii")).hexdigest()

    def ja4(self) -> str:
        """
        Build the hashed JA4 fingerprint for TCP
        """
        ciphers = self._ja4_ciphers()
        extensions = self._ja4_extensions()
        sigalgs = self._ja4_sigalgs()

        if ciphers:
            part_b = _truncated_sha256(",".join(ciphers))
        else:
            part_b = _empty_hash()

        if extensions:
            part_c_input = ",".join(extensions)
            if sigalgs:
                part_c_input += "_" + ",".join(sigalgs)
            part_c = _truncated_sha256(part_c_input)
        else:
            part_c = _empty_hash()

        return f"{self._ja4_prefix()}_{part_b}_{part_c}"

    def ja4_r(self) -> str:
        """
        Build the unhashed JA4 fingerprint for TCP
        """
        parts = [
            self._ja4_prefix(),
            ",".join(self._ja4_ciphers()),
            ",".join(self._ja4_extensions()),
        ]
        sigalgs = self._ja4_sigalgs()
        if sigalgs:
            parts.append(",".join(sigalgs))
        return "_".join(parts)

    def _ja4_prefix(self) -> str:
        """
        Build the JA4 section a: protocol, version, SNI flag, counts and ALPN characters
        """
        versions = [version for version in self.supported_versions if not is_grease(version)]
        version = max(versions) if versions else self.legacy_version
        version_text = ja4_versions.get(version, "00")
        sni_flag = "d" if self.server_name is not None else "i"
        cipher_count = min(len([c for c in self.cipher_suites if not is_grease(c)]), 99)
        ext_count = min(len([t for t in self.extension_types() if not is_grease(t)]), 99)
        return f"t{version_text}{sni_flag}{cipher_count:02d}{ext_count:02d}{_alpn_chars(self.alpn)}"

    def _ja4_ciphers(self) -> list[str]:
        """
        Return sorted non-GREASE cipher suites as 4-digit hex
        """
        values = sorted(c for c in self.cipher_suites if not is_grease(c))
        return [f"{c:04x}" for c in values]

    def _ja4_extensions(self) -> list[str]:
        """
        Return sorted extension types as 4-digit hex, excluding SNI, ALPN and GREASE
        """
        values = sorted(t for t in self.extension_types() if not is_grease(t) and t not in (ext_server_name, ext_alpn))
        return [f"{t:04x}" for t in values]

    def _ja4_sigalgs(self) -> list[str]:
        """
        Return signature algorithms in wire order as 4-digit hex, GREASE excluded
        """
        return [f"{s:04x}" for s in self.signature_algorithms if not is_grease(s)]


def is_grease(value: int) -> bool:
    """
    Check whether value is an RFC 8701 GREASE codepoint
    """
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def read_client_hello(data: bytes) -> tuple[ClientHello | None, int]:
    """
    Parse a ClientHello from buffered TLS records, returning (None, 0) when more bytes are needed
    """
    if not data:
        return None, 0
    if data[0] != content_type_handshake:
        raise ValueError(f"not a TLS handshake record: first byte is 0x{data[0]:02x}")
    if len(data) >= 6 and data[5] != handshake_client_hello:
        raise ValueError(f"expected ClientHello (0x01), got handshake type 0x{data[5]:02x}")

    handshake = bytearray()
    pos = 0
    record_version = None
    message_length = None
    while True:
        if len(data) < pos + 5:
            return None, 0
        if data[pos] != content_type_handshake:
            raise ValueError(f"record type 0x{data[pos]:02x} inside ClientHello, expected 0x16")
        if record_version is None:
            record_version = int.from_bytes(data[pos + 1 : pos + 3], "big")
        record_length = int.from_bytes(data[pos + 3 : pos + 5], "big")
        record_end = pos + 5 + record_length
        if len(data) < record_end:
            return None, 0
        handshake += data[pos + 5 : record_end]
        pos = record_end

        if message_length is None and len(handshake) >= 4:
            message_length = 4 + int.from_bytes(handshake[1:4], "big")
        if message_length is not None and len(handshake) >= message_length:
            break

    message = bytes(handshake[:message_length])
    return _parse_client_hello(message, record_version), pos


def _parse_client_hello(message: bytes, record_version: int) -> ClientHello:
    """
    Decode a complete handshake message (type, length, body) into a ClientHello
    """
    body = _Reader(message)
    body.take(4)
    legacy_version = body.u16()
    random = body.take(32)
    session_id = body.vec8()
    cipher_suites = _split_u16(body.vec16())
    compression_methods = list(body.vec8())

    extensions = []
    if body.remaining():
        ext_reader = _Reader(body.vec16())
        while ext_reader.remaining():
            ext_type = ext_reader.u16()
            ext_length = ext_reader.u16()
            extensions.append((ext_type, ext_reader.take(ext_length)))

    alps_type = None
    alps_protocols = []
    for ext_type, ext_body in extensions:
        if ext_type in (ext_alps, ext_alps_old):
            alps_type = ext_type
            alps_protocols = _parse_string_list(ext_body)
            break

    return ClientHello(
        record_version=record_version,
        legacy_version=legacy_version,
        random=random,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        extensions=extensions,
        server_name=_view(extensions, ext_server_name, _parse_server_name, None),
        alpn=_view(extensions, ext_alpn, _parse_string_list, []),
        supported_groups=_view(extensions, ext_supported_groups, _parse_u16_list, []),
        key_shares=_view(extensions, ext_key_share, _parse_key_shares, []),
        signature_algorithms=_view(extensions, ext_signature_algorithms, _parse_u16_list, []),
        supported_versions=_view(extensions, ext_supported_versions, _parse_u8_u16_list, []),
        psk_key_exchange_modes=_view(extensions, ext_psk_key_exchange_modes, _parse_u8_list, []),
        ec_point_formats=_view(extensions, ext_ec_point_formats, _parse_u8_list, []),
        cert_compression=_view(extensions, ext_cert_compression, _parse_u8_u16_list, []),
        alps_protocols=alps_protocols,
        alps_type=alps_type,
        record_size_limit=_view(extensions, ext_record_size_limit, _parse_u16, None),
        status_request=any(ext_type == ext_status_request for ext_type, _ in extensions),
        trust_anchor_ids=_view(extensions, ext_trust_anchors, _parse_trust_anchor_ids, []),
        raw=message,
    )


def _view(extensions: list[tuple[int, bytes]], ext_type: int, parser, default):
    """
    Parse the body of ext_type with parser, or return default when the extension is absent
    """
    for current_type, body in extensions:
        if current_type == ext_type:
            return parser(body)
    return default


def _parse_server_name(body: bytes) -> str | None:
    """
    Return the first host_name entry of a server_name extension
    """
    reader = _Reader(_Reader(body).vec16())
    while reader.remaining():
        name_type = reader.u8()
        name_length = reader.u16()
        name = reader.take(name_length)
        if name_type == 0:
            return name.decode("latin-1")
    return None


def _parse_key_shares(body: bytes) -> list[KeyShareEntry]:
    """
    Decode the key_share entries as group and key length pairs
    """
    reader = _Reader(_Reader(body).vec16())
    entries = []
    while reader.remaining():
        group = reader.u16()
        key_length = reader.u16()
        reader.take(key_length)
        entries.append(KeyShareEntry(group=group, key_length=key_length))
    return entries


def _parse_string_list(body: bytes) -> list[str]:
    """
    Decode a u16-prefixed list of u8-prefixed strings, used by ALPN and ALPS
    """
    return _split_strings(_Reader(body).vec16())


def _split_strings(data: bytes) -> list[str]:
    """
    Split a run of u8-length-prefixed strings
    """
    reader = _Reader(data)
    values = []
    while reader.remaining():
        length = reader.u8()
        values.append(reader.take(length).decode("latin-1"))
    return values


def _parse_u16_list(body: bytes) -> list[int]:
    """
    Decode a u16-length-prefixed list of u16 values
    """
    return _split_u16(_Reader(body).vec16())


def _parse_u8_u16_list(body: bytes) -> list[int]:
    """
    Decode a u8-length-prefixed list of u16 values
    """
    return _split_u16(_Reader(body).vec8())


def _parse_u8_list(body: bytes) -> list[int]:
    """
    Decode a u8-length-prefixed list of u8 values
    """
    return list(_Reader(body).vec8())


def _parse_trust_anchor_ids(body: bytes) -> list[bytes]:
    """
    Decode a u16-length-prefixed list of u8-length-prefixed trust anchor identifiers
    """
    reader = _Reader(_Reader(body).vec16())
    entries = []
    while reader.remaining():
        entries.append(reader.vec8())
    return entries


def _parse_u16(body: bytes) -> int:
    """
    Decode a single big-endian u16 extension body
    """
    return _Reader(body).u16()


def _split_u16(data: bytes) -> list[int]:
    """
    Split a byte run into big-endian u16 values
    """
    if len(data) % 2:
        raise ValueError(f"u16 list has odd length {len(data)}")
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


def _join_decimal(values: list[int]) -> str:
    """
    Join non-GREASE values in decimal with "-"
    """
    return "-".join(str(v) for v in values if not is_grease(v))


def _alpn_chars(alpn: list[str]) -> str:
    """
    Build the two JA4 ALPN characters from the first ALPN value
    """
    if not alpn or not alpn[0]:
        return "00"
    value = alpn[0]
    if value[0].isascii() and value[0].isalnum() and value[-1].isascii() and value[-1].isalnum():
        return value[0] + value[-1]
    hexed = value.encode("latin-1").hex()
    return hexed[0] + hexed[-1]


def _truncated_sha256(text: str) -> str:
    """
    Return the first 12 hex characters of the sha256 of text
    """
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _empty_hash() -> str:
    """
    Return the JA4 placeholder hash used when a list is empty
    """
    return "000000000000"
