"""
JanusProfile: an editable client identity made of the ClientHello, the HTTP/2 connection and the request header order.
"""

from __future__ import annotations

import copy
import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import _native
from .registry import (
    CertCompressionAlgorithm,
    CipherSuite,
    ExtensionType,
    H2Setting,
    NamedGroup,
    SignatureScheme,
    TlsVersion,
)

# ==========================================================================
# placeholder inside any TLS list: replaced by a fresh GREASE value on every connection
GREASE: int = _native.GREASE
# ==========================================================================


class PseudoHeader(str, enum.Enum):
    """
    HTTP/2 request pseudo-header, valued by its Akamai fingerprint letter.
    """

    method = "m"
    authority = "a"
    scheme = "s"
    path = "p"


class PriorityMode(str, enum.Enum):
    """
    How HEADERS frames get a priority when the request does not pass one.
    """

    # headers_priority on every stream
    fixed = "fixed"
    # Chromium: exclusive dependency on the newest open stream of the same or higher urgency
    chrome = "chrome"


class Huffman(str, enum.Enum):
    """
    When HPACK string literals are Huffman-coded.
    """

    always = "always"
    never = "never"
    if_shorter = "if_shorter"


class Indexing(str, enum.Enum):
    """
    HPACK literal representation for a header field.
    """

    incremental = "incremental"
    without_indexing = "without_indexing"
    never_indexed = "never_indexed"


def named(enum_cls: type[enum.IntEnum], value: int) -> int:
    """
    Enum member for value when the registry knows it, else the plain int (GREASE stays an int).
    """
    if value == GREASE:
        return value
    try:
        return enum_cls(value)
    except ValueError:
        return value


@dataclass
class JanusPriority:
    """
    RFC 7540 stream priority; weight is 1..256.
    """

    depends_on: int = 0
    weight: int = 16
    exclusive: bool = False

    def to_native(self) -> tuple[int, int, bool]:
        return self.depends_on, self.weight, self.exclusive


@dataclass
class JanusHpack:
    """
    HPACK encoding policy for request headers.
    """

    huffman: Huffman = Huffman.if_shorter
    indexing: Indexing = Indexing.incremental
    # per-name overrides, lowercase names, pseudo-headers with the leading ':'
    rules: dict[str, Indexing] = field(default_factory=dict)
    # split cookie values on ';' into separate fields
    crumble_cookies: bool = False

    @classmethod
    def from_native(cls, data: dict[str, Any]) -> JanusHpack:
        return cls(
            huffman=Huffman(data["huffman"]),
            indexing=Indexing(data["indexing"]),
            rules={name: Indexing(indexing) for name, indexing in data["rules"]},
            crumble_cookies=data["crumble_cookies"],
        )

    def to_native(self) -> dict[str, Any]:
        return {
            "huffman": Huffman(self.huffman).value,
            "indexing": Indexing(self.indexing).value,
            "rules": [(name.lower(), Indexing(indexing).value) for name, indexing in self.rules.items()],
            "crumble_cookies": self.crumble_cookies,
        }


@dataclass
class JanusTls:
    """
    ClientHello content as wire values; list order is wire order, GREASE marks a random GREASE value.
    """

    ciphers: list[int] = field(default_factory=list)
    # every extension type in wire order; types without a built-in encoder need a raw_extensions body
    extensions: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    # groups that get a key share, in order
    key_shares: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    versions: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    # client ALPS settings per protocol, sent when the server negotiates application_settings
    alps: dict[str, bytes] = field(default_factory=dict)
    cert_compression: list[int] = field(default_factory=list)
    # extension type -> exact body bytes
    raw_extensions: dict[int, bytes] = field(default_factory=dict)
    ocsp: bool = False
    ech_grease: bool = False
    # shuffle the extensions on every connection, as Chrome does
    permute_extensions: bool = False

    @classmethod
    def from_native(cls, data: dict[str, Any]) -> JanusTls:
        return cls(
            ciphers=[named(CipherSuite, v) for v in data["ciphers"]],
            extensions=[named(ExtensionType, v) for v in data["extensions"]],
            groups=[named(NamedGroup, v) for v in data["groups"]],
            key_shares=[named(NamedGroup, v) for v in data["key_shares"]],
            signature_algorithms=[named(SignatureScheme, v) for v in data["signature_algorithms"]],
            versions=[named(TlsVersion, v) for v in data["versions"]],
            alpn=list(data["alpn"]),
            alps={proto: bytes(settings) for proto, settings in data["alps"]},
            cert_compression=[named(CertCompressionAlgorithm, v) for v in data["cert_compression"]],
            raw_extensions={named(ExtensionType, t): bytes(body) for t, body in data["raw_extensions"]},
            ocsp=data["ocsp"],
            ech_grease=data["ech_grease"],
            permute_extensions=data["permute_extensions"],
        )

    @classmethod
    def from_spec(cls, text: str) -> JanusTls:
        """
        Parse the line-based spec format (`ciphers grease 1301 ...`).
        """
        return cls.from_native(_native.tls_from_spec(text))

    def to_native(self) -> dict[str, Any]:
        return {
            "ciphers": [int(v) for v in self.ciphers],
            "extensions": [int(v) for v in self.extensions],
            "groups": [int(v) for v in self.groups],
            "key_shares": [int(v) for v in self.key_shares],
            "signature_algorithms": [int(v) for v in self.signature_algorithms],
            "versions": [int(v) for v in self.versions],
            "alpn": list(self.alpn),
            "alps": [(proto, bytes(settings)) for proto, settings in self.alps.items()],
            "cert_compression": [int(v) for v in self.cert_compression],
            "raw_extensions": [(int(t), bytes(body)) for t, body in self.raw_extensions.items()],
            "ocsp": self.ocsp,
            "ech_grease": self.ech_grease,
            "permute_extensions": self.permute_extensions,
        }

    def to_spec(self) -> str:
        """
        Render as the line-based spec format.
        """
        return _native.tls_to_spec(self.to_native())

    def set_trust_anchors(self, anchor_ids: list[bytes]) -> None:
        """
        Set the trust_anchors (0xca34) body from binary trust anchor IDs, in the given order.
        """
        entries = b"".join(len(anchor).to_bytes(1, "big") + anchor for anchor in anchor_ids)
        self.raw_extensions[ExtensionType.trust_anchors] = len(entries).to_bytes(2, "big") + entries

    def trust_anchors(self) -> list[bytes]:
        """
        Binary trust anchor IDs carried in the trust_anchors (0xca34) body.
        """
        body = self.raw_extensions.get(ExtensionType.trust_anchors, b"")
        anchors = []
        pos = 2

        while pos < len(body):
            size = body[pos]
            anchors.append(body[pos + 1 : pos + 1 + size])
            pos += 1 + size
        return anchors

    def set_alps_offer(self, protocols: list[str], codepoint: int = ExtensionType.application_settings) -> None:
        """
        Set the ClientHello ALPS extension body offering protocols under codepoint (0x44cd or the old 0x4469).
        """
        entries = b"".join(len(p).to_bytes(1, "big") + p.encode() for p in protocols)
        self.raw_extensions[named(ExtensionType, codepoint)] = len(entries).to_bytes(2, "big") + entries


@dataclass
class JanusHttp2:
    """
    HTTP/2 connection preface and HEADERS shaping.
    """

    # SETTINGS in wire order, (id, value)
    settings: list[tuple[int, int]] = field(default_factory=list)
    # connection WINDOW_UPDATE increment sent after SETTINGS, 0 for none
    window_update: int = 0
    # PRIORITY frames sent after the preface, (stream id, priority)
    priority_frames: list[tuple[int, JanusPriority]] = field(default_factory=list)
    pseudo_order: list[PseudoHeader] = field(
        default_factory=lambda: [PseudoHeader.method, PseudoHeader.authority, PseudoHeader.scheme, PseudoHeader.path]
    )
    # priority on HEADERS frames under PriorityMode.fixed, None to send none
    headers_priority: JanusPriority | None = None
    priority_mode: PriorityMode = PriorityMode.fixed
    # None keeps the h2 crate encoder (always Huffman, nghttp2-style indexing)
    hpack: JanusHpack | None = None

    @classmethod
    def from_native(cls, data: dict[str, Any]) -> JanusHttp2:
        headers_priority = None
        if data["headers_priority"] is not None:
            headers_priority = JanusPriority(*data["headers_priority"])

        hpack = None
        if data["hpack"] is not None:
            hpack = JanusHpack.from_native(data["hpack"])

        return cls(
            settings=[(named(H2Setting, i), v) for i, v in data["settings"]],
            window_update=data["window_update"],
            priority_frames=[
                (sid, JanusPriority(dep, weight, excl)) for sid, dep, weight, excl in data["priority_frames"]
            ],
            pseudo_order=[PseudoHeader(c) for c in data["pseudo_order"]],
            headers_priority=headers_priority,
            priority_mode=PriorityMode(data["priority_mode"]),
            hpack=hpack,
        )

    @classmethod
    def from_akamai(cls, text: str) -> JanusHttp2:
        """
        Parse an Akamai fingerprint (SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order).
        """
        return cls.from_native(_native.http2_from_akamai(text))

    def to_native(self) -> dict[str, Any]:
        headers_priority = None
        if self.headers_priority is not None:
            headers_priority = self.headers_priority.to_native()

        hpack = None
        if self.hpack is not None:
            hpack = self.hpack.to_native()

        return {
            "settings": [(int(i), int(v)) for i, v in self.settings],
            "window_update": self.window_update,
            "priority_frames": [(sid, *p.to_native()) for sid, p in self.priority_frames],
            "pseudo_order": "".join(PseudoHeader(p).value for p in self.pseudo_order),
            "headers_priority": headers_priority,
            "priority_mode": PriorityMode(self.priority_mode).value,
            "hpack": hpack,
        }

    def akamai(self) -> str:
        """
        Akamai HTTP/2 fingerprint string.
        """
        settings = ";".join(f"{int(i)}:{v}" for i, v in self.settings)
        frames = ",".join(f"{sid}:{int(p.exclusive)}:{p.depends_on}:{p.weight}" for sid, p in self.priority_frames)
        pseudo = ",".join(PseudoHeader(p).value for p in self.pseudo_order)
        return f"{settings}|{self.window_update}|{frames or '0'}|{pseudo}"


@dataclass
class JanusProfile:
    """
    Complete client identity: ClientHello, HTTP/2 connection and header order; header values come from the caller.
    """

    name: str
    tls: JanusTls = field(default_factory=JanusTls)
    http2: JanusHttp2 = field(default_factory=JanusHttp2)
    # lowercase header names in wire order; unlisted headers go last
    header_order: list[str] = field(default_factory=list)

    @classmethod
    def builtin(cls, name: str) -> JanusProfile:
        """
        A built-in profile ("chrome155", "chrome155_fetch").
        """
        return cls.from_native(_native.builtin_profile(name))

    @classmethod
    def resolve(cls, value: str | JanusProfile) -> JanusProfile:
        """
        Independent copy of a profile given by name or object.
        """
        if isinstance(value, JanusProfile):
            return value.copy()
        return cls.builtin(value)

    @classmethod
    def from_native(cls, data: dict[str, Any]) -> JanusProfile:
        return cls(
            name=data["name"],
            tls=JanusTls.from_native(data["tls"]),
            http2=JanusHttp2.from_native(data["http2"]),
            header_order=list(data["header_order"]),
        )

    def to_native(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tls": self.tls.to_native(),
            "http2": self.http2.to_native(),
            "header_order": [n.lower() for n in self.header_order],
        }

    def copy(self) -> JanusProfile:
        return copy.deepcopy(self)

    def to_json(self) -> str:
        """
        JSON text of the profile, bytes as hex strings.
        """
        data = self.to_native()

        data["tls"]["alps"] = [(proto, settings.hex()) for proto, settings in data["tls"]["alps"]]
        data["tls"]["raw_extensions"] = [(t, body.hex()) for t, body in data["tls"]["raw_extensions"]]
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, text: str) -> JanusProfile:
        data = json.loads(text)

        data["tls"]["alps"] = [(proto, bytes.fromhex(h)) for proto, h in data["tls"]["alps"]]
        data["tls"]["raw_extensions"] = [(t, bytes.fromhex(h)) for t, h in data["tls"]["raw_extensions"]]
        return cls.from_native(data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> JanusProfile:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def to_python(self, variable: str = "profile") -> str:
        """
        Python source that rebuilds this profile into `variable`.
        """
        from .codegen import ProfileWriter

        return ProfileWriter(self, variable).render()
