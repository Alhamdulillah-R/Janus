"""
Render a JanusProfile as Python source that rebuilds it with named enums.
"""

from __future__ import annotations

import enum
import json
from typing import TYPE_CHECKING

from .profile import GREASE, JanusHpack, JanusHttp2, JanusPriority, JanusTls, PseudoHeader
from .registry import (
    CertCompressionAlgorithm,
    CipherSuite,
    ExtensionType,
    H2Setting,
    NamedGroup,
    SignatureScheme,
    TlsVersion,
)

if TYPE_CHECKING:
    from .profile import JanusProfile


class ProfileWriter:
    """
    Python source writer for one profile.
    """

    def __init__(self, profile: JanusProfile, variable: str):
        self.profile = profile
        self.variable = variable
        # names imported from janus_requests and janus_requests.registry by the generated code
        self.package_names: set[str] = {"JanusProfile"}
        self.registry_names: set[str] = set()
        self.hex_line_chars = 64

    def render(self) -> str:
        """
        Imports plus `variable = JanusProfile(...)`.
        """
        body = self.expression()
        return self.imports() + f"\n\n{self.variable} = {body}\n"

    def expression(self) -> str:
        """
        The `JanusProfile(...)` call; records the names it needs for imports().
        """
        p = self.profile
        return self.call(
            "JanusProfile",
            [
                ("name", self.string(p.name)),
                ("tls", self.tls(p.tls, 1)),
                ("http2", self.http2(p.http2, 1)),
                ("header_order", self.names(p.header_order, 1)),
            ],
            0,
        )

    def imports(self) -> str:
        lines = [self.import_line("janus_requests", self.package_names)]
        if self.registry_names:
            lines.append(self.import_line("janus_requests.registry", self.registry_names))
        return "\n".join(lines)

    def names(self, names: list[str], level: int) -> str:
        """
        A list of strings, one per line.
        """
        return self.items([self.string(n) for n in names], level)

    def import_line(self, module: str, names: set[str]) -> str:
        ordered = sorted(names, key=lambda n: (not n.isupper(), n))
        if len(ordered) <= 3:
            return f"from {module} import {', '.join(ordered)}"
        inner = "".join(f"    {n},\n" for n in ordered)
        return f"from {module} import (\n{inner})"

    def tls(self, tls: JanusTls, level: int) -> str:
        self.package_names.add("JanusTls")
        fields = [
            ("ciphers", self.codes(CipherSuite, tls.ciphers, level + 1)),
            ("extensions", self.codes(ExtensionType, tls.extensions, level + 1)),
            ("groups", self.codes(NamedGroup, tls.groups, level + 1)),
            ("key_shares", self.codes(NamedGroup, tls.key_shares, level + 1)),
            ("signature_algorithms", self.codes(SignatureScheme, tls.signature_algorithms, level + 1)),
            ("versions", self.codes(TlsVersion, tls.versions, level + 1)),
            ("alpn", self.items([self.string(a) for a in tls.alpn], level + 1)),
        ]
        if tls.alps:
            entries = [(self.string(proto), self.bytes_literal(s, level + 2)) for proto, s in tls.alps.items()]
            fields.append(("alps", self.mapping(entries, level + 1)))
        if tls.cert_compression:
            fields.append(("cert_compression", self.codes(CertCompressionAlgorithm, tls.cert_compression, level + 1)))
        if tls.raw_extensions:
            entries = [
                (self.code(ExtensionType, t), self.bytes_literal(body, level + 2))
                for t, body in tls.raw_extensions.items()
            ]
            fields.append(("raw_extensions", self.mapping(entries, level + 1)))
        for flag in ("ocsp", "ech_grease", "permute_extensions"):
            if getattr(tls, flag):
                fields.append((flag, "True"))
        return self.call("JanusTls", fields, level)

    def http2(self, http2: JanusHttp2, level: int) -> str:
        self.package_names.add("JanusHttp2")
        settings = [f"({self.code(H2Setting, i)}, {v})" for i, v in http2.settings]
        fields = [("settings", self.items(settings, level + 1))]

        if http2.window_update:
            fields.append(("window_update", str(http2.window_update)))
        if http2.priority_frames:
            frames = [f"({sid}, {self.priority(p)})" for sid, p in http2.priority_frames]
            fields.append(("priority_frames", self.items(frames, level + 1)))

        self.package_names.add("PseudoHeader")
        pseudo = [f"PseudoHeader.{PseudoHeader(p).name}" for p in http2.pseudo_order]
        fields.append(("pseudo_order", self.items(pseudo, level + 1)))

        if http2.headers_priority is not None:
            fields.append(("headers_priority", self.priority(http2.headers_priority)))
        self.package_names.add("PriorityMode")
        fields.append(("priority_mode", self.member(http2.priority_mode)))
        if http2.hpack is not None:
            fields.append(("hpack", self.hpack(http2.hpack, level + 1)))
        return self.call("JanusHttp2", fields, level)

    def hpack(self, hpack: JanusHpack, level: int) -> str:
        self.package_names.update({"JanusHpack", "Huffman", "Indexing"})
        rules = [(self.string(name), self.member(indexing)) for name, indexing in hpack.rules.items()]
        fields = [
            ("huffman", self.member(hpack.huffman)),
            ("indexing", self.member(hpack.indexing)),
            ("rules", self.mapping(rules, level + 1)),
            ("crumble_cookies", str(hpack.crumble_cookies)),
        ]
        return self.call("JanusHpack", fields, level)

    def priority(self, p: JanusPriority) -> str:
        self.package_names.add("JanusPriority")
        return f"JanusPriority(depends_on={p.depends_on}, weight={p.weight}, exclusive={p.exclusive})"

    def member(self, value: enum.Enum) -> str:
        return f"{type(value).__name__}.{value.name}"

    def code(self, enum_cls: type[enum.IntEnum], value: int) -> str:
        """
        GREASE, the registry member name, or a hex literal for an unregistered value.
        """
        if value == GREASE:
            self.package_names.add("GREASE")
            return "GREASE"
        try:
            member = enum_cls(value)
        except ValueError:
            return f"0x{int(value):04x}"
        self.registry_names.add(enum_cls.__name__)
        return f"{enum_cls.__name__}.{member.name}"

    def codes(self, enum_cls: type[enum.IntEnum], values: list[int], level: int) -> str:
        return self.items([self.code(enum_cls, v) for v in values], level)

    def string(self, value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    def headers(self, headers: list[tuple[str, str | None]], level: int) -> str:
        """
        A header dict literal in wire order; None values render as None.
        """
        entries = [(self.string(n), "None" if v is None else self.string(v)) for n, v in headers]
        return self.mapping(entries, level)

    def bytes_literal(self, data: bytes, level: int) -> str:
        """
        bytes.fromhex(...), long values split over several string lines.
        """
        text = data.hex()
        if len(text) <= self.hex_line_chars:
            return f'bytes.fromhex("{text}")'

        pad = "    " * (level + 1)
        parts = [text[i : i + self.hex_line_chars] for i in range(0, len(text), self.hex_line_chars)]
        inner = "".join(f'{pad}"{part}"\n' for part in parts)
        return f"bytes.fromhex(\n{inner}{'    ' * level})"

    def items(self, rendered: list[str], level: int) -> str:
        """
        List literal: inline up to 3 items, one per line beyond that.
        """
        if not rendered:
            return "[]"
        if len(rendered) <= 3 and all("\n" not in r for r in rendered):
            return f"[{', '.join(rendered)}]"

        pad = "    " * (level + 1)
        inner = "".join(f"{pad}{r},\n" for r in rendered)
        return f"[\n{inner}{'    ' * level}]"

    def mapping(self, entries: list[tuple[str, str]], level: int) -> str:
        if not entries:
            return "{}"

        pad = "    " * (level + 1)
        inner = "".join(f"{pad}{k}: {v},\n" for k, v in entries)
        return f"{{\n{inner}{'    ' * level}}}"

    def call(self, name: str, fields: list[tuple[str, str]], level: int) -> str:
        pad = "    " * (level + 1)
        inner = "".join(f"{pad}{key}={value},\n" for key, value in fields)
        return f"{name}(\n{inner}{'    ' * level})"
