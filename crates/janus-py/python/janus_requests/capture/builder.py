"""
Build a JanusProfile from captured ClientHellos and the first request of a connection.
"""

from __future__ import annotations

import copy
from collections import Counter

from ..profile import (
    GREASE,
    Huffman,
    Indexing,
    JanusHpack,
    JanusHttp2,
    JanusPriority,
    JanusProfile,
    JanusTls,
    PriorityMode,
    PseudoHeader,
    named,
)
from ..registry import ExtensionType
from .clienthello import ClientHello, is_grease
from .h2frames import ClientConnection, HeaderField, huffman_codes


class ProfileBuilder:
    """
    Turns what one browser sent into a JanusProfile; every inference is recorded in `notes`.
    """

    def __init__(self, hellos: list[ClientHello], name: str):
        self.hellos = hellos
        self.name = name
        self.notes: list[str] = []
        # one request from a client without JavaScript stands for both the page and the fetch
        self.single_request = False

        # extensions the Janus kernel builds itself from the profile lists and flags
        self.native_extensions = {
            0x0000,
            0x0005,
            0x000A,
            0x000B,
            0x000D,
            0x0010,
            0x0015,
            0x0017,
            0x001B,
            0x0023,
            0x0029,
            0x002B,
            0x002D,
            0x0033,
            0xFE0D,
            0xFF01,
        }
        # bodies the kernel produces for the fixed-content native extensions; anything else is sent raw
        self.native_bodies = {
            0x0005: bytes.fromhex("0100000000"),
            0x000B: bytes.fromhex("0100"),
            0x0017: b"",
            0x0023: b"",
            0x002D: bytes.fromhex("0101"),
            0xFF01: bytes.fromhex("00"),
        }
        # Chromium Spdy3PriorityToHttp2Weight, indexed by urgency
        self.chromium_weights = [256, 220, 183, 147, 110, 74, 37, 1]

    def build(
        self,
        document: list[tuple[str, str]],
        fetch: list[tuple[str, str]],
        connection: ClientConnection | None,
    ) -> list[tuple[JanusProfile, list[tuple[str, str]]]]:
        """
        Navigation and `_fetch` profiles, each with the headers that request carried (Janus sends no default headers).
        """
        tls = self.tls()

        if connection is not None and connection.headers:
            http2 = self.http2(connection)
        else:
            http2 = JanusProfile.builtin("chrome155").http2
            self.notes.append("no HTTP/2 connection was captured: http2 settings are copied from the chrome155 profile")

        headers, order = self.template(document, "navigation")
        navigation = JanusProfile(
            name=self.name,
            tls=tls,
            http2=http2,
            header_order=order,
        )

        fetch_headers, order = self.template(fetch, "fetch")
        fetch_profile = JanusProfile(
            name=f"{self.name}_fetch",
            tls=copy.deepcopy(tls),
            http2=copy.deepcopy(http2),
            header_order=order,
        )
        if self.single_request:
            self.notes.append(
                "captured from a single request (/janus-capture/now): fetch headers equal the page request, no JS client"
            )
        return [(navigation, headers), (fetch_profile, fetch_headers)]

    def base_hello(self) -> ClientHello:
        """
        The first ClientHello of a full handshake (no pre_shared_key), else the first one.
        """
        for hello in self.hellos:
            if 0x0029 not in hello.extension_types():
                return hello
        self.notes.append("every captured handshake was a resumption; extension bodies come from a resumed hello")
        return self.hellos[0]

    def grease(self, value: int) -> int:
        if is_grease(value):
            return GREASE
        return value

    def tls(self) -> JanusTls:
        hello = self.base_hello()
        types = hello.extension_types()
        extensions = [self.grease(t) for t in types]

        if 0x0000 not in types:
            position = 1 if extensions and extensions[0] == GREASE else 0
            extensions.insert(position, 0x0000)
            self.notes.append(
                "no server_name was sent (page opened by IP address): server_name inserted near the front; "
                "open https://localhost:PORT/ to capture its real position"
            )
        if 0x0029 not in types and any(0x0029 in h.extension_types() for h in self.hellos):
            extensions.append(0x0029)
        if 0x0029 not in extensions:
            self.notes.append(
                "no resumed handshake seen, so pre_shared_key (0x0029) is not in extensions: "
                "reload the page after a few seconds to capture one"
            )

        raw_extensions = {}
        for ext_type, body in hello.extensions:
            if is_grease(ext_type) or ext_type == 0x0029:
                continue
            if ext_type in self.native_extensions and self.native_bodies.get(ext_type, body) == body:
                continue
            raw_extensions[named(ExtensionType, ext_type)] = body

        tls = JanusTls(
            ciphers=[self.grease(c) for c in hello.cipher_suites],
            extensions=extensions,
            groups=[self.grease(g) for g in hello.supported_groups],
            key_shares=[self.grease(k.group) for k in hello.key_shares],
            signature_algorithms=[self.grease(s) for s in hello.signature_algorithms],
            versions=[self.grease(v) for v in hello.supported_versions],
            alpn=list(hello.alpn),
            cert_compression=list(hello.cert_compression),
            raw_extensions=raw_extensions,
            ocsp=0x0005 in types,
            ech_grease=0xFE0D in types,
            permute_extensions=self.permuted(),
        )
        tls = JanusTls.from_native(tls.to_native())

        if hello.alps_protocols:
            tls.alps = {proto: b"" for proto in hello.alps_protocols}
            self.notes.append(
                "client ALPS settings set to empty (what Chrome 155 sends); this server cannot negotiate ALPS to observe them"
            )
        return tls

    def permuted(self) -> bool:
        """
        Whether the extension order changed between captured ClientHellos.
        """
        orders = set()
        for hello in self.hellos:
            order = [t for t in hello.extension_types() if not is_grease(t) and t not in (0x0015, 0x0029)]
            orders.add(tuple(order))

        if len(orders) > 1:
            self.notes.append(f"extension order differed across {len(self.hellos)} handshakes: permute_extensions on")
            return True
        if len(self.hellos) == 1:
            self.notes.append("only one handshake captured: cannot tell whether the browser permutes extensions (off)")
        return False

    def http2(self, connection: ClientConnection) -> JanusHttp2:
        first = connection.headers[0]
        letters = {
            ":method": PseudoHeader.method,
            ":authority": PseudoHeader.authority,
            ":scheme": PseudoHeader.scheme,
            ":path": PseudoHeader.path,
        }

        headers_priority = None
        if first.priority is not None:
            headers_priority = JanusPriority(first.priority.depends_on, first.priority.weight, first.priority.exclusive)

        http2 = JanusHttp2(
            settings=list(connection.settings),
            window_update=connection.window_update,
            priority_frames=[
                (sid, JanusPriority(p.depends_on, p.weight, p.exclusive)) for sid, p in connection.priority_frames
            ],
            pseudo_order=[letters[f.name] for f in first.fields if f.name in letters],
            headers_priority=headers_priority,
            priority_mode=self.priority_mode(first.fields, headers_priority),
            hpack=self.hpack(connection),
        )
        return JanusHttp2.from_native(http2.to_native())

    def priority_mode(self, fields: list[HeaderField], priority: JanusPriority | None) -> PriorityMode:
        """
        chrome when the HEADERS priority matches Chromium's weight for the request's urgency.
        """
        if priority is None or not priority.exclusive:
            return PriorityMode.fixed

        urgency = 3
        for f in fields:
            if f.name != "priority":
                continue
            for item in f.value.split(","):
                item = item.strip()
                if item.startswith("u=") and item[2:].isdigit():
                    urgency = min(int(item[2:]), 7)

        if priority.weight == self.chromium_weights[urgency]:
            self.notes.append(
                f"HEADERS weight {priority.weight} matches Chromium for u={urgency}: priority_mode chrome"
            )
            return PriorityMode.chrome
        return PriorityMode.fixed

    def hpack(self, connection: ClientConnection) -> JanusHpack:
        """
        HPACK policy that reproduces how the captured header blocks were encoded.
        """
        literals = []
        representations: dict[str, str] = {}
        crumble = False

        for block in connection.headers:
            if sum(1 for f in block.fields if f.name == "cookie") > 1:
                crumble = True
            for f in block.fields:
                if f.representation == "indexed":
                    continue
                representations.setdefault(f.name, f.representation)
                if f.value_huffman is not None:
                    literals.append((f.value, f.value_huffman))
                if f.name_huffman is not None:
                    literals.append((f.name, f.name_huffman))

        indexing = {
            "incremental": Indexing.incremental,
            "without_indexing": Indexing.without_indexing,
            "never_indexed": Indexing.never_indexed,
        }
        default = Indexing.incremental
        if representations:
            default = indexing[Counter(representations.values()).most_common(1)[0][0]]
        rules = {name: indexing[r] for name, r in representations.items() if indexing[r] != default}

        return JanusHpack(
            huffman=self.huffman_mode(literals),
            indexing=default,
            rules=rules,
            crumble_cookies=crumble,
        )

    def huffman_mode(self, literals: list[tuple[str, bool]]) -> Huffman:
        """
        Huffman mode consistent with every captured literal string.
        """
        if not literals:
            return Huffman.if_shorter
        if all(used == (self.huffman_length(text) < len(text.encode("latin-1"))) for text, used in literals):
            return Huffman.if_shorter
        if all(used for _, used in literals):
            return Huffman.always
        if not any(used for _, used in literals):
            return Huffman.never

        self.notes.append("Huffman use fits none of always/never/if_shorter exactly; using if_shorter")
        return Huffman.if_shorter

    def huffman_length(self, text: str) -> int:
        bits = sum(huffman_codes[b][1] for b in text.encode("latin-1"))
        return (bits + 7) // 8

    def template(self, headers: list[tuple[str, str]], kind: str) -> tuple[list[tuple[str, str]], list[str]]:
        """
        Headers worth sending on every such request (per-request ones dropped) and the wire order of one request.
        """
        per_request = {
            "host",
            "connection",
            "content-length",
            "content-type",
            "cookie",
            "origin",
            "referer",
            "authorization",
        }
        template = [(n, v) for n, v in headers if n.lower() not in per_request]
        order = [n.lower() for n, _ in headers]
        values = {n.lower(): v for n, v in headers}

        if "HeadlessChrome" in values.get("user-agent", ""):
            self.notes.append(f"{kind}: captured from headless Chrome, the user-agent says HeadlessChrome")
        if kind == "fetch" and not self.single_request and values.get("priority", "").startswith("u=0"):
            self.notes.append(
                "fetch: the capture XHR is synchronous, which Chrome sends at u=0; fetch() and async XHR use u=1"
            )

        if "host" not in order:
            order[:0] = ["host", "connection"]
            self.notes.append(f"{kind}: HTTP/2 carries no Host/Connection; they lead header_order for HTTP/1.1")
        if "content-length" not in order:
            order.insert(order.index("connection") + 1 if "connection" in order else 0, "content-length")
            self.notes.append(f"{kind}: no request body, content-length placed after connection")
        if "cookie" not in order:
            self.notes.append(f"{kind}: no cookies were sent, cookie goes after the listed headers")
        return template, order
