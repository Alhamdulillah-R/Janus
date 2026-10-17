"""
Local HTTPS server that records a browser's ClientHellos and page request, and serves the JanusProfile they imply.
"""

from __future__ import annotations

import datetime
import html
import ipaddress
import logging
import select
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .builder import ProfileBuilder
from .clienthello import ClientHello, is_grease, read_client_hello
from .h2frames import ClientConnection, ClientStream, HeadersBlock
from .module import CaptureModule, is_module_name

log = logging.getLogger("janus_requests.capture")


@dataclass
class PageRequest:
    """
    The page request of one browser configuration and the connection it came on.
    """

    headers: list[tuple[str, str]]
    connection: ClientConnection | None
    protocol: str
    # the handler serving that connection; later requests on it refresh `connection`
    owner: object


class CaptureServer(socketserver.ThreadingTCPServer):
    """
    Captures from one browser are written to `out_dir` as an importable `<name>.py` and shown on the page.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8443,
        out_dir: str | Path = "captured",
        name: str = "captured",
        cert: str | Path | None = None,
        key: str | Path | None = None,
        rounds: int = 4,
    ):
        if not is_module_name(name):
            raise ValueError(f"capture name {name!r} must be a Python identifier, e.g. my_chrome")

        self.out_dir = Path(out_dir)
        self.name = name
        self.lock = threading.Lock()
        # ClientHellos grouped by browser configuration (order-independent), oldest first
        self.hellos: dict[tuple, list[ClientHello]] = {}
        # last page request per browser configuration
        self.documents: dict[tuple, PageRequest] = {}
        # fetch() rounds the page sends after loading, each on a new connection
        self.rounds = rounds
        self.peek_timeout_s = 10
        self.idle_timeout_s = 5
        # how long a closing connection waits for the client to hang up
        self.drain_timeout_s = 2
        self.max_data_frame = 16384

        self.out_dir.mkdir(parents=True, exist_ok=True)
        if cert is None:
            cert, key = self.generate_certificate(host)
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(str(cert), None if key is None else str(key))
        self.context.set_alpn_protocols(["h2", "http/1.1"])

        super().__init__((host, port), CaptureHandler)

    def generate_certificate(self, host: str) -> tuple[Path, Path]:
        """
        Self-signed certificate for host, localhost and 127.0.0.1 (needs the `cryptography` package).
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError as e:
            raise SystemExit(
                "generating the capture certificate needs cryptography: install janus-requests[capture], "
                "or pass --cert/--key"
            ) from e

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "janus capture")])
        names: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))

        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, hashes.SHA256())
        )

        directory = Path(tempfile.mkdtemp(prefix="janus-capture-"))
        cert_path = directory / "cert.pem"
        key_path = directory / "key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    def remember(self, hello: ClientHello) -> tuple:
        """
        Store a ClientHello; returns its browser-configuration key.
        """
        ignored = {0x0015, 0x0029}
        group = (
            tuple(sorted(c for c in hello.cipher_suites if not is_grease(c))),
            tuple(sorted(t for t in hello.extension_types() if not is_grease(t) and t not in ignored)),
        )
        with self.lock:
            hellos = self.hellos.setdefault(group, [])
            hellos.append(hello)
        return group

    def page(self, report: bytes) -> bytes:
        """
        Capture page: the report of the page request, then fetch() rounds that each land on a new connection.
        """
        script = f"""<script>
var rounds = {self.rounds + 1};
function next(round) {{
  if (round > rounds) return;
  setTimeout(function () {{
    fetch("/janus-capture/round?n=" + round + "&t=" + Date.now())
      .then(function (r) {{ return r.text(); }})
      .then(function (t) {{
        document.getElementById("out").innerHTML = t;
        document.getElementById("round").textContent = "round " + round + " / " + rounds + (round < rounds ? ", next in a moment" : ", done");
        next(round + 1);
      }});
  }}, 1500);
}}
next(1);
</script>"""
        head = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>Janus capture</title>
<style>body{font-family:system-ui,sans-serif;margin:2em;line-height:1.5}pre{background:#f4f4f4;padding:1em;overflow:auto}</style>
</head><body><div id="out">"""
        tail = b"""</div><p id="round">more handshakes need JavaScript; without it this capture is final</p>\n"""
        return head + report + tail + script.encode() + b"\n</body></html>\n"

    def publish(self, group: tuple) -> bytes:
        """
        Write `<name>.py` (importable) and `<name>.json` from the page request and every handshake so far; returns the report.
        """
        with self.lock:
            document = self.documents.get(group)
            hellos = list(self.hellos.get(group, []))
        if document is None:
            log.info("round request before any page request from the same TLS configuration; open / first")
            return b"<p>open / first: the page request was not captured for this browser</p>"
        headers, connection, protocol = document.headers, document.connection, document.protocol

        builder = ProfileBuilder(hellos, self.name)
        profile, template = builder.build(headers, connection)
        user_agent = next((v for n, v in headers if n.lower() == "user-agent"), "(none)")
        summary = [
            f"captured  {time.strftime('%Y-%m-%d %H:%M:%S')} over {protocol}, {len(hellos)} TLS handshake(s)",
            f"browser   {user_agent}",
            f"JA4       {hellos[-1].ja4()}",
            f"Akamai    {profile.http2.akamai()}",
        ]
        code = CaptureModule(self.name, profile, template).render(summary, builder.notes)

        module = self.out_dir / f"{self.name}.py"
        # one module per name: the latest capture replaces it
        with self.lock:
            module.write_text(code, encoding="utf-8")
            profile.save(self.out_dir / f"{profile.name}.json")
        log.info(
            "captured %s over %s, %d handshake(s): %s (import %s)", self.name, protocol, len(hellos), module, self.name
        )
        for note in builder.notes:
            log.info("  note: %s", note)

        notes = "".join(f"<li>{html.escape(n)}</li>" for n in builder.notes)
        lines = "<br>".join(html.escape(line) for line in summary)
        report = (
            f"<h1>Janus capture</h1><p>{lines}</p>"
            f"<p>saved to {html.escape(str(module))} &mdash; <code>import {html.escape(self.name)}</code>, "
            f"then <code>{html.escape(self.name)}.session()</code></p>"
            f"<h2>notes</h2><ul>{notes}</ul><pre>{html.escape(code)}</pre>"
        )
        return report.encode("utf-8")

    def respond(
        self,
        group: tuple,
        path: str,
        headers: list[tuple[str, str]],
        connection: ClientConnection | None,
        protocol: str,
        owner: object,
    ) -> tuple[int, bytes]:
        """
        Status and body for one request; `owner` identifies the connection it came on.
        """
        if path == "/":
            with self.lock:
                self.documents[group] = PageRequest(headers, connection, protocol, owner)
            return 200, self.page(self.publish(group))
        if path.startswith("/janus-capture/round"):
            # the first round reuses the page connection: its header blocks show how literals are encoded
            with self.lock:
                document = self.documents.get(group)
                if document is not None and document.owner is owner:
                    document.connection = connection
            return 200, self.publish(group)
        return 404, b""


class CaptureHandler(socketserver.BaseRequestHandler):
    """
    One TCP connection: peek the ClientHello, finish TLS, answer requests.
    """

    server: CaptureServer

    def handle(self) -> None:
        sock: socket.socket = self.request

        try:
            hello = self.peek_client_hello(sock)
        except (ValueError, OSError) as e:
            log.warning("no ClientHello from %s: %s", self.client_address, e)
            return
        if hello is None:
            return
        group = self.server.remember(hello)

        try:
            tls = self.server.context.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError) as e:
            # browsers reject the self-signed certificate once before the user proceeds
            log.info("handshake from %s ended: %s (ClientHello recorded)", self.client_address, e)
            return

        try:
            if tls.selected_alpn_protocol() == "h2":
                self.serve_h2(tls, group)
            else:
                self.serve_h1(tls, group)
        except (ssl.SSLError, OSError) as e:
            log.info("connection from %s closed: %s", self.client_address, e)
        except ValueError as e:
            log.warning("malformed request from %s: %s", self.client_address, e)
        finally:
            tls.close()

    def peek_client_hello(self, sock: socket.socket) -> ClientHello | None:
        """
        Read the ClientHello without consuming it, so the TLS handshake still sees it.
        """
        deadline = time.monotonic() + self.server.peek_timeout_s
        seen = 0

        while time.monotonic() < deadline:
            ready, _, _ = select.select([sock], [], [], 0.2)
            if not ready:
                continue

            data = sock.recv(65536, socket.MSG_PEEK)
            if not data:
                return None
            hello, _ = read_client_hello(data)
            if hello is not None:
                return hello
            if len(data) == seen:
                # nothing new arrived since the last peek; wait for the rest of the record
                time.sleep(0.01)
            seen = len(data)
        raise ValueError("incomplete ClientHello")

    def serve_h2(self, tls: ssl.SSLSocket, group: tuple) -> None:
        stream = ClientStream()
        seen = 0
        # request blocks whose body has not ended yet, by stream id
        pending: dict[int, HeadersBlock] = {}

        tls.sendall(self.frame(4, 0, 0, b""))
        tls.settimeout(self.server.idle_timeout_s)
        settings_acked = False
        closing = False

        while not closing:
            try:
                data = tls.recv(65536)
            except TimeoutError:
                break
            if not data:
                break

            frames = stream.feed(data)
            connection = stream.connection()
            if connection.settings and not settings_acked:
                tls.sendall(self.frame(4, 1, 0, b""))
                settings_acked = True

            ready = []
            for block in connection.headers[seen:]:
                if block.end_stream:
                    ready.append(block)
                else:
                    pending[block.stream_id] = block
            seen = len(connection.headers)
            for frame in frames:
                if frame.type == 0 and frame.flags & 0x1 and frame.stream_id in pending:
                    ready.append(pending.pop(frame.stream_id))

            for block in ready:
                path = next((f.value for f in block.fields if f.name == ":path"), "/")
                headers = [(f.name, f.value) for f in block.fields if not f.name.startswith(":")]
                status, body = self.server.respond(group, path, headers, connection, "h2", self)
                self.respond_h2(tls, block.stream_id, status, body)
                # every round after the page starts a new TLS connection
                if path.startswith("/janus-capture/"):
                    closing = True

        # GOAWAY, last stream id, NO_ERROR
        snapshot = stream.connection()
        last = snapshot.headers[-1].stream_id if snapshot.headers else 0
        tls.sendall(self.frame(7, 0, 0, last.to_bytes(4, "big") + bytes(4)))
        if closing:
            self.drain(tls)

    def drain(self, tls: ssl.SSLSocket) -> None:
        """
        Read until the client closes: closing with unread data sends a TCP RST that can wipe the response and tickets.
        """
        tls.settimeout(self.server.drain_timeout_s)
        try:
            while tls.recv(65536):
                pass
        except (TimeoutError, ssl.SSLError, OSError):
            return

    def respond_h2(self, tls: ssl.SSLSocket, stream_id: int, status: int, body: bytes | None) -> None:
        body = body or b""
        block = self.hpack_literal(":status", str(status))
        block += self.hpack_literal("content-type", "text/html; charset=utf-8")
        block += self.hpack_literal("content-length", str(len(body)))
        block += self.hpack_literal("cache-control", "no-store")

        if not body:
            tls.sendall(self.frame(1, 0x4 | 0x1, stream_id, block))
            return

        tls.sendall(self.frame(1, 0x4, stream_id, block))
        for start in range(0, len(body), self.server.max_data_frame):
            piece = body[start : start + self.server.max_data_frame]
            last = start + self.server.max_data_frame >= len(body)
            tls.sendall(self.frame(0, 0x1 if last else 0, stream_id, piece))

    def serve_h1(self, tls: ssl.SSLSocket, group: tuple) -> None:
        tls.settimeout(self.server.idle_timeout_s)
        buffer = b""

        while b"\r\n\r\n" not in buffer:
            data = tls.recv(65536)
            if not data:
                return
            buffer += data

        head, _, rest = buffer.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        target = lines[0].split(" ")[1] if " " in lines[0] else "/"
        headers = []
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers.append((name, value.strip()))

        length = next((int(v) for n, v in headers if n.lower() == "content-length"), 0)
        while len(rest) < length:
            data = tls.recv(65536)
            if not data:
                return
            rest += data

        status, body = self.server.respond(group, target, headers, None, "http/1.1", self)
        reason = "OK" if status == 200 else "Not Found"
        tls.sendall(
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n".encode()
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )

    def frame(self, frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + stream_id.to_bytes(4, "big") + payload

    def hpack_literal(self, name: str, value: str) -> bytes:
        """
        Literal header field without indexing, new name, no Huffman.
        """
        return b"\x00" + self.hpack_string(name) + self.hpack_string(value)

    def hpack_string(self, text: str) -> bytes:
        data = text.encode("latin-1")
        return self.hpack_integer(len(data), 7) + data

    def hpack_integer(self, value: int, prefix_bits: int) -> bytes:
        limit = (1 << prefix_bits) - 1
        if value < limit:
            return bytes([value])

        out = bytearray([limit])
        value -= limit
        while value >= 128:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)
