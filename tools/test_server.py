"""
Local HTTP/1.1 test server for janus_requests's requests semantics (cookies, redirects, codings, auth, streaming).

usage: uv run --with brotli --with zstandard python test_server.py <port>
"""

import gzip
import hashlib
import json
import sys
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import brotli
import zstandard

digest_realm = "janus"
digest_nonce = "0123456789abcdef"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def send_body(self, status: int, body: bytes, headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        for name, value in headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def echo(self) -> dict:
        chunks = 0
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body, chunks = self.read_chunked()
        else:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
        return {
            "method": self.command,
            "path": self.path,
            "headers": [[k, v] for k, v in self.headers.items()],
            "body": body.decode("utf-8", "replace"),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_length": len(body),
            "chunks": chunks,
            "client_port": self.client_address[1],
        }

    def read_chunked(self) -> tuple[bytes, int]:
        body = b""
        chunks = 0
        while True:
            size = int(self.rfile.readline().split(b";")[0].strip(), 16)
            if size == 0:
                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                return body, chunks
            body += self.rfile.read(size)
            self.rfile.readline()
            chunks += 1

    def handle_any(self) -> None:
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        parts = [p for p in url.path.split("/") if p]
        route = parts[0] if parts else ""

        if route == "echo":
            self.send_body(200, json.dumps(self.echo()).encode(), [("Content-Type", "application/json")])
        elif route == "set-cookie":
            self.echo()
            headers = [("Set-Cookie", f"{k}={v[0]}; Path=/") for k, v in query.items()]
            self.send_body(200, b"ok", headers)
        elif route == "redirect":
            self.echo()
            left = int(parts[1])
            target = f"/redirect/{left - 1}" if left > 1 else "/echo"
            self.send_body(302, b"", [("Location", target), ("Set-Cookie", f"hop{left}=1; Path=/")])
        elif route == "redirect-code":
            self.echo()
            self.send_body(int(parts[1]), b"", [("Location", "/echo")])
        elif route == "coding":
            self.echo()
            coding = parts[1]
            raw = ("janus " * 2000).encode()
            if coding == "gzip":
                data = gzip.compress(raw)
            elif coding == "deflate":
                data = zlib.compress(raw)
            elif coding == "br":
                data = brotli.compress(raw)
            elif coding == "zstd":
                data = zstandard.ZstdCompressor().compress(raw)
            else:
                data = raw
            self.send_body(200, data, [("Content-Encoding", coding), ("Content-Type", "text/plain; charset=utf-8")])
        elif route == "chunked":
            self.echo()
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            for i in range(5):
                line = f"line {i}\n".encode()
                self.wfile.write(f"{len(line):x}\r\n".encode() + line + b"\r\n")
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
        elif route == "slow":
            self.echo()
            time.sleep(float(query.get("delay", ["2"])[0]))
            self.send_body(200, b"slow")
        elif route == "status":
            self.echo()
            self.send_body(int(parts[1]), b"status")
        elif route == "basic-auth":
            self.echo()
            import base64

            expected = "Basic " + base64.b64encode(f"{parts[1]}:{parts[2]}".encode()).decode()
            if self.headers.get("Authorization") == expected:
                self.send_body(200, b"authorized")
            else:
                self.send_body(401, b"no", [("WWW-Authenticate", 'Basic realm="janus"')])
        elif route == "digest-auth":
            self.echo()
            self.digest(parts[1], parts[2])
        elif route == "dup":
            self.echo()
            self.send_body(
                200, b"dup", [("X-Dup", "a"), ("X-Dup", "b"), ("Set-Cookie", "c1=1"), ("Set-Cookie", "c2=2")]
            )
        elif route == "bytes":
            self.echo()
            self.send_body(200, bytes(i % 251 for i in range(int(parts[1]))))
        else:
            self.send_body(404, b"not found")

    def digest(self, user: str, password: str) -> None:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Digest "):
            challenge = f'Digest realm="{digest_realm}", nonce="{digest_nonce}", qop="auth", algorithm=MD5'
            self.send_body(401, b"challenge", [("WWW-Authenticate", challenge)])
            return

        fields = {}
        for item in header[len("Digest ") :].split(","):
            key, _, value = item.strip().partition("=")
            fields[key] = value.strip('"')

        ha1 = hashlib.md5(f"{user}:{digest_realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{self.command}:{fields.get('uri')}".encode()).hexdigest()
        expected = hashlib.md5(
            f"{ha1}:{digest_nonce}:{fields.get('nc')}:{fields.get('cnonce')}:auth:{ha2}".encode()
        ).hexdigest()
        if fields.get("response") == expected:
            self.send_body(200, b"digest ok")
        else:
            self.send_body(401, b"digest bad")

    do_GET = handle_any
    do_POST = handle_any
    do_PUT = handle_any
    do_PATCH = handle_any
    do_DELETE = handle_any
    do_HEAD = handle_any
    do_OPTIONS = handle_any


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
