"""
Local TLS HTTP/2 server that answers every request with what it received: headers, body hash and DATA frame count.
/early answers at once without reading the body, then resets the stream with NO_ERROR (RFC 9113 8.1).
/truncated announces 1000 bytes, sends 300 and resets with NO_ERROR without END_STREAM.

usage: uv run --with h2 --with cryptography python h2_echo_server.py <port>
"""

import asyncio
import datetime
import hashlib
import ipaddress
import json
import ssl
import sys
import tempfile
from pathlib import Path

import h2.config
import h2.connection
import h2.errors
import h2.events
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class EchoServer:
    """
    One h2 connection per client; each stream gets a JSON summary of its request.
    """

    def __init__(self, port: int):
        self.port = port
        self.context = self.tls_context()

    def tls_context(self) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        san = x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )

        directory = Path(tempfile.mkdtemp(prefix="h2echo-"))
        (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
        context.set_alpn_protocols(["h2"])
        return context

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        streams: dict[int, dict] = {}

        while True:
            data = await reader.read(65536)
            if not data:
                break

            for event in conn.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    path = dict(event.headers).get(b":path", b"")
                    if path.startswith(b"/early") and not event.stream_ended:
                        self.answer_early(conn, event.stream_id)
                        continue
                    if path.startswith(b"/truncated"):
                        self.answer_truncated(conn, event.stream_id)
                        continue
                    streams[event.stream_id] = {
                        "headers": [[n.decode(), v.decode()] for n, v in event.headers],
                        "body": hashlib.sha256(),
                        "length": 0,
                        "data_frames": 0,
                    }
                elif isinstance(event, h2.events.DataReceived):
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    state = streams.get(event.stream_id)
                    if state is None:
                        continue
                    state["body"].update(event.data)
                    state["length"] += len(event.data)
                    if event.data:
                        state["data_frames"] += 1
                elif isinstance(event, h2.events.StreamEnded) and event.stream_id in streams:
                    self.respond(conn, event.stream_id, streams.pop(event.stream_id))
            writer.write(conn.data_to_send())
            await writer.drain()
        writer.close()

    def answer_early(self, conn: h2.connection.H2Connection, stream_id: int) -> None:
        body = b'{"early": true}'
        conn.send_headers(
            stream_id,
            [(":status", "200"), ("content-type", "application/json"), ("content-length", str(len(body)))],
        )
        conn.send_data(stream_id, body, end_stream=True)
        conn.reset_stream(stream_id, h2.errors.ErrorCodes.NO_ERROR)

    def answer_truncated(self, conn: h2.connection.H2Connection, stream_id: int) -> None:
        conn.send_headers(stream_id, [(":status", "200"), ("content-length", "1000")])
        conn.send_data(stream_id, b"x" * 300)
        conn.reset_stream(stream_id, h2.errors.ErrorCodes.NO_ERROR)

    def respond(self, conn: h2.connection.H2Connection, stream_id: int, state: dict) -> None:
        body = json.dumps(
            {
                "headers": state["headers"],
                "length": state["length"],
                "sha256": state["body"].hexdigest(),
                "data_frames": state["data_frames"],
            }
        ).encode()

        conn.send_headers(
            stream_id,
            [(":status", "200"), ("content-type", "application/json"), ("content-length", str(len(body)))],
        )
        conn.send_data(stream_id, body, end_stream=True)

    async def serve(self) -> None:
        server = await asyncio.start_server(self.handle, "127.0.0.1", self.port, ssl=self.context)
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(EchoServer(int(sys.argv[1])).serve())
