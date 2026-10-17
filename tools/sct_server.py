"""
Local `openssl s_server -www` that answers the SCT extension (0x0012) like CT-logged sites: in the TLS 1.2 ServerHello
or the TLS 1.3 Certificate entry. Extra arguments go to s_server (e.g. -tls1_2).

usage: uv run --with cryptography python sct_server.py <openssl binary> <port> [s_server args...]
"""

import base64
import datetime
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def write_certificate(directory: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def write_serverinfo(directory: Path) -> None:
    """
    SERVERINFOV2 record for 0x0012 in ClientHello context, TLS 1.2 ServerHello and TLS 1.3 Certificate; one dummy SCT.
    """
    sct = bytes(range(10))
    sct_list = struct.pack(">HH", len(sct) + 2, len(sct)) + sct
    record = struct.pack(">IHH", 0x80 | 0x100 | 0x1000, 0x0012, len(sct_list)) + sct_list

    pem = (
        "-----BEGIN SERVERINFOV2 FOR SCT-----\n"
        + base64.b64encode(record).decode()
        + "\n-----END SERVERINFOV2 FOR SCT-----\n"
    )
    (directory / "serverinfo.pem").write_text(pem)


def main() -> None:
    openssl, port, *extra = sys.argv[1:]
    directory = Path(tempfile.mkdtemp(prefix="sct-server-"))

    write_certificate(directory)
    write_serverinfo(directory)
    command = [
        openssl,
        "s_server",
        "-accept",
        port,
        "-cert",
        str(directory / "cert.pem"),
        "-key",
        str(directory / "key.pem"),
        "-serverinfo",
        str(directory / "serverinfo.pem"),
        "-www",
        "-quiet",
        *extra,
    ]
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
