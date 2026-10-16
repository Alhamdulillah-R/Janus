"""
Generate janus_requests/registry.py from the IANA TLS and HTTP/2 registries.
"""

import csv
import datetime
import io
import re
import urllib.request
from pathlib import Path


def fetch_csv_rows(url):
    """Download an IANA CSV registry and return its data rows without the header."""
    request = urllib.request.Request(url, headers={"User-Agent": "janus-registry-gen"})
    with urllib.request.urlopen(request, timeout=60) as response:
        text = response.read().decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text)))[1:]


def parse_value(raw):
    """Parse a registry Value cell into an int, returning None for ranges, wildcards and non-numeric cells."""
    text = raw.strip()
    if "-" in text or "*" in text:
        return None
    parts = text.split(",")
    try:
        if len(parts) == 2:
            return (int(parts[0], 16) << 8) | int(parts[1], 16)
        if len(parts) == 1:
            return int(text, 0)
    except ValueError:
        return None
    return None


def is_reserved(raw_name):
    """Tell whether a registry name or description marks an unassigned or reserved entry."""
    text = raw_name.strip()
    return text == "Unassigned" or text.startswith("Reserved")


def is_grease(value):
    """Tell whether value is one of the 16 RFC 8701 GREASE codepoints."""
    high = value >> 8
    return 0 <= value <= 0xFFFF and high == (value & 0xFF) and (high & 0x0F) == 0x0A


def clean_name(raw_name):
    """Cut an IANA name at its first space or parenthesis and sanitise it into a Python identifier."""
    head = re.split(r"[ (]", raw_name.strip(), maxsplit=1)[0]
    name = re.sub(r"[^A-Za-z0-9_]", "_", head)
    name = re.sub(r"_+", "_", name).strip("_")
    if name[:1].isdigit():
        name = "_" + name
    return name


def collect_members(rows, name_index, value_index):
    """Turn registry rows into (value, name, comment) tuples, dropping ranges, reserved and GREASE entries."""
    members = []
    seen_names = set()
    for row in rows:
        if len(row) <= max(name_index, value_index):
            continue
        value = parse_value(row[value_index])
        if value is None or is_reserved(row[name_index]) or is_grease(value):
            continue
        name = clean_name(row[name_index])
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        members.append((value, name, None))
    return members


def extra_extension_members(existing):
    """Return the browser extension codepoints that the IANA registry does not list."""
    extras = [
        (0x44CD, "application_settings", "ALPS as used by Chrome"),
        (0x4469, "application_settings_old", "ALPS, original codepoint"),
        (0x3374, "next_protocol_negotiation", "NPN"),
        (0x7550, "channel_id", "Channel ID"),
        (0xCA34, "trust_anchors", "Trust Anchor IDs as used by Chrome"),
    ]
    known_values = {value for value, _, _ in existing}
    known_names = {name for _, name, _ in existing}
    return [member for member in extras if member[0] not in known_values and member[1] not in known_names]


def handwritten_members():
    """Return the hand-written TLS enums as (class_name, doc, as_hex, members) tuples."""
    tls_version = [
        (0x0300, "ssl3", None),
        (0x0301, "tls1_0", None),
        (0x0302, "tls1_1", None),
        (0x0303, "tls1_2", None),
        (0x0304, "tls1_3", None),
    ]
    cert_compression = [
        (1, "zlib", None),
        (2, "brotli", None),
        (3, "zstd", None),
    ]
    psk_modes = [
        (0, "psk_ke", None),
        (1, "psk_dhe_ke", None),
    ]
    ec_point_formats = [
        (0, "uncompressed", None),
        (1, "ansiX962_compressed_prime", None),
        (2, "ansiX962_compressed_char2", None),
    ]
    return [
        ("TlsVersion", "TLS and SSL protocol version numbers.", True, tls_version),
        ("CertCompressionAlgorithm", "RFC 8879 certificate compression algorithm IDs.", False, cert_compression),
        ("PskKeyExchangeMode", "RFC 8446 PSK key exchange modes.", False, psk_modes),
        ("ECPointFormat", "RFC 8422 EC point formats.", False, ec_point_formats),
    ]


def format_value(value, as_hex):
    """Format an enum value as a zero-padded hex literal or a decimal literal."""
    if as_hex:
        return f"0x{value:04X}"
    return str(value)


def render_enum(class_name, doc, members, as_hex):
    """Render one enum.IntEnum class with its members sorted by value."""
    lines = [
        f"class {class_name}(enum.IntEnum):",
        f'    """{doc}"""',
        "",
    ]
    for value, name, comment in sorted(members, key=lambda member: member[0]):
        if comment is not None:
            lines.append(f"    # {comment}")
        lines.append(f"    {name} = {format_value(value, as_hex)}")
    return "\n".join(lines) + "\n"


def render_helpers():
    """Render the is_grease and describe helper functions for the generated module."""
    return '''def is_grease(value: int) -> bool:
    """Tell whether value is one of the 16 RFC 8701 GREASE codepoints."""
    high = value >> 8
    return 0 <= value <= 0xFFFF and high == (value & 0xFF) and (high & 0x0F) == 0x0A


def describe(enum_cls: type[enum.IntEnum], value: int) -> str:
    """Return the member name for value, GREASE for GREASE codepoints, or a hex string."""
    for name, member in enum_cls.__members__.items():
        if member.value == value:
            return name
    if is_grease(value):
        return "GREASE"
    return f"0x{value:04x}"
'''


def render_module(sections):
    """Assemble the generated module text from the rendered sections."""
    utc_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    header = (
        '"""\n'
        f"Generated by tools/gen_registry.py from IANA registries on {utc_date} (UTC).\n"
        "Do not edit by hand.\n"
        '"""\n\n'
        "import enum\n\n\n"
    )
    body = "\n\n".join(sections)
    return header + body + "\n\n" + render_helpers()


def main():
    """Download the IANA registries and write the generated janus_requests/registry.py."""
    cipher_rows = fetch_csv_rows("https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv")
    extension_rows = fetch_csv_rows(
        "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv"
    )
    group_rows = fetch_csv_rows("https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv")
    signature_rows = fetch_csv_rows("https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv")
    settings_rows = fetch_csv_rows("https://www.iana.org/assignments/http2-parameters/settings.csv")

    cipher_members = collect_members(cipher_rows, 1, 0)
    extension_members = collect_members(extension_rows, 1, 0)
    extension_members.extend(extra_extension_members(extension_members))
    group_members = collect_members(group_rows, 1, 0)
    signature_members = collect_members(signature_rows, 1, 0)
    settings_members = collect_members(settings_rows, 1, 0)

    sections = [
        render_enum("CipherSuite", "IANA TLS cipher suites.", cipher_members, True),
        render_enum("ExtensionType", "IANA TLS extension types.", extension_members, True),
        render_enum("NamedGroup", "IANA TLS supported groups.", group_members, True),
        render_enum("SignatureScheme", "IANA TLS signature schemes.", signature_members, True),
        render_enum("H2Setting", "IANA HTTP/2 SETTINGS identifiers.", settings_members, False),
    ]
    for class_name, doc, as_hex, members in handwritten_members():
        sections.append(render_enum(class_name, doc, members, as_hex))

    output_path = Path(__file__).resolve().parents[1] / "crates" / "janus-py" / "python" / "janus_requests" / "registry.py"
    output_path.write_text(render_module(sections), encoding="utf-8")
    print(f"wrote {output_path}")


if __name__ == "__main__":
    main()
