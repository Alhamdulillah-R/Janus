"""
python -m janus_requests.capture [--host 127.0.0.1] [--port 8443] [--out captured] [--name NAME] [--cert PEM --key PEM]
"""

import argparse
import logging

from .server import CaptureServer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Open https://HOST:PORT/ in a browser to capture it as a JanusProfile."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--out", default="captured", help="directory for NAME.py and the profile JSON files")
    parser.add_argument("--name", default="captured", help="module and profile name, a Python identifier")
    parser.add_argument("--cert", help="PEM certificate (default: a fresh self-signed one)")
    parser.add_argument("--key", help="PEM private key for --cert")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    server = CaptureServer(
        host=args.host,
        port=args.port,
        out_dir=args.out,
        name=args.name,
        cert=args.cert,
        key=args.key,
    )

    # by IP address browsers send no server_name, so point them at a host name
    shown = "localhost" if args.host in ("127.0.0.1", "0.0.0.0") else args.host
    logging.getLogger("janus_requests.capture").info("open https://%s:%d/ in the browser to capture", shown, args.port)
    with server:
        server.serve_forever()


if __name__ == "__main__":
    main()
