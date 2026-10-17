"""
List the license of every crate linked into the janus-py extension, for crates/janus-py/licenses/rust-crates.txt.

usage: python rust_licenses.py <workspace dir> > crates/janus-py/licenses/rust-crates.txt
"""

import json
import subprocess
import sys


def main() -> None:
    workspace = sys.argv[1]
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=workspace,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    metadata = json.loads(output)

    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = next(p["id"] for p in metadata["packages"] if p["name"] == "janus-py")

    # normal dependencies only: build and dev dependencies do not end up in the binary
    seen = set()
    pending = [root]
    while pending:
        node = nodes[pending.pop()]
        for dep in node["deps"]:
            kinds = {k["kind"] for k in dep["dep_kinds"]}
            if None in kinds and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                pending.append(dep["pkg"])

    members = set(metadata["workspace_members"])
    print("Rust crates statically linked into janus_requests._native (name, version, license, source).")
    print("Workspace crates (janus, janus-h2) are covered by LICENSE and the janus-h2 notice below.\n")
    for package in sorted((packages[i] for i in seen if i not in members), key=lambda p: (p["name"], p["version"])):
        source = package.get("repository") or "crates.io"
        print(f"{package['name']} {package['version']}  {package.get('license') or 'see source'}  {source}")

    print("\njanus-h2 is a fork of http2 0.5.20 (https://github.com/0x676e67/http2), itself a fork of h2:")
    print("MIT License, Copyright (c) 2017 h2 authors")


if __name__ == "__main__":
    main()
