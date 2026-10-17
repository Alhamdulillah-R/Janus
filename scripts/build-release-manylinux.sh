#!/bin/bash
# Release build inside quay.io/pypa/manylinux_2_28_x86_64: the manylinux wheel and the Rust example binaries, into dist/.
#
#   docker run --rm -v "$PWD":/janus -w /janus quay.io/pypa/manylinux_2_28_x86_64 bash scripts/build-release-manylinux.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
version=$(grep -m1 '^version' "$root/crates/janus/Cargo.toml" | cut -d'"' -f2)

dnf install -yq perl-IPC-Cmd perl-Time-Piece perl-Pod-Html git
if ! command -v cargo > /dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
fi
if ! command -v uv > /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH=$HOME/.cargo/bin:$HOME/.local/bin:$PATH
if ! command -v cmake > /dev/null; then
    uv tool install cmake
fi

bash "$root/scripts/build-openssl-linux.sh"

cd "$root"
rm -rf dist
mkdir -p dist/rust

cargo build --release -p janus --examples
cp target/release/examples/get target/release/examples/session dist/rust/
tar czf "dist/janus-$version-rust-x86_64-unknown-linux-gnu.tar.gz" -C dist/rust get session

cd crates/janus-py
uvx maturin build --release --compatibility manylinux_2_28 -i /opt/python/cp310-cp310/bin/python -o "$root/dist"

cd "$root"
ldd dist/rust/get
sha256sum dist/*.whl dist/*.tar.gz
