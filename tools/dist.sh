#!/bin/bash
# Release builds for Linux: the Rust example binaries and the janus_requests wheel, into /root/janus/dist; log in /root/janus/dist.log.
export PATH=/root/.cargo/bin:/root/.local/bin:$PATH
cd /root/janus
rm -rf crates && tar xzf janus-ws.tgz
rm -rf dist && mkdir -p dist/rust
(
    set -e
    cargo build --release -p janus --examples
    cp target/release/examples/get target/release/examples/session dist/rust/
    tar czf dist/janus-0.2.0-rust-x86_64-unknown-linux-gnu.tar.gz -C dist/rust get session
    cd crates/janus-py
    uvx maturin build --release --compatibility linux -o /root/janus/dist
    cd /root/janus
    ls -l dist dist/rust
    ldd dist/rust/get
    sha256sum dist/*.whl dist/*.tar.gz
) > /root/janus/dist.log 2>&1
echo EXIT=$? >> /root/janus/dist.log
