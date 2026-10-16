#!/bin/bash
# Build janus_requests into the uv project /root/janus/py-check, start the local test servers and proxies, run the functional script; log to /root/janus/py.log.
export PATH=/root/.cargo/bin:/root/.local/bin:$PATH
cd /root/janus
rm -rf /root/janus/crates && tar xzf /root/janus/janus-ws.tgz
(
    if [ ! -f py-check/pyproject.toml ]; then
        uv init --bare --no-workspace --python 3.12 py-check
    fi
    cd py-check
    uv add --editable ../crates/janus-py --extra capture
    uv sync --reinstall-package janus-requests
    uv run --with brotli --with zstandard python ../tools/test_server.py 8765 &
    uvx --python 3.12 pproxy -l http://127.0.0.1:8899 -l socks5://127.0.0.1:8898 &
    uv run --with h2 --with cryptography python ../tools/h2_echo_server.py 8766 &
    for _ in $(seq 1 90); do
        curl -s -o /dev/null http://127.0.0.1:8765/echo && nc -z 127.0.0.1 8899 && nc -z 127.0.0.1 8766 && break
        sleep 1
    done
    uv run python ../tools/py_functional.py 8765 8899 8898 8766
    status=$?
    pkill -f "test_server[.]py 8765"
    pkill -f "pproxy -l http"
    pkill -f "h2_echo_server[.]py 8766"
    exit $status
) > /root/janus/py.log 2>&1
echo EXIT=$? >> /root/janus/py.log
