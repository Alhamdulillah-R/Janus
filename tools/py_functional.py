"""
Functional check of janus_requests's requests compatibility and fingerprint, against our own servers only:
h2probe on the test machine, mignon-rex.tokyo, and tools/test_server.py on 127.0.0.1.

usage: python py_functional.py <local-port> [http-proxy-port socks5-proxy-port [h2-echo-port [sct-port]]]

sct-port runs tools/sct_server.py (TLS 1.3 and up), sct-port + 1 the same with -tls1_2.
"""

import asyncio
import copy
import hashlib
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import janus_requests as requests
from janus_requests import JanusAsyncSession, JanusProfile, JanusSession, JanusTls, PriorityMode
from janus_requests.capture.server import CaptureServer
from janus_requests.registry import CipherSuite, H2Setting

h2probe = "https://169-58-190-113.sslip.io:80"
trackme = "https://mignon-rex.tokyo/api/all"
chrome_ja4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"
chrome_akamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
results: list[tuple[str, bool, str]] = []
# Chrome 155 navigation headers: Janus sends none by default, the tests that compare with Chrome pass these
chrome_headers = {
    "sec-ch-ua": '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Priority": "u=0, i",
}


def check(name: str, ok: bool, detail: object = "") -> None:
    results.append((name, bool(ok), str(detail)))
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")


def expect_raise(name: str, exc: type[BaseException], fn) -> None:
    try:
        fn()
    except exc as e:
        check(name, True, f"{type(e).__name__}: {str(e)[:90]}")
    except Exception as e:  # noqa: BLE001 - any other exception is the failure being reported
        check(name, False, f"wrong exception {type(e).__name__}: {e}")
    else:
        check(name, False, "no exception")


def fingerprint() -> None:
    bare = requests.get(trackme).json()
    sent = next(f for f in bare["http2"]["sent_frames"] if f["frame_type"] == "HEADERS")["headers"]
    names = [h.split(": ", 1)[0] for h in sent]
    check("no default headers on h2", names == [":method", ":authority", ":scheme", ":path"], names)

    r = requests.get(trackme, headers=chrome_headers)
    data = r.json()
    check("module get is requests.Response", isinstance(r, requests.Response), type(r))
    check("trackme ja4", data["tls"]["ja4"] == chrome_ja4, data["tls"]["ja4"])
    check(
        "trackme akamai",
        data["http2"]["akamai_fingerprint"] == chrome_akamai,
        data["http2"]["akamai_fingerprint"],
    )
    sent = next(f for f in data["http2"]["sent_frames"] if f["frame_type"] == "HEADERS")["headers"]
    names = [h.split(": ", 1)[0] for h in sent]
    expected = [":method", ":authority", ":scheme", ":path", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"]
    check("trackme header order", names[:7] == expected, names)

    with JanusSession(headers=chrome_headers) as s:
        first = s.get(trackme)
        s.close()
        second = s.get(trackme)
        check(
            "tls resumption flag",
            first.raw.tls_session_reused is False and second.raw.tls_session_reused,
            second.raw.tls_session_reused,
        )
        check("resumed ja4 adds psk", second.json()["tls"]["ja4"].startswith("t13d1518h2"), second.json()["tls"]["ja4"])
        check("http version on raw", second.raw.version_string == "HTTP/2", second.raw.version_string)


def local(base: str) -> None:
    with JanusSession() as bare:
        names = [k.lower() for k, _ in bare.get(f"{base}/echo").json()["headers"]]
        check("no default headers on h1 (Host only)", names == ["host"], names)

    s = requests.Session(headers=chrome_headers)

    r = s.get(f"{base}/echo", params={"q": "1"}, headers={"X-Test": "yes", "Accept-Language": None})
    echo = r.json()
    names = [k.lower() for k, _ in echo["headers"]]
    check("params", echo["path"] == "/echo?q=1", echo["path"])
    check("None header removes a session header", "accept-language" not in names, names)
    check("h1 header order host first", names[0] == "host" and "connection" not in names, names[:4])
    check("custom header present", "x-test" in names, names[-3:])

    port_a = s.get(f"{base}/echo").json()["client_port"]
    port_b = s.get(f"{base}/echo").json()["client_port"]
    check("h1 keep-alive reuse", port_a == port_b and r.raw.version_string == "HTTP/1.1", (port_a, port_b))

    s.get(f"{base}/set-cookie", params={"a": "1", "b": "2"})
    check("cookie jar", s.cookies.get_dict() == {"a": "1", "b": "2"}, s.cookies.get_dict())
    cookie_header = {k.lower(): v for k, v in s.get(f"{base}/echo").json()["headers"]}.get("cookie")
    check("cookie sent", cookie_header in ("a=1; b=2", "b=2; a=1"), cookie_header)

    r = s.get(f"{base}/redirect/3")
    check(
        "redirect chain",
        r.url.endswith("/echo") and [h.status_code for h in r.history] == [302, 302, 302],
        (r.url, r.history),
    )
    check("cookies set during redirects", {"hop1", "hop2", "hop3"} <= set(s.cookies.keys()), sorted(s.cookies.keys()))

    r = s.post(f"{base}/redirect-code/303", data={"x": "1"})
    check("303 turns POST into GET", r.json()["method"] == "GET", r.json()["method"])
    r = s.post(f"{base}/redirect-code/307", data={"x": "1"})
    check("307 keeps POST body", r.json()["method"] == "POST" and r.json()["body"] == "x=1", r.json()["body"])

    r = s.get(f"{base}/redirect/2", allow_redirects=False)
    check(
        "allow_redirects=False",
        r.status_code == 302 and r.is_redirect and r.next.url.endswith("/redirect/1"),
        r.next.url,
    )

    for coding in ("gzip", "deflate", "br", "zstd"):
        r = s.get(f"{base}/coding/{coding}")
        check(f"content-encoding {coding}", r.text == "janus " * 2000, len(r.content))

    r = s.get(f"{base}/coding/gzip", stream=True)
    raw = r.raw.read()
    check("raw.read stays encoded", raw[:2] == b"\x1f\x8b", raw[:4])

    r = s.get(f"{base}/chunked", stream=True)
    lines = list(r.iter_lines())
    check("stream iter_lines over chunked", lines == [f"line {i}".encode() for i in range(5)], lines)

    r = s.get(f"{base}/bytes/300000", stream=True)
    sizes = [len(c) for c in r.iter_content(chunk_size=65536)]
    check("iter_content chunk_size", sum(sizes) == 300000 and max(sizes) <= 65536, sizes[:6])

    expect_raise(
        "read timeout", requests.ReadTimeout, lambda: s.get(f"{base}/slow", params={"delay": "2"}, timeout=0.5)
    )
    expect_raise("connect timeout", requests.ConnectTimeout, lambda: s.get("http://10.255.255.1/", timeout=(0.5, 5)))
    expect_raise("connection refused", requests.ConnectionError, lambda: s.get("http://127.0.0.1:1/"))
    expect_raise("raise_for_status", requests.HTTPError, lambda: s.get(f"{base}/status/418").raise_for_status())
    expect_raise("invalid schema", requests.exceptions.InvalidSchema, lambda: s.get("ftp://example.invalid/"))
    expect_raise("missing schema", requests.exceptions.MissingSchema, lambda: s.get("example.invalid"))
    expect_raise("bad CA path", OSError, lambda: s.get(h2probe, verify="/nonexistent/ca.pem"))

    check("basic auth", s.get(f"{base}/basic-auth/u/p", auth=("u", "p")).status_code == 200)
    r = s.get(f"{base}/digest-auth/u/p", auth=requests.auth.HTTPDigestAuth("u", "p"))
    check("digest auth", r.status_code == 200 and r.text == "digest ok", (r.status_code, r.text))

    r = s.get(f"{base}/dup")
    check("duplicate headers joined", r.headers["X-Dup"] == "a, b", r.headers["X-Dup"])
    check("response cookies", r.cookies.get_dict() == {"c1": "1", "c2": "2"}, r.cookies.get_dict())

    r = s.post(f"{base}/echo", json={"a": 1, "b": [1, 2]})
    echo = r.json()
    content_type = {k.lower(): v for k, v in echo["headers"]}.get("content-type")
    check(
        "json body",
        json.loads(echo["body"]) == {"a": 1, "b": [1, 2]} and content_type == "application/json",
        echo["body"],
    )

    r = s.post(f"{base}/echo", files={"f": ("hello.txt", b"hello world", "text/plain")}, data={"k": "v"})
    body = r.json()["body"]
    check("multipart files", 'filename="hello.txt"' in body and "hello world" in body, body[:60])

    seen = []
    s.get(f"{base}/echo", hooks={"response": lambda resp, **kw: seen.append(resp.status_code)})
    check("response hook", seen == [200], seen)

    s.close()


def header(echo: dict, name: str) -> str | None:
    return {k.lower(): v for k, v in echo["headers"]}.get(name)


def uploads(base: str, h2_echo: str | None) -> None:
    payload = bytes(i % 251 for i in range(1_000_000))
    digest = hashlib.sha256(payload).hexdigest()

    with requests.Session() as s:
        r = s.post(f"{base}/echo", data=(c for c in [b"ab", b"cd", b"ef"]))
        echo = r.json()
        check(
            "h1 generator body is chunked",
            echo["body"] == "abcdef" and echo["chunks"] == 3 and header(echo, "transfer-encoding") == "chunked",
            (echo["chunks"], header(echo, "transfer-encoding")),
        )

        r = s.post(f"{base}/echo", data=io.BytesIO(payload))
        echo = r.json()
        check(
            "h1 file body streamed with Content-Length",
            echo["body_sha256"] == digest and echo["chunks"] == 0 and header(echo, "content-length") == "1000000",
            (echo["body_length"], header(echo, "content-length")),
        )

        def broken():
            yield b"x" * 10
            raise RuntimeError("producer failed")

        expect_raise("generator error propagates", RuntimeError, lambda: s.post(f"{base}/echo", data=broken()))
        check("session usable after aborted upload", s.get(f"{base}/echo").status_code == 200)

        if h2_echo is None:
            return

        # the server answers before reading the body and resets the stream with NO_ERROR: the answer must win
        early = h2_echo.replace("/upload", "/early")
        r = s.post(early, data=(payload[i : i + 50_000] for i in range(0, len(payload), 50_000)), verify=False)
        check("h2 early response during upload", r.status_code == 200 and r.json() == {"early": True}, r.text)
        check("session usable after early response", s.post(h2_echo, data=b"after", verify=False).status_code == 200)
        r = s.post(early, data=payload, verify=False)
        check("h2 early response during a bytes body", r.status_code == 200 and r.json() == {"early": True}, r.text)
        expect_raise(
            "h2 NO_ERROR reset before END_STREAM is an error",
            requests.exceptions.ChunkedEncodingError,
            lambda: s.get(h2_echo.replace("/upload", "/truncated"), verify=False),
        )

        r = s.post(h2_echo, data=(payload[i : i + 50_000] for i in range(0, len(payload), 50_000)), verify=False)
        echo = r.json()
        check(
            "h2 generator body streamed",
            r.raw.version_string == "HTTP/2"
            and echo["sha256"] == digest
            and echo["data_frames"] > 20
            and header(echo, "content-length") is None,
            (echo["length"], echo["data_frames"]),
        )

        r = s.post(h2_echo, data=io.BytesIO(payload), verify=False)
        echo = r.json()
        check(
            "h2 file body with content-length",
            echo["sha256"] == digest and header(echo, "content-length") == "1000000",
            (echo["length"], header(echo, "content-length")),
        )


def profiles() -> None:
    chrome = JanusProfile.builtin("chrome155")
    namespace: dict = {}
    exec(chrome.to_python("rebuilt"), namespace)  # noqa: S102 - running the generated profile code is the test

    check("to_python round trip", namespace["rebuilt"] == chrome)
    check("json round trip", JanusProfile.from_json(chrome.to_json()) == chrome)
    check("tls spec round trip", JanusTls.from_spec(chrome.tls.to_spec()) == chrome.tls)
    check("akamai string", chrome.http2.akamai() == chrome_akamai, chrome.http2.akamai())

    with JanusSession(janus=namespace["rebuilt"]) as s:
        data = s.get(trackme).json()
        check("rebuilt profile ja4", data["tls"]["ja4"] == chrome_ja4, data["tls"]["ja4"])

    custom = chrome.copy()
    custom.tls.ciphers.remove(CipherSuite.TLS_AES_256_GCM_SHA384)
    custom.http2.settings = [(H2Setting.HEADER_TABLE_SIZE, 4096), (H2Setting.INITIAL_WINDOW_SIZE, 1048576)]
    custom.http2.window_update = 1000000
    with JanusSession(janus=custom) as s:
        data = s.get(trackme).json()
        check(
            "edited profile reaches the wire",
            data["tls"]["ja4"].startswith("t13d1417h2_")
            and data["http2"]["akamai_fingerprint"] == "1:4096;4:1048576|1000000|0|m,a,s,p",
            (data["tls"]["ja4"], data["http2"]["akamai_fingerprint"]),
        )
    check("builtin untouched by edits", len(JanusProfile.builtin("chrome155").tls.ciphers) == 16)


def capture() -> None:
    chrome = JanusProfile.builtin("chrome155")
    out_dir = Path(tempfile.mkdtemp(prefix="janus-capture-"))
    server = CaptureServer(port=8767, out_dir=out_dir, name="loopback")
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # what the capture page's script does: the page request, then a PUT XHR on the same connection
    fetch_headers = {
        "sec-ch-ua-platform": None,
        "Upgrade-Insecure-Requests": None,
        "Sec-Fetch-User": None,
        "Content-Type": "text/plain",
        "Accept": "*/*",
        "Origin": "https://localhost:8767",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://localhost:8767/",
        "Priority": "u=1, i",
    }
    with JanusSession(headers=chrome_headers) as s:
        for _ in range(3):
            page = s.get("https://localhost:8767/", verify=False)
            report = s.put(
                "https://localhost:8767/janus-capture/fetch?t=1", data=b"janus", headers=fetch_headers, verify=False
            )
            s.close()
            s.clear_tls_sessions()
        s.get("https://localhost:8767/", verify=False)
        s.close()
        resumed = s.get("https://localhost:8767/", verify=False)
        report = s.put(
            "https://localhost:8767/janus-capture/fetch?t=2", data=b"janus", headers=fetch_headers, verify=False
        )
    server.shutdown()
    server.server_close()

    check("capture page served over h2", page.status_code == 200 and "XMLHttpRequest" in page.text, page.status_code)
    check("capture report", report.status_code == 200 and "JanusProfile(" in report.text, report.status_code)
    check("capture resumed handshake", resumed.raw.tls_session_reused, resumed.raw.tls_session_reused)

    check("capture report shows the import", "import loopback" in report.text, report.status_code)
    captured = JanusProfile.load(out_dir / "loopback.json")
    captured_fetch = JanusProfile.load(out_dir / "loopback_fetch.json")
    tls = captured.tls
    expected = chrome.tls
    check(
        "captured tls lists",
        tls.ciphers == expected.ciphers
        and sorted(tls.extensions) == sorted(expected.extensions)
        and tls.groups == expected.groups
        and tls.key_shares == expected.key_shares
        and tls.signature_algorithms == expected.signature_algorithms
        and tls.versions == expected.versions
        and tls.alpn == expected.alpn,
        [hex(e) for e in tls.extensions],
    )
    check(
        "captured tls extras",
        tls.raw_extensions == expected.raw_extensions
        and tls.alps == expected.alps
        and tls.permute_extensions
        and tls.ocsp
        and tls.ech_grease
        and tls.cert_compression == expected.cert_compression
        and tls.extensions[-1] == 0x0029,
        sorted(hex(t) for t in tls.raw_extensions),
    )
    hpack = captured.http2.hpack
    check(
        "captured http2",
        captured.http2.akamai() == chrome_akamai
        and captured.http2.priority_mode == PriorityMode.chrome
        and captured.http2.headers_priority == chrome.http2.headers_priority
        and hpack.huffman == chrome.http2.hpack.huffman
        and hpack.rules.get(":path") == chrome.http2.hpack.rules[":path"]
        and hpack.rules.get(":method") == chrome.http2.hpack.rules[":method"],
        (captured.http2.akamai(), captured.http2.priority_mode, hpack.rules),
    )
    spec = importlib.util.spec_from_file_location("loopback", out_dir / "loopback.py")
    loopback = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loopback)
    check(
        "generated module: profile and page headers",
        loopback.profile == captured
        and {n.lower(): v for n, v in loopback.headers.items()} == {n.lower(): v for n, v in chrome_headers.items()},
        list(loopback.headers)[:3],
    )
    fetch_values = {n.lower(): v for n, v in loopback.fetch_headers.items()}
    check(
        "generated module: fetch headers",
        loopback.fetch_header_order == captured_fetch.header_order
        and loopback.fetch_header_order[:3] == ["host", "connection", "content-length"]
        and fetch_values.get("sec-fetch-mode") == "cors"
        and fetch_values.get("upgrade-insecure-requests", "missing") is None
        and fetch_values.get("sec-ch-ua-platform", "missing") is None
        and not {"content-type", "origin", "referer"} & set(fetch_values),
        fetch_values,
    )

    with loopback.session() as s:
        data = s.get(trackme).json()
        check(
            "generated session() replays",
            data["tls"]["ja4"] == chrome_ja4
            and data["http2"]["akamai_fingerprint"] == chrome_akamai
            and "user-agent" in sent_names(data),
            data["tls"]["ja4"],
        )
        names = sent_names(
            s.get(trackme, headers=loopback.fetch_headers, header_order=loopback.fetch_header_order).json()
        )
        check(
            "generated fetch headers on a page session",
            "upgrade-insecure-requests" not in names
            and "sec-ch-ua-platform" not in names
            and listed_in_order(names, loopback.fetch_header_order),
            names,
        )
    with loopback.fetch_session() as s:
        names = sent_names(s.get(trackme).json())
        check(
            "generated fetch_session()", "upgrade-insecure-requests" not in names and "sec-fetch-mode" in names, names
        )

    expect_raise("capture name must be importable", ValueError, lambda: CaptureServer(port=8768, name="my-chrome"))


def listed_in_order(names: list[str], order: list[str]) -> bool:
    listed = [n for n in names if n in order]
    return listed == sorted(listed, key=order.index)


def sent_names(data: dict) -> list[str]:
    """
    Header names of the request TrackMe saw, pseudo-headers left out.
    """
    frame = next(f for f in data["http2"]["sent_frames"] if f["frame_type"] == "HEADERS")
    return [h.split(": ", 1)[0] for h in frame["headers"] if not h.startswith(":")]


def cookies(base: str) -> None:
    with JanusSession(cookies={"s": "session"}) as s:
        sent = header(s.get(f"{base}/echo", cookies={"r": "request"}).json(), "cookie")
        check("session + request cookies sent", sent in ("s=session; r=request", "r=request; s=session"), sent)
        check("request cookies not stored in the jar", s.cookies.get_dict() == {"s": "session"}, s.cookies.get_dict())

        sent = header(s.get(f"{base}/echo", cookies={"s": "override"}).json(), "cookie")
        check("request cookie overrides session cookie", sent == "s=override", sent)

        s.get(f"{base}/set-cookie", params={"from_server": "1"})
        check("response cookie stored", s.cookies.get("from_server") == "1", s.cookies.get_dict())

    sent = header(requests.get(f"{base}/echo", cookies={"m": "module"}).json(), "cookie")
    check("module-level cookies", sent == "m=module", sent)


def session_options(base: str, http_port: str | None, h2_echo: str | None) -> None:
    seen = []
    elapsed = []

    def log(req, resp) -> None:
        seen.append((req.method, req.url, resp.status_code))
        elapsed.append(resp.elapsed.total_seconds())

    with JanusSession(logs=log) as s:
        s.get(f"{base}/redirect/3")
    check("logs sees elapsed", all(e > 0 for e in elapsed), elapsed)
    check(
        "logs called for every hop",
        [code for _, _, code in seen] == [302, 302, 302, 200] and seen[-1][1].endswith("/echo"),
        seen,
    )

    if h2_echo is not None:
        r = JanusSession().post(h2_echo, data=b"verify off by default")
        check("verify off by default", r.status_code == 200, r.status_code)
        expect_raise(
            "verify=True still checks",
            requests.exceptions.SSLError,
            lambda: JanusSession(verify=True).get(h2_echo),
        )

    if http_port is not None:
        proxy = f"http://127.0.0.1:{http_port}"
        dead = "http://127.0.0.1:1"
        check("session proxy=", JanusSession(proxy=proxy).get(f"{base}/echo").status_code == 200)
        check("session proxies=", JanusSession(proxies={"http": proxy}).get(f"{base}/echo").status_code == 200)
        check("request proxy=", JanusSession().get(f"{base}/echo", proxy=proxy).status_code == 200)
        r = requests.get(f"{base}/echo", proxy=proxy, janus="chrome155_fetch")
        check("module-level proxy= and janus=", r.status_code == 200, r.status_code)
        # a dead proxy fails every form: the proxy is really on the path
        expect_raise(
            "session proxy= is used",
            requests.exceptions.ProxyError,
            lambda: JanusSession(proxy=dead).get(f"{base}/echo"),
        )
        expect_raise(
            "request proxy= is used",
            requests.exceptions.ProxyError,
            lambda: JanusSession().get(f"{base}/echo", proxy=dead),
        )
        expect_raise(
            "module-level proxy= is used",
            requests.exceptions.ProxyError,
            lambda: requests.get(f"{base}/echo", proxy=dead),
        )
        expect_raise(
            "proxy and proxies together", ValueError, lambda: JanusSession(proxy=proxy, proxies={"http": proxy})
        )
        expect_raise("proxy and empty proxies together", ValueError, lambda: JanusSession(proxy=proxy, proxies={}))

    saved = {
        k: os.environ.pop(k)
        for k in list(os.environ)
        if k.lower() in ("http_proxy", "https_proxy", "no_proxy", "all_proxy")
    }
    os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
    try:
        r = JanusSession().get(f"{base}/echo")
        check("environment proxy ignored", r.status_code == 200, r.status_code)
    finally:
        del os.environ["HTTP_PROXY"]
        os.environ.update(saved)

    accepted = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    port = listener.getsockname()[1]

    def slam() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            accepted.append(1)
            conn.close()

    threading.Thread(target=slam, daemon=True).start()

    expect_raise(
        "retry_num on connection errors",
        requests.ConnectionError,
        lambda: JanusSession(retry_num=2).get(f"http://127.0.0.1:{port}/"),
    )
    check("retry_num attempts", len(accepted) == 3, len(accepted))

    accepted.clear()
    expect_raise(
        "POST not retried after the connection dropped",
        requests.ConnectionError,
        lambda: JanusSession(retry_num=2).post(f"http://127.0.0.1:{port}/", data=b"once"),
    )
    check("POST single attempt", len(accepted) == 1, len(accepted))

    accepted.clear()
    expect_raise(
        "generator body not replayed",
        requests.ConnectionError,
        lambda: JanusSession(retry_num=2).post(f"http://127.0.0.1:{port}/", data=(c for c in [b"a", b"b"])),
    )
    check("generator body single attempt", len(accepted) == 1, len(accepted))
    listener.close()

    expect_raise("negative retry_num", ValueError, lambda: JanusSession(retry_num=-1))
    expect_raise("negative per-request retry_num", ValueError, lambda: JanusSession().get(f"{base}/echo", retry_num=-1))
    check("head accepts data=", requests.head(f"{base}/echo", data=b"x").status_code == 200)
    check("async session copies", copy.copy(JanusAsyncSession()).sync is not None)

    bad = JanusProfile.builtin("chrome155")
    bad.http2.window_update = 2**31
    expect_raise("window_update out of range", ValueError, lambda: JanusSession(janus=bad))
    bad = JanusProfile.builtin("chrome155")
    bad.http2.settings = [(H2Setting.ENABLE_PUSH, 5)]
    expect_raise("SETTINGS value out of range", ValueError, lambda: JanusSession(janus=bad))

    started = time.monotonic()
    expect_raise(
        "read timeout not retried",
        requests.ReadTimeout,
        lambda: JanusSession(retry_num=3).get(f"{base}/slow", params={"delay": "2"}, timeout=0.5),
    )
    check("read timeout single attempt", time.monotonic() - started < 1.8, round(time.monotonic() - started, 2))


def sct(port: str) -> None:
    """
    Servers that answer the SCT extension Chrome sends from its raw body.
    """
    for version, server in (("TLSv1.3", int(port)), ("TLSv1.2", int(port) + 1)):
        r = JanusSession().get(f"https://localhost:{server}/", timeout=15)
        check(f"SCT answered over {version}", r.status_code == 200 and version in r.text, r.status_code)


def proxies(base: str, http_port: str, socks_port: str) -> None:
    with requests.Session() as s:
        r = s.get(f"{h2probe}/api/get", proxies={"https": f"http://127.0.0.1:{http_port}"}, timeout=30)
        check("https via http CONNECT proxy", r.status_code == 200 and r.raw.version_string == "HTTP/2", r.text)
        r = s.get(f"{h2probe}/api/get", proxies={"https": f"socks5h://127.0.0.1:{socks_port}"}, timeout=30)
        check("https via socks5h", r.status_code == 200, r.text)
        r = s.get(f"{base}/echo", proxies={"http": f"http://127.0.0.1:{http_port}"}, timeout=30)
        check("http via proxy absolute-form", r.status_code == 200, r.status_code)
        expect_raise(
            "dead proxy",
            requests.exceptions.ProxyError,
            lambda: s.get(f"{h2probe}/api/get", proxies={"https": "http://127.0.0.1:1"}),
        )


async def run_async(base: str, h2_echo: str | None) -> None:
    async with requests.AsyncSession() as s:
        responses = await asyncio.gather(*(s.get(f"{h2probe}/api/get", params={"i": i}) for i in range(5)))
        check(
            "async gather on h2",
            all(r.status_code == 200 for r in responses),
            [r.raw.version_string for r in responses],
        )

        r = await s.get(f"{base}/redirect/2")
        check("async redirects", r.url.endswith("/echo") and len(r.history) == 2, (r.url, len(r.history)))
        check("async cookie jar", {"hop1", "hop2"} <= set(s.cookies.keys()), sorted(s.cookies.keys()))

        r = await s.get(f"{base}/chunked", stream=True)
        lines = [line async for line in r.aiter_lines()]
        check("async aiter_lines", lines == [f"line {i}".encode() for i in range(5)], lines)

        r = await s.get(f"{base}/coding/br")
        check("async decoded body", r.text == "janus " * 2000, len(r.content))

        try:
            await s.get(f"{base}/slow", params={"delay": "2"}, timeout=0.5)
            check("async read timeout", False, "no exception")
        except requests.ReadTimeout as e:
            check("async read timeout", True, e)

        async def parts():
            for piece in (b"one", b"two", b"three"):
                await asyncio.sleep(0.01)
                yield piece

        r = await s.post(f"{base}/echo", data=parts())
        echo = r.json()
        check(
            "async generator body is chunked",
            echo["body"] == "onetwothree" and echo["chunks"] == 3,
            (echo["body"], echo["chunks"]),
        )

        if h2_echo is not None:
            r = await s.post(h2_echo, data=(bytes([i]) * 30_000 for i in range(10)), verify=False)
            echo = r.json()
            check("async h2 streamed body", echo["length"] == 300_000, echo["length"])

    seen = []

    async def log(req, resp) -> None:
        await asyncio.sleep(0)
        seen.append(resp.status_code)

    async with JanusAsyncSession(logs=log, retry_num=1) as s:
        await s.get(f"{base}/redirect/2")
    check("async logs coroutine", seen == [302, 302, 200], seen)


if __name__ == "__main__":
    base = f"http://127.0.0.1:{sys.argv[1]}"

    h2_echo = f"https://127.0.0.1:{sys.argv[4]}/upload" if len(sys.argv) > 4 else None

    fingerprint()
    if len(sys.argv) > 5:
        sct(sys.argv[5])
    local(base)
    cookies(base)
    session_options(base, sys.argv[2] if len(sys.argv) > 2 else None, h2_echo)
    uploads(base, h2_echo)
    profiles()
    capture()
    if len(sys.argv) > 3:
        proxies(base, sys.argv[2], sys.argv[3])
    asyncio.run(run_async(base, h2_echo))

    failed = [name for name, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("failed:", failed)
        sys.exit(1)
