# janus-requests

requests 兼容的 HTTP 客户端，TLS ClientHello 和 HTTP/2 帧逐字节可控：扩展顺序、GREASE、ALPS、密码套件、SETTINGS、WINDOW_UPDATE、伪头顺序、HPACK 编码都由 profile 决定。核心是 Rust，TLS 用打过补丁的 OpenSSL 4.0.3（静态链接在 wheel 里）。

```bash
uv add janus-requests
```

## 用法

```python
from janus_requests import JanusSession

with JanusSession(janus="chrome155", headers={"User-Agent": "..."}, proxy="http://127.0.0.1:7890", retry_num=2) as s:
    r = s.get("https://example.com/")
    print(r.status_code, r.raw.version_string)
```

- 不带任何默认请求头，发出去的头只有你给的（外加 Host / Content-Length / Cookie）
- `verify` 默认关，不读环境变量和系统代理
- `janus=` 接受内置名 `chrome155` 或 `JanusProfile`
- `logs=func(req, resp)` 每个响应回调一次，`retry_num=` 只重试连接类错误
- `timeout=` 可以设在 session 上（秒数或 `(connect, read)`），请求级 `timeout=` 优先
- 请求级 `headers=` 覆盖 session 的同名头，值为 `None` 表示这次不发
- `JanusAsyncSession` 是 asyncio 版本；`import janus_requests as requests` 可当 requests 用

## 从真浏览器抓 profile

```bash
uv add "janus-requests[capture]"
uv run janus-capture --name my_chrome
# 浏览器打开 https://localhost:8443/
```

打开页面当场写出 `my_chrome.py` 和 `my_chrome.json`，`import my_chrome; my_chrome.session()` 即可复现这个浏览器。页面脚本随后再开几轮新连接（`--rounds`，默认 4），补上扩展乱序和会话恢复（PSK）。抓取时关掉系统代理，否则抓到的是代理的指纹。

## 许可证

MIT。wheel 里静态链接的 OpenSSL（含 Janus 的 ClientHello 补丁）按 Apache-2.0 发布，zlib、brotli、zstd 和 Rust 依赖的许可证见 wheel 的 `.dist-info/licenses/`。
