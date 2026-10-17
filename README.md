# Janus

可精确控制 TLS ClientHello 与 HTTP/2 帧的 HTTP 客户端：Rust 核心 + requests 兼容的 Python 包 `janus_requests`。

- `crates/janus`：客户端核心（HTTP/1.1、HTTP/2、TLS 会话复用、代理、流式上传）
- `crates/janus-h2`：fork 自 [http2](https://github.com/0x676e67/http2) 0.5.20（它本身是 [h2](https://github.com/hyperium/h2) 的 fork），加了单请求优先级和 HPACK 编码控制
- `crates/janus-py`：PyO3 绑定和 Python 包 `janus_requests`（含本地浏览器抓取服务器 `janus-capture`）
- `patches/openssl`：给 OpenSSL 4.0.3 的 ClientHello 补丁（扩展顺序、GREASE、ALPS、原始扩展等）
- `tools`：测试服务器和功能测试脚本

## 用法

```python
from janus_requests import JanusSession

with JanusSession(janus="chrome155", headers={"User-Agent": "..."}, proxy="http://127.0.0.1:7890", retry_num=2) as s:
    r = s.get("https://example.com/")
```

- 不带任何默认请求头，发出去的头只有你给的（外加 Host / Content-Length / Cookie）
- `verify` 默认关，不读环境变量和系统代理
- `janus=` 接受内置名 `chrome155` 或 `JanusProfile`
- `logs=func(req, resp)` 每个响应回调一次，`retry_num=` 只重试连接类错误
- `import janus_requests as requests` 可当 requests 用

抓取真实浏览器生成 profile：

```bash
uv run janus-capture --name my_chrome
# 浏览器打开 https://localhost:8443/
```

打开页面当场写出 `my_chrome.py`（`import my_chrome; my_chrome.session()`）和 `my_chrome.json`；页面脚本随后再开几轮新连接（`--rounds`，默认 4），补上扩展乱序和会话恢复（PSK）。不跑 JS 的客户端只打开一次也能出结果，notes 里会写明缺了什么。抓取时关掉系统代理（如 Reqable），否则抓到的是代理的指纹。

## 编译

依赖源码放在 `third_party/`（不进仓库）：

```bash
git clone https://github.com/openssl/openssl third_party/openssl      # openssl-4.0.3 = af1775b6
git clone -b v1.3.1 https://github.com/madler/zlib third_party/zlib
git clone -b v1.2.0 https://github.com/google/brotli third_party/brotli
git clone -b v1.5.7 https://github.com/facebook/zstd third_party/zstd
```

1. OpenSSL（打补丁并静态编译到 `build/`）
   - Windows：`scripts\build-openssl-windows.ps1`（MSVC、Strawberry Perl、NASM、CMake，路径在脚本顶部）
   - Linux：`scripts/build-openssl-linux.sh`（需要 `libz-dev libbrotli-dev libzstd-dev`）
2. Rust：`cargo build --release -p janus`
3. Python wheel：`cd crates/janus-py && uvx maturin build --release`

## 测试

`tools/py-run.ps1`（Windows）和 `tools/py-run.sh`（Linux）会编译、起本地测试服务器和代理，跑 `tools/py_functional.py`。

## 许可证

- 本仓库代码以 MIT 发布，见 `LICENSE`
- `crates/janus-h2` 沿用上游 http2 / h2 的 MIT 许可证，见 `crates/janus-h2/LICENSE`
- `patches/openssl` 是 OpenSSL 的衍生作品，按 OpenSSL 的 Apache-2.0 许可证发布；静态链接了 OpenSSL 的二进制分发时需附带其许可证
