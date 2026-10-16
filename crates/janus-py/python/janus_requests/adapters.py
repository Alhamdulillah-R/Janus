from __future__ import annotations

import inspect
import os
import time
from collections.abc import Callable, Iterator, Mapping
from datetime import timedelta
from typing import Any

from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.exceptions import (
    ChunkedEncodingError,
    ConnectTimeout,
    ContentDecodingError,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    SSLError,
    Timeout,
)
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.models import PreparedRequest, Response
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers, prepend_scheme_if_needed, rewind_body, select_proxy
from urllib3.util import Timeout as Urllib3Timeout

from ._native import NativeClient, NativeError, NativeUpload
from ._raw import JanusRaw
from .profile import JanusProfile


class JanusAdapter(BaseAdapter):
    """
    requests transport adapter that sends through Janus with an exact TLS/HTTP2 identity.
    """

    def __init__(
        self,
        janus: str | JanusProfile = "chrome155",
        *,
        http_version: str = "auto",
        logs: Callable[[PreparedRequest, Response], Any] | None = None,
        retry_num: int = 0,
    ):
        super().__init__()

        # a private copy: editing the caller's profile later does not change this adapter
        self.profile = JanusProfile.resolve(janus)
        self.native = NativeClient(self.profile.to_native(), http_version=http_version)
        self.upload_chunk_size = 64 * 1024
        # called as logs(request, response) for every response that comes back, redirect hops included
        self.logs = logs
        # extra attempts after a connection-level failure (refused, reset, TLS, proxy, connect timeout)
        self.retry_num = retry_num

    def send(
        self,
        request: PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
        proxies: Mapping[str, str] | None = None,
        priority: tuple[int, int, bool] | None = None,
        header_order: list[str] | None = None,
        retry_num: int | None = None,
    ) -> Response:
        method, url, headers, kwargs = self.native_args(request, timeout, verify, cert, proxies, priority, header_order)
        attempts = self.attempts(retry_num)
        start = time.perf_counter()

        for attempt in range(attempts):
            try:
                if self.is_streamed(request.body):
                    native = self.send_streamed(request, method, url, headers, kwargs)
                else:
                    native = self.native.request(method, url, headers, self.body_bytes(request.body), **kwargs)
                break
            except NativeError as e:
                if attempt + 1 == attempts or not self.can_retry(e, request):
                    raise self.send_error(e, request) from e

        response = self.build_response(request, JanusRaw(native))
        response.elapsed = timedelta(seconds=time.perf_counter() - start)
        if not stream:
            response._content = response.raw.read(decode_content=True)
            response._content_consumed = True

        if self.logs is not None:
            result = self.logs(request, response)
            if inspect.isawaitable(result):
                result.close()
                response.close()
                raise TypeError(
                    "logs= of a JanusSession must be a plain function; use JanusAsyncSession for async logs"
                )
        return response

    async def send_async(
        self,
        request: PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
        proxies: Mapping[str, str] | None = None,
        priority: tuple[int, int, bool] | None = None,
        header_order: list[str] | None = None,
        retry_num: int | None = None,
        response_class: type[Response] = Response,
    ) -> Response:
        """
        asyncio counterpart of send; the body may also be an async iterable, logs may be a coroutine function.
        """
        method, url, headers, kwargs = self.native_args(request, timeout, verify, cert, proxies, priority, header_order)
        attempts = self.attempts(retry_num)
        start = time.perf_counter()

        for attempt in range(attempts):
            try:
                if self.is_streamed(request.body):
                    native = await self.send_streamed_async(request, method, url, headers, kwargs)
                else:
                    body = self.body_bytes(request.body)
                    native = await self.native.request_async(method, url, headers, body, **kwargs)
                break
            except NativeError as e:
                if attempt + 1 == attempts or not self.can_retry(e, request):
                    raise self.send_error(e, request) from e

        response = self.build_response(request, JanusRaw(native), response_class)
        response.elapsed = timedelta(seconds=time.perf_counter() - start)
        if not stream:
            response._content = await response.raw.aread(decode_content=True)
            response._content_consumed = True

        if self.logs is not None:
            result = self.logs(request, response)
            if inspect.isawaitable(result):
                await result
        return response

    def attempts(self, retry_num: int | None) -> int:
        """
        Total tries for one request: 1 plus the per-request or adapter retry_num.
        """
        retries = self.retry_num if retry_num is None else retry_num
        if not isinstance(retries, int) or isinstance(retries, bool) or retries < 0:
            raise ValueError(f"retry_num must be a non-negative int, got {retries!r}")
        return 1 + retries

    def can_retry(self, error: NativeError, request: PreparedRequest) -> bool:
        """
        Retry connection failures: before the request went out always, after it went out only for idempotent methods.
        """
        kind = error.args[0]
        if kind in ("disconnected", "io", "http2"):
            if request.method not in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"):
                return False
        elif kind not in ("connect", "connect_timeout", "proxy", "tls"):
            return False

        if not self.is_streamed(request.body):
            return True
        if request._body_position is None or not hasattr(request.body, "seek"):
            return False

        rewind_body(request)
        return True

    def send_streamed(
        self,
        request: PreparedRequest,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        kwargs: dict[str, Any],
    ) -> Any:
        """
        Send a file or iterable body piece by piece; returns the native response.
        """
        upload = self.start_upload(request, method, url, headers, kwargs)

        try:
            for chunk in self.body_chunks(request.body):
                if not upload.write(chunk):
                    break
        except BaseException:
            upload.abort()
            raise
        return upload.response()

    async def send_streamed_async(
        self,
        request: PreparedRequest,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        kwargs: dict[str, Any],
    ) -> Any:
        upload = self.start_upload(request, method, url, headers, kwargs)

        try:
            if hasattr(request.body, "__aiter__"):
                async for part in request.body:
                    if not await upload.write_async(self.chunk_bytes(part)):
                        break
            else:
                for chunk in self.body_chunks(request.body):
                    if not await upload.write_async(chunk):
                        break
        except BaseException:
            upload.abort()
            raise
        return await upload.response_async()

    def start_upload(
        self,
        request: PreparedRequest,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        kwargs: dict[str, Any],
    ) -> NativeUpload:
        """
        Start a streamed request; Content-Length and Transfer-Encoding are set by Janus per protocol.
        """
        length = None
        framing = []

        for name, value in headers:
            lower = name.lower()
            if lower == "content-length":
                length = int(value)
            if lower in ("content-length", "transfer-encoding"):
                framing.append((name, value))

        sent = [(n, v) for n, v in headers if (n, v) not in framing]
        return self.native.start(method, url, sent, body_length=length, **kwargs)

    def is_streamed(self, body: Any) -> bool:
        return body is not None and not isinstance(body, (bytes, bytearray, memoryview, str))

    def chunk_bytes(self, part: Any) -> bytes:
        if isinstance(part, str):
            return part.encode("utf-8")
        return bytes(part)

    def body_chunks(self, body: Any) -> Iterator[bytes]:
        """
        Pieces of a file object (read in blocks) or of an iterable body.
        """
        if hasattr(body, "read"):
            while True:
                data = body.read(self.upload_chunk_size)
                if not data:
                    return
                yield self.chunk_bytes(data)

        for part in body:
            yield self.chunk_bytes(part)

    def close(self) -> None:
        self.native.close()

    def build_response(
        self, req: PreparedRequest, raw: JanusRaw, response_class: type[Response] = Response
    ) -> Response:
        """
        Same fields as requests' HTTPAdapter.build_response, from a Janus raw response.
        """
        response = response_class()

        response.status_code = raw.status
        response.headers = CaseInsensitiveDict(raw.headers)
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = raw
        response.reason = raw.reason
        response.url = req.url.decode("utf-8") if isinstance(req.url, bytes) else req.url

        extract_cookies_to_jar(response.cookies, req, raw)

        response.request = req
        response.connection = self
        return response

    def native_args(
        self,
        request: PreparedRequest,
        timeout: Any,
        verify: bool | str,
        cert: str | tuple[str, str] | None,
        proxies: Mapping[str, str] | None,
        priority: tuple[int, int, bool] | None,
        header_order: list[str] | None,
    ) -> tuple[str, str, list[tuple[str, str]], dict[str, Any]]:
        """
        Method, URL, headers and keyword options for NativeClient.request/start built from a PreparedRequest.
        """
        connect_timeout, read_timeout = self.split_timeout(timeout)
        headers = []

        for name, value in request.headers.items():
            # the proxy handshake carries its own credentials, they must not reach the origin
            if name.lower() == "proxy-authorization":
                continue
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            headers.append((name, str(value)))

        proxy = select_proxy(request.url, proxies)
        if proxy:
            proxy = prepend_scheme_if_needed(proxy, "http")

        kwargs = {
            "connect_timeout": connect_timeout,
            "read_timeout": read_timeout,
            "verify": self.verify_arg(request.url, verify),
            "cert": self.cert_arg(cert),
            "proxy": proxy,
            "priority": priority,
            "header_order": header_order,
        }
        return request.method or "GET", request.url, headers, kwargs

    def split_timeout(self, timeout: Any) -> tuple[float | None, float | None]:
        """
        (connect, read) seconds from a requests timeout value.
        """
        if timeout is None:
            return None, None
        if isinstance(timeout, Urllib3Timeout):
            return timeout.connect_timeout, timeout.read_timeout
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
            except ValueError:
                raise ValueError(
                    f"Invalid timeout {timeout}. Pass a (connect, read) timeout tuple, or a single float to set both timeouts to the same value."
                ) from None
            return connect, read
        return timeout, timeout

    def verify_arg(self, url: str, verify: bool | str) -> bool | str:
        """
        Validate verify the way requests does; True means the operating-system trust store.
        """
        if verify is True or verify is False:
            return verify
        if not url.lower().startswith("https"):
            return bool(verify)
        if not os.path.exists(verify):
            raise OSError(f"Could not find a suitable TLS CA certificate bundle, invalid path: {verify}")
        return verify

    def cert_arg(self, cert: str | tuple[str, str] | None) -> str | tuple[str, str] | None:
        if not cert:
            return None

        if isinstance(cert, str):
            cert_file, key_file = cert, None
        else:
            cert_file, key_file = cert[0], cert[1]

        if not os.path.exists(cert_file):
            raise OSError(f"Could not find the TLS certificate file, invalid path: {cert_file}")
        if key_file and not os.path.exists(key_file):
            raise OSError(f"Could not find the TLS key file, invalid path: {key_file}")
        if key_file:
            return cert_file, key_file
        return cert_file

    def body_bytes(self, body: bytes | bytearray | memoryview | str | None) -> bytes | None:
        if body is None:
            return None
        return self.chunk_bytes(body)

    def send_error(self, e: NativeError, request: PreparedRequest) -> Exception:
        """
        Map a native send error to the exception HTTPAdapter.send would raise.
        """
        kind, message = e.args

        if kind == "connect_timeout":
            return ConnectTimeout(message, request=request)
        if kind == "read_timeout":
            return ReadTimeout(message, request=request)
        if kind == "timeout":
            return Timeout(message, request=request)
        if kind == "proxy":
            return ProxyError(message, request=request)
        if kind == "tls":
            return SSLError(message, request=request)
        if kind == "url":
            return InvalidURL(message, request=request)
        if kind == "decode":
            return ContentDecodingError(message, request=request)
        if kind == "body":
            return ChunkedEncodingError(message, request=request)
        return RequestsConnectionError(message, request=request)
