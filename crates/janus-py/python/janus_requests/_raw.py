from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from http import HTTPStatus
from http.client import HTTPMessage

from requests.exceptions import ChunkedEncodingError, ContentDecodingError, SSLError
from requests.exceptions import ConnectionError as RequestsConnectionError
from urllib3 import HTTPHeaderDict

from ._native import NativeError, NativeResponse


class _OriginalResponse:
    """
    Stand-in for http.client.HTTPResponse carrying the parsed headers the way cookiejar reads them.
    """

    def __init__(self, msg: HTTPMessage):
        self.msg = msg


class JanusRaw:
    """
    The `Response.raw` object: a urllib3.HTTPResponse-like reader over a native response body.
    """

    def __init__(self, native: NativeResponse):
        self._native = native
        self._buffer = bytearray()
        self._eof = False
        self._closed = False

        self.status: int = native.status
        self.version: int = native.version
        self.version_string: str = native.http_version
        self.url: str = native.url
        self.request_headers: list[tuple[str, str]] = native.request_headers
        self.tls_session_reused: bool = native.tls_session_reused
        self.decode_content = False

        try:
            self.reason = HTTPStatus(self.status).phrase
        except ValueError:
            self.reason = ""

        self.headers = HTTPHeaderDict()
        msg = HTTPMessage()
        for name, value in native.headers:
            self.headers.add(name, value)
            msg[name] = value
        self._original_response = _OriginalResponse(msg)

    @property
    def closed(self) -> bool:
        return self._closed

    def readable(self) -> bool:
        return True

    def isclosed(self) -> bool:
        return self._closed

    def _body_error(self, e: NativeError) -> Exception:
        """
        Map a native body error to the exception requests raises while reading content.
        """
        kind, message = e.args
        if kind == "decode":
            return ContentDecodingError(message)
        if kind == "tls":
            return SSLError(message)
        if kind in ("body", "http2", "protocol"):
            return ChunkedEncodingError(message)
        return RequestsConnectionError(message)

    def _next(self, decode: bool) -> bytes | None:
        if self._eof:
            return None
        try:
            chunk = self._native.read_chunk(decode)
        except NativeError as e:
            self._eof = True
            raise self._body_error(e) from e

        if chunk is None:
            self._eof = True
        return chunk

    async def _anext(self, decode: bool) -> bytes | None:
        if self._eof:
            return None
        try:
            chunk = await self._native.read_chunk_async(decode)
        except NativeError as e:
            self._eof = True
            raise self._body_error(e) from e

        if chunk is None:
            self._eof = True
        return chunk

    def read(self, amt: int | None = None, decode_content: bool | None = None, cache_content: bool = False) -> bytes:
        """
        Read up to amt bytes (everything when amt is None); undecoded unless decode_content is true.
        """
        decode = self.decode_content if decode_content is None else bool(decode_content)

        if amt is None:
            data = bytes(self._buffer)
            self._buffer.clear()
            if not self._eof:
                try:
                    data += self._native.read_all(decode)
                except NativeError as e:
                    raise self._body_error(e) from e
                finally:
                    self._eof = True
            return data

        while len(self._buffer) < amt:
            chunk = self._next(decode)
            if chunk is None:
                break
            self._buffer += chunk

        data = bytes(self._buffer[:amt])
        del self._buffer[:amt]
        return data

    def stream(self, amt: int | None = 2**16, decode_content: bool | None = None) -> Iterator[bytes]:
        """
        Yield the body in pieces of at most amt bytes, or as it arrives when amt is None.
        """
        decode = self.decode_content if decode_content is None else bool(decode_content)

        if amt is None:
            if self._buffer:
                yield bytes(self._buffer)
                self._buffer.clear()
            while True:
                chunk = self._next(decode)
                if chunk is None:
                    return
                yield chunk

        while True:
            data = self.read(amt, decode)
            if not data:
                return
            yield data

    async def aread(self, amt: int | None = None, decode_content: bool | None = None) -> bytes:
        """
        Awaitable read with the same semantics as read.
        """
        decode = self.decode_content if decode_content is None else bool(decode_content)

        if amt is None:
            data = bytes(self._buffer)
            self._buffer.clear()
            if not self._eof:
                try:
                    data += await self._native.read_all_async(decode)
                except NativeError as e:
                    raise self._body_error(e) from e
                finally:
                    self._eof = True
            return data

        while len(self._buffer) < amt:
            chunk = await self._anext(decode)
            if chunk is None:
                break
            self._buffer += chunk

        data = bytes(self._buffer[:amt])
        del self._buffer[:amt]
        return data

    async def astream(self, amt: int | None = 2**16, decode_content: bool | None = None) -> AsyncIterator[bytes]:
        """
        Awaitable counterpart of stream.
        """
        decode = self.decode_content if decode_content is None else bool(decode_content)

        if amt is None:
            if self._buffer:
                yield bytes(self._buffer)
                self._buffer.clear()
            while True:
                chunk = await self._anext(decode)
                if chunk is None:
                    return
                yield chunk

        while True:
            data = await self.aread(amt, decode)
            if not data:
                return
            yield data

    def close(self) -> None:
        if not self._closed:
            self._native.close()
            self._closed = True
            self._eof = True

    def release_conn(self) -> None:
        """
        Connections return to the pool on their own once the body is fully read.
        """
