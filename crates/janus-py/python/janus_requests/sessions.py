from __future__ import annotations

import codecs
import time
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import timedelta
from http.cookiejar import CookieJar
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import requests
from requests._internal_utils import to_native_string
from requests.cookies import cookiejar_from_dict, extract_cookies_to_jar, merge_cookies
from requests.exceptions import ChunkedEncodingError, ContentDecodingError, StreamConsumedError, TooManyRedirects
from requests.hooks import dispatch_hook
from requests.models import ITER_CHUNK_SIZE, PreparedRequest, Request, Response
from requests.status_codes import codes
from requests.structures import CaseInsensitiveDict
from requests.utils import requote_uri, resolve_proxies, rewind_body

from .adapters import JanusAdapter
from .profile import JanusProfile

if TYPE_CHECKING:
    from typing_extensions import Self


class JanusSession(requests.Session):
    """
    requests.Session whose http:// and https:// traffic goes through Janus with one fixed identity.
    """

    def __init__(
        self,
        janus: str | JanusProfile = "chrome155",
        *,
        http_version: str = "auto",
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | CookieJar | None = None,
        proxies: Mapping[str, str] | None = None,
        proxy: str | None = None,
        verify: bool | str = False,
        logs: Callable[[PreparedRequest, Response], Any] | None = None,
        retry_num: int = 0,
        timeout: Any = None,
    ):
        super().__init__()

        adapter = JanusAdapter(janus, http_version=http_version, logs=logs, retry_num=retry_num)
        adapter.attempts(None)
        self.mount("https://", adapter)
        self.mount("http://", adapter)
        self.janus_adapter = adapter

        # no default headers: only what the caller sets goes on the wire (plus Host/Content-Length/Cookie)
        self.headers = CaseInsensitiveDict(headers or {})
        self.verify = verify
        # seconds or (connect, read) for requests that pass no timeout=
        self.timeout = timeout
        self.proxies = proxy_map(proxies, proxy) or {}
        # never read the environment: system / env proxies would silently override proxies=
        self.trust_env = False
        if cookies is not None:
            self.cookies = cookiejar_from_dict(cookies) if isinstance(cookies, Mapping) else cookies

    @property
    def profile(self) -> JanusProfile:
        """
        Copy of the profile in use; a changed copy takes effect in a new session.
        """
        return self.janus_adapter.profile.copy()

    @property
    def janus(self) -> str:
        """
        Name of the profile in use.
        """
        return self.janus_adapter.profile.name

    @property
    def logs(self) -> Callable[[PreparedRequest, Response], Any] | None:
        return self.janus_adapter.logs

    @logs.setter
    def logs(self, func: Callable[[PreparedRequest, Response], Any] | None) -> None:
        self.janus_adapter.logs = func

    @property
    def retry_num(self) -> int:
        return self.janus_adapter.retry_num

    @retry_num.setter
    def retry_num(self, value: int) -> None:
        self.janus_adapter.retry_num = value
        self.janus_adapter.attempts(None)

    def clear_tls_sessions(self) -> None:
        """
        Forget cached TLS sessions so the next connections do full handshakes.
        """
        self.janus_adapter.native.clear_tls_sessions()

    def request(
        self,
        method: str | bytes,
        url: str | bytes,
        params: Any = None,
        data: Any = None,
        headers: Any = None,
        cookies: Any = None,
        files: Any = None,
        auth: Any = None,
        timeout: Any = None,
        allow_redirects: bool = True,
        proxies: dict[str, str] | None = None,
        hooks: Any = None,
        stream: bool | None = None,
        verify: bool | str | None = None,
        cert: Any = None,
        json: Any = None,
        priority: tuple[int, int, bool] | None = None,
        header_order: list[str] | None = None,
        proxy: str | None = None,
        retry_num: int | None = None,
    ) -> Response:
        """
        requests.Session.request plus priority=(depends_on, weight, exclusive), header_order, proxy and retry_num;
        timeout=None falls back to the session's timeout.
        """
        prep, send_kwargs = self.prepare_send(
            method,
            url,
            params,
            data,
            headers,
            cookies,
            files,
            auth,
            timeout,
            allow_redirects,
            proxies,
            hooks,
            stream,
            verify,
            cert,
            json,
            priority,
            header_order,
            proxy,
            retry_num,
        )
        return self.send(prep, **send_kwargs)

    def prepare_send(
        self,
        method: str | bytes,
        url: str | bytes,
        params: Any,
        data: Any,
        headers: Any,
        cookies: Any,
        files: Any,
        auth: Any,
        timeout: Any,
        allow_redirects: bool,
        proxies: dict[str, str] | None,
        hooks: Any,
        stream: bool | None,
        verify: bool | str | None,
        cert: Any,
        json: Any,
        priority: tuple[int, int, bool] | None,
        header_order: list[str] | None,
        proxy: str | None,
        retry_num: int | None,
    ) -> tuple[PreparedRequest, dict[str, Any]]:
        """
        The PreparedRequest and send() keyword arguments requests.Session.request would build.
        """
        # requests cannot prepare an async iterable body: prepare without it, then attach it chunked
        async_body = data if hasattr(data, "__aiter__") else None
        if async_body is not None:
            data = None

        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)
        if async_body is not None:
            prep.body = async_body
            if not any(str(name).lower() == "content-length" for name in headers or {}):
                prep.headers.pop("Content-Length", None)
                prep.headers["Transfer-Encoding"] = "chunked"

        if timeout is None:
            timeout = self.timeout

        settings = self.merge_environment_settings(prep.url, proxy_map(proxies, proxy) or {}, stream, verify, cert)
        send_kwargs: dict[str, Any] = {
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        }
        send_kwargs.update(settings)
        if priority is not None:
            send_kwargs["priority"] = priority
        if header_order is not None:
            send_kwargs["header_order"] = header_order
        if retry_num is not None:
            send_kwargs["retry_num"] = retry_num
        return prep, send_kwargs


class AsyncResponse(Response):
    """
    Response with awaitable body access for AsyncSession(stream=True).
    """

    async def aread(self) -> bytes:
        """
        Read and cache the whole decoded body.
        """
        if self._content is False:
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed")
            if self.status_code == 0 or self.raw is None:
                self._content = None
            else:
                self._content = await self.raw.aread(decode_content=True)
        self._content_consumed = True
        return self._content

    async def aiter_content(self, chunk_size: int | None = 1, decode_unicode: bool = False) -> AsyncIterator[Any]:
        """
        Async iter_content: decoded body pieces of at most chunk_size bytes.
        """
        if self._content_consumed and isinstance(self._content, bool):
            raise StreamConsumedError()
        if chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError(f"chunk_size must be an int, it is instead a {type(chunk_size)}.")

        decoder = None
        if decode_unicode and self.encoding is not None:
            decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")

        if self._content_consumed:
            content = self._content or b""
            step = chunk_size or len(content) or 1
            source = [content[i : i + step] for i in range(0, len(content), step)]
        else:
            source = None

        if source is not None:
            for chunk in source:
                out = decoder.decode(chunk) if decoder else chunk
                if out:
                    yield out
        else:
            async for chunk in self.raw.astream(chunk_size, decode_content=True):
                out = decoder.decode(chunk) if decoder else chunk
                if out:
                    yield out
            self._content_consumed = True

        if decoder:
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail

    async def aiter_lines(
        self,
        chunk_size: int = ITER_CHUNK_SIZE,
        decode_unicode: bool = False,
        delimiter: str | bytes | None = None,
    ) -> AsyncIterator[Any]:
        """
        Async iter_lines with the same splitting rules as requests.
        """
        pending = None

        async for chunk in self.aiter_content(chunk_size=chunk_size, decode_unicode=decode_unicode):
            if pending is not None:
                chunk = pending + chunk

            lines = chunk.split(delimiter) if delimiter else chunk.splitlines()
            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending

    async def aclose(self) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.close()


class JanusAsyncSession:
    """
    asyncio session with requests' semantics (cookies, auth, redirects, hooks, environment) over Janus.
    """

    def __init__(
        self,
        janus: str | JanusProfile = "chrome155",
        *,
        http_version: str = "auto",
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | CookieJar | None = None,
        proxies: Mapping[str, str] | None = None,
        proxy: str | None = None,
        verify: bool | str = False,
        logs: Callable[[PreparedRequest, Response], Any] | None = None,
        retry_num: int = 0,
        timeout: Any = None,
    ):
        """
        Same options as JanusSession; logs may also be a coroutine function.
        """
        self.sync = JanusSession(
            janus,
            http_version=http_version,
            headers=headers,
            cookies=cookies,
            proxies=proxies,
            proxy=proxy,
            verify=verify,
            logs=logs,
            retry_num=retry_num,
            timeout=timeout,
        )

    def __getattr__(self, name: str) -> Any:
        # headers, cookies, auth, proxies, params, verify, cert, max_redirects, trust_env, profile ...
        if name == "sync":
            raise AttributeError(name)
        return getattr(self.sync, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "sync":
            object.__setattr__(self, name, value)
            return
        setattr(self.sync, name, value)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.sync.close()

    async def request(
        self,
        method: str | bytes,
        url: str | bytes,
        params: Any = None,
        data: Any = None,
        headers: Any = None,
        cookies: Any = None,
        files: Any = None,
        auth: Any = None,
        timeout: Any = None,
        allow_redirects: bool = True,
        proxies: dict[str, str] | None = None,
        hooks: Any = None,
        stream: bool | None = None,
        verify: bool | str | None = None,
        cert: Any = None,
        json: Any = None,
        priority: tuple[int, int, bool] | None = None,
        header_order: list[str] | None = None,
        proxy: str | None = None,
        retry_num: int | None = None,
    ) -> AsyncResponse:
        prep, send_kwargs = self.sync.prepare_send(
            method,
            url,
            params,
            data,
            headers,
            cookies,
            files,
            auth,
            timeout,
            allow_redirects,
            proxies,
            hooks,
            stream,
            verify,
            cert,
            json,
            priority,
            header_order,
            proxy,
            retry_num,
        )
        return await self.send(prep, **send_kwargs)

    async def send(self, request: PreparedRequest, **kwargs: Any) -> AsyncResponse:
        """
        requests.Session.send with an awaited transport and awaited redirects.
        """
        session = self.sync
        kwargs.setdefault("stream", session.stream)
        kwargs.setdefault("verify", session.verify)
        kwargs.setdefault("cert", session.cert)
        if "proxies" not in kwargs:
            kwargs["proxies"] = resolve_proxies(request, session.proxies, session.trust_env)

        if isinstance(request, Request):
            raise ValueError("You can only send PreparedRequests.")  # noqa: TRY004 - same exception as requests

        allow_redirects = kwargs.pop("allow_redirects", True)
        stream = kwargs.get("stream")
        hooks = request.hooks

        adapter = session.get_adapter(url=request.url)
        if not isinstance(adapter, JanusAdapter):
            raise TypeError(f"JanusAsyncSession needs a JanusAdapter for {request.url}, got {type(adapter).__name__}")

        start = time.perf_counter()
        r = await adapter.send_async(request, response_class=AsyncResponse, **kwargs)
        r.elapsed = timedelta(seconds=time.perf_counter() - start)

        r = dispatch_hook("response", hooks, r, **kwargs)

        if r.history:
            for resp in r.history:
                extract_cookies_to_jar(session.cookies, resp.request, resp.raw)
        extract_cookies_to_jar(session.cookies, request, r.raw)

        history = await self.resolve_redirects(r, request, **kwargs) if allow_redirects else []
        if history:
            history.insert(0, r)
            r = history.pop()
            r.history = history

        if not allow_redirects and session.get_redirect_target(r):
            await r.aread()
            try:
                r._next = next(session.resolve_redirects(r, request, yield_requests=True, **kwargs))
            except StopIteration:
                pass

        if not stream:
            await r.aread()
        return r

    async def resolve_redirects(
        self,
        resp: AsyncResponse,
        req: PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: Any = None,
        proxies: dict[str, str] | None = None,
        **adapter_kwargs: Any,
    ) -> list[AsyncResponse]:
        """
        requests' resolve_redirects with awaited sends; returns every response after the first.
        """
        session = self.sync
        hist: list[AsyncResponse] = []
        out: list[AsyncResponse] = []

        url = session.get_redirect_target(resp)
        previous_fragment = urlparse(req.url).fragment
        while url:
            prepared_request = req.copy()

            resp.history = hist[:]
            hist.append(resp)

            try:
                await resp.aread()
            except (ChunkedEncodingError, ContentDecodingError, RuntimeError):
                await resp.raw.aread(decode_content=False)

            if len(resp.history) >= session.max_redirects:
                raise TooManyRedirects(f"Exceeded {session.max_redirects} redirects.", response=resp)

            resp.close()

            if url.startswith("//"):
                parsed_rurl = urlparse(resp.url)
                url = ":".join([to_native_string(parsed_rurl.scheme), url])

            parsed = urlparse(url)
            if parsed.fragment == "" and previous_fragment:
                parsed = parsed._replace(fragment=previous_fragment)
            elif parsed.fragment:
                previous_fragment = parsed.fragment
            url = parsed.geturl()

            if not parsed.netloc:
                url = urljoin(resp.url, requote_uri(url))
            else:
                url = requote_uri(url)

            prepared_request.url = to_native_string(url)
            session.rebuild_method(prepared_request, resp)

            if resp.status_code not in (codes.temporary_redirect, codes.permanent_redirect):
                for header in ("Content-Length", "Content-Type", "Transfer-Encoding"):
                    prepared_request.headers.pop(header, None)
                prepared_request.body = None

            headers = prepared_request.headers
            headers.pop("Cookie", None)

            cookie_jar = prepared_request._cookies
            extract_cookies_to_jar(cookie_jar, req, resp.raw)
            merge_cookies(cookie_jar, session.cookies)
            prepared_request.prepare_cookies(cookie_jar)

            proxies = session.rebuild_proxies(prepared_request, proxies)
            session.rebuild_auth(prepared_request, resp)

            rewindable = prepared_request._body_position is not None and (
                "Content-Length" in headers or "Transfer-Encoding" in headers
            )
            if rewindable:
                rewind_body(prepared_request)

            req = prepared_request
            resp = await self.send(
                req,
                stream=stream,
                timeout=timeout,
                verify=verify,
                cert=cert,
                proxies=proxies,
                allow_redirects=False,
                **adapter_kwargs,
            )
            extract_cookies_to_jar(session.cookies, prepared_request, resp.raw)

            url = session.get_redirect_target(resp)
            out.append(resp)
        return out

    async def get(self, url: str, **kwargs: Any) -> AsyncResponse:
        kwargs.setdefault("allow_redirects", True)
        return await self.request("GET", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> AsyncResponse:
        kwargs.setdefault("allow_redirects", True)
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> AsyncResponse:
        kwargs.setdefault("allow_redirects", False)
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> AsyncResponse:
        return await self.request("POST", url, data=data, json=json, **kwargs)

    async def put(self, url: str, data: Any = None, **kwargs: Any) -> AsyncResponse:
        return await self.request("PUT", url, data=data, **kwargs)

    async def patch(self, url: str, data: Any = None, **kwargs: Any) -> AsyncResponse:
        return await self.request("PATCH", url, data=data, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> AsyncResponse:
        return await self.request("DELETE", url, **kwargs)


def proxy_map(proxies: Mapping[str, str] | None, proxy: str | None) -> dict[str, str] | None:
    """
    requests-style proxies dict from either proxies= or a single proxy= URL used for http and https.
    """
    if proxy is None:
        return None if proxies is None else dict(proxies)
    if proxies is not None:
        raise ValueError("pass either proxy= or proxies=, not both")
    return {"http": proxy, "https": proxy}


# requests compatibility: `import janus_requests as requests` keeps Session / AsyncSession working
Session = JanusSession
AsyncSession = JanusAsyncSession


def session(janus: str | JanusProfile = "chrome155", **options: Any) -> JanusSession:
    """
    Same as JanusSession(...), mirroring requests.session().
    """
    return JanusSession(janus, **options)
