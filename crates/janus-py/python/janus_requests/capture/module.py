"""
Render one capture as an importable Python module: the profile, the headers, and ready-made session factories.
"""

from __future__ import annotations

import keyword

from ..codegen import ProfileWriter
from ..profile import JanusProfile


class CaptureModule:
    """
    Source of `<name>.py` for a navigation capture and the fetch()/XHR capture from the same page.
    """

    def __init__(
        self,
        name: str,
        navigation: JanusProfile,
        headers: list[tuple[str, str]],
        fetch: JanusProfile,
        fetch_headers: list[tuple[str, str]],
    ):
        if not is_module_name(name):
            raise ValueError(f"capture name {name!r} must be a Python identifier, e.g. my_chrome")

        self.name = name
        self.navigation = navigation
        self.headers = headers
        self.fetch = fetch
        self.fetch_headers = fetch_headers

    def render(self, summary: list[str], notes: list[str]) -> str:
        """
        Whole module text; `summary` lines and `notes` go into its docstring.
        """
        writer = ProfileWriter(self.navigation, "profile")
        body = writer.expression()
        writer.package_names.update({"JanusAsyncSession", "JanusSession"})

        page_headers = writer.headers(self.headers, 0)
        fetch_headers = writer.headers(self.fetch_overrides(), 0)
        fetch_order = writer.names(self.fetch.header_order, 0)

        sections = [
            self.docstring(summary, notes),
            writer.imports(),
            f"profile = {body}\n",
            f"# headers of the page request, sent by every request of session()\nheaders = {page_headers}\n",
            (
                "# a fetch()/XHR from the page: pass both to one request; "
                "None drops a page header the XHR does not send\n"
                f"fetch_headers = {fetch_headers}\n"
                f"fetch_header_order = {fetch_order}\n"
            ),
            self.factories(),
        ]
        return "\n\n".join(sections)

    def docstring(self, summary: list[str], notes: list[str]) -> str:
        lines = [f"{self.name}: browser identity captured by janus-capture.", "", *summary, ""]
        lines += [
            "Usage:",
            "",
            f"    import {self.name}",
            "",
            f"    s = {self.name}.session()",
            '    page = s.get("https://example.com/")',
            "    api = s.post(",
            '        "https://example.com/api",',
            "        json={...},",
            f"        headers={self.name}.fetch_headers,",
            f"        header_order={self.name}.fetch_header_order,",
            "    )",
            "",
            f"    {self.name}.fetch_session() sends every request like the fetch()/XHR, for API-only clients;",
            f"    {self.name}.async_session() is the asyncio version of session(); keyword options go to JanusSession.",
        ]
        if notes:
            lines += ["", "Notes:", *(f"- {n}" for n in notes)]

        text = "\n".join(lines).replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
        return f'"""\n{text}\n"""'

    def fetch_overrides(self) -> list[tuple[str, str | None]]:
        """
        The XHR's own headers plus None for each page header it does not carry.
        """
        sent = {n.lower() for n, _ in self.fetch_headers}
        dropped = [(n, None) for n, _ in self.headers if n.lower() not in sent]
        return [*self.fetch_headers, *dropped]

    def factories(self) -> str:
        fetch_name = f"{self.navigation.name}_fetch"
        return f'''def session(**options) -> JanusSession:
    """
    JanusSession with this browser's identity and page headers; options go to JanusSession.
    """
    options.setdefault("headers", headers)
    return JanusSession(janus=profile, **options)


def async_session(**options) -> JanusAsyncSession:
    """
    JanusAsyncSession with this browser's identity and page headers.
    """
    options.setdefault("headers", headers)
    return JanusAsyncSession(janus=profile, **options)


def fetch_session(**options) -> JanusSession:
    """
    JanusSession whose every request looks like the page's fetch()/XHR.
    """
    janus = profile.copy()
    janus.name = {fetch_name!r}
    janus.header_order = list(fetch_header_order)

    options.setdefault("headers", {{n: v for n, v in fetch_headers.items() if v is not None}})
    return JanusSession(janus=janus, **options)
'''


def is_module_name(name: str) -> bool:
    return name.isidentifier() and not keyword.iskeyword(name)
