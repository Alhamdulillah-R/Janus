"""
Render one capture as an importable Python module: the profile, the page headers, and ready-made session factories.
"""

from __future__ import annotations

import keyword

from ..codegen import ProfileWriter
from ..profile import JanusProfile


class CaptureModule:
    """
    Source of `<name>.py` for one captured browser.
    """

    def __init__(self, name: str, profile: JanusProfile, headers: list[tuple[str, str]]):
        if not is_module_name(name):
            raise ValueError(f"capture name {name!r} must be a Python identifier, e.g. my_chrome")

        self.name = name
        self.profile = profile
        self.headers = headers

    def render(self, summary: list[str], notes: list[str]) -> str:
        """
        Whole module text; `summary` lines and `notes` go into its docstring.
        """
        writer = ProfileWriter(self.profile, "profile")
        body = writer.expression()
        writer.package_names.update({"JanusAsyncSession", "JanusSession"})

        sections = [
            self.docstring(summary, notes),
            writer.imports(),
            f"profile = {body}\n",
            f"# headers of the page request, sent by every request of session()\nheaders = {writer.headers(self.headers, 0)}\n",
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
            '        headers={"Sec-Fetch-Mode": "cors", "Upgrade-Insecure-Requests": None},',
            "    )",
            "",
            f"    {self.name}.async_session() is the asyncio version; keyword options go to JanusSession.",
            "    Per-request headers= replace a page header, None drops it.",
        ]
        if notes:
            lines += ["", "Notes:", *(f"- {n}" for n in notes)]

        text = "\n".join(lines).replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
        return f'"""\n{text}\n"""'

    def factories(self) -> str:
        return '''def session(**options) -> JanusSession:
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
'''


def is_module_name(name: str) -> bool:
    return name.isidentifier() and not keyword.iskeyword(name)
