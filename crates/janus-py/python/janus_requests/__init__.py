"""
requests-compatible HTTP client whose TLS ClientHello and HTTP/2 framing are specified exactly.

`from janus_requests import JanusSession` for the Janus API, or `import janus_requests as requests`:
everything requests exports is exported here, with Session and the module-level functions sending through Janus.

init by Claude Opus 5.5 & Mignon Rex
"""

from requests import (
    ConnectionError,
    ConnectTimeout,
    FileModeWarning,
    HTTPError,
    JSONDecodeError,
    PreparedRequest,
    ReadTimeout,
    Request,
    RequestException,
    Response,
    Timeout,
    TooManyRedirects,
    URLRequired,
    auth,
    codes,
    cookies,
    exceptions,
    hooks,
    models,
    status_codes,
    structures,
    utils,
)

from . import registry
from .adapters import JanusAdapter
from .api import delete, get, head, options, patch, post, put, request
from .profile import (
    GREASE,
    EchGrease,
    Huffman,
    Indexing,
    JanusHpack,
    JanusHttp2,
    JanusPriority,
    JanusProfile,
    JanusTls,
    PriorityMode,
    PseudoHeader,
)
from .sessions import AsyncResponse, AsyncSession, JanusAsyncSession, JanusSession, Session, session

__version__ = "0.2.2"
__author__ = "Claude Opus 5.5 & Mignon Rex"

__all__ = [
    "GREASE",
    "AsyncResponse",
    "AsyncSession",
    "ConnectTimeout",
    "ConnectionError",
    "EchGrease",
    "FileModeWarning",
    "HTTPError",
    "Huffman",
    "Indexing",
    "JSONDecodeError",
    "JanusAdapter",
    "JanusAsyncSession",
    "JanusHpack",
    "JanusHttp2",
    "JanusPriority",
    "JanusProfile",
    "JanusSession",
    "JanusTls",
    "PreparedRequest",
    "PriorityMode",
    "PseudoHeader",
    "ReadTimeout",
    "Request",
    "RequestException",
    "Response",
    "Session",
    "Timeout",
    "TooManyRedirects",
    "URLRequired",
    "auth",
    "codes",
    "cookies",
    "delete",
    "exceptions",
    "get",
    "head",
    "hooks",
    "models",
    "options",
    "patch",
    "post",
    "put",
    "registry",
    "request",
    "session",
    "status_codes",
    "structures",
    "utils",
]
