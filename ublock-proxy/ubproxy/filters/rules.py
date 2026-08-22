"""Rule objects and the request description they are matched against."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Pattern
from urllib.parse import urlsplit

from ..domains import host_matches, registrable_domain, same_site

#: Request types understood by the engine (uBlock Origin naming).
REQUEST_TYPES = frozenset(
    {
        "document",
        "subdocument",
        "script",
        "stylesheet",
        "image",
        "media",
        "font",
        "xmlhttprequest",
        "websocket",
        "ping",
        "object",
        "other",
    }
)

#: Aliases accepted in filter options.
TYPE_ALIASES = {
    "doc": "document",
    "frame": "subdocument",
    "css": "stylesheet",
    "xhr": "xmlhttprequest",
    "beacon": "ping",
    "object-subrequest": "object",
}

TOKEN_RE = re.compile(r"[0-9a-z%]{2,}")

#: Tokens too common to be useful as an index key.
BAD_TOKENS = frozenset(
    {
        "http", "https", "www", "com", "net", "org", "html", "htm", "php",
        "js", "css", "img", "images", "static", "assets", "cdn", "api",
        "index", "the", "and", "for",
    }
)


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text)


class Request:
    """One outgoing request, as seen by the filtering engine."""

    __slots__ = (
        "url",
        "lowered",
        "hostname",
        "document_hostname",
        "type",
        "method",
        "_third_party",
        "_tokens",
    )

    def __init__(
        self,
        url: str,
        request_type: str = "other",
        document_hostname: str = "",
        method: str = "GET",
        hostname: Optional[str] = None,
        third_party: Optional[bool] = None,
    ) -> None:
        self.url = url
        self.lowered = url.lower()
        self.hostname = (hostname or urlsplit(url).hostname or "").lower()
        self.document_hostname = (document_hostname or "").lower()
        self.type = request_type if request_type in REQUEST_TYPES else "other"
        self.method = method
        self._third_party: Optional[bool] = third_party
        self._tokens: Optional[list[str]] = None

    @property
    def third_party(self) -> bool:
        if self._third_party is None:
            doc = self.document_hostname
            self._third_party = bool(doc) and not same_site(self.hostname, doc)
        return self._third_party

    @property
    def tokens(self) -> list[str]:
        if self._tokens is None:
            self._tokens = tokenize(self.lowered)
        return self._tokens

    @property
    def domain(self) -> str:
        return registrable_domain(self.hostname)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Request {self.type} {self.url!r} doc={self.document_hostname!r}>"


@dataclass(slots=True)
class NetworkRule:
    """A ``||ads.example.com^$script,third-party`` style rule.

    The pattern is only turned into a regular expression the first time it is
    actually needed: on a 100k-rule list most rules are plain ``||host^``
    filters answered by :attr:`hostname_anchor`, and compiling every pattern up
    front costs far more than the whole rest of the load.
    """

    raw: str
    pattern: str
    is_exception: bool = False
    important: bool = False
    match_case: bool = False
    third_party: Optional[bool] = None
    types: frozenset[str] = frozenset()
    excluded_types: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()
    excluded_domains: frozenset[str] = frozenset()
    denyallow: frozenset[str] = frozenset()
    hostname_anchor: str = ""
    #: Literal substrings guaranteed to appear in a matching URL; the engine
    #: indexes each rule under the rarest of them.
    candidate_tokens: tuple[str, ...] = ()
    token: str = ""
    _regex: Optional[Pattern[str]] = None

    @property
    def regex(self) -> Pattern[str]:
        if self._regex is None:
            from .parser import compile_pattern

            self._regex = compile_pattern(self.pattern, self.match_case)
        return self._regex

    def matches(self, request: Request) -> bool:
        if self.types and request.type not in self.types:
            return False
        if self.excluded_types and request.type in self.excluded_types:
            return False
        if self.third_party is not None and self.third_party != request.third_party:
            return False
        if self.domains or self.excluded_domains:
            doc = request.document_hostname or request.hostname
            if self.excluded_domains and any(
                host_matches(doc, d) for d in self.excluded_domains
            ):
                return False
            if self.domains and not any(host_matches(doc, d) for d in self.domains):
                return False
        if self.denyallow and any(
            host_matches(request.hostname, d) for d in self.denyallow
        ):
            return False
        if self.hostname_anchor:
            # Fast path: plain ``||host^`` rules need no regex at all.
            if not host_matches(request.hostname, self.hostname_anchor):
                return False
            return True
        target = request.url if self.match_case else request.lowered
        return self.regex.search(target) is not None


@dataclass(slots=True)
class CosmeticRule:
    """``example.com##.ad-banner`` — element hiding."""

    selector: str
    domains: frozenset[str] = frozenset()
    excluded_domains: frozenset[str] = frozenset()
    is_exception: bool = False

    @property
    def is_generic(self) -> bool:
        return not self.domains

    def applies_to(self, hostname: str) -> bool:
        if self.excluded_domains and any(
            host_matches(hostname, d) for d in self.excluded_domains
        ):
            return False
        if not self.domains:
            return True
        return any(host_matches(hostname, d) for d in self.domains)


@dataclass(slots=True)
class ParseStats:
    """What happened while loading the lists."""

    network: int = 0
    cosmetic: int = 0
    comments: int = 0
    unsupported: int = 0
    badfilters: int = 0
    unsupported_samples: list[str] = field(default_factory=list)

    def note_unsupported(self, line: str) -> None:
        self.unsupported += 1
        if len(self.unsupported_samples) < 20:
            self.unsupported_samples.append(line)
