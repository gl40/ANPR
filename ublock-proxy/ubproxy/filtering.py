"""Glue between the filter engine and the proxy: typing, decisions, cosmetics."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from .config import Config
from .domains import host_matches
from .filters.engine import Decision, FilterEngine
from .filters.lists import load_source
from .filters.rules import Request
from .net.http1 import Headers

log = logging.getLogger("ubproxy.filtering")

#: Sec-Fetch-Dest -> uBlock request type.
_FETCH_DEST = {
    "document": "document",
    "iframe": "subdocument",
    "frame": "subdocument",
    "script": "script",
    "worker": "script",
    "sharedworker": "script",
    "serviceworker": "script",
    "style": "stylesheet",
    "image": "image",
    "font": "font",
    "audio": "media",
    "video": "media",
    "track": "media",
    "embed": "object",
    "object": "object",
    "manifest": "other",
    "report": "ping",
    "empty": "xmlhttprequest",
}

_EXTENSIONS = {
    "js": "script", "mjs": "script",
    "css": "stylesheet",
    "png": "image", "gif": "image", "jpg": "image", "jpeg": "image",
    "webp": "image", "svg": "image", "ico": "image", "bmp": "image", "avif": "image",
    "woff": "font", "woff2": "font", "ttf": "font", "otf": "font", "eot": "font",
    "mp4": "media", "webm": "media", "mp3": "media", "ogg": "media", "m4a": "media",
    "m3u8": "media", "ts": "media",
    "json": "xmlhttprequest",
    "html": "document", "htm": "document",
    "swf": "object",
}

_EXT_RE = re.compile(r"\.([a-z0-9]{1,5})(?:$|[?#])", re.IGNORECASE)


def infer_request_type(method: str, url: str, headers: Headers) -> str:
    """Best-effort request type, the way a browser extension would know it."""
    dest = (headers.get("Sec-Fetch-Dest") or "").strip().lower()
    if dest in _FETCH_DEST:
        return _FETCH_DEST[dest]

    upgrade = (headers.get("Upgrade") or "").lower()
    if "websocket" in upgrade:
        return "websocket"
    if (headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return "xmlhttprequest"
    if method in ("POST", "PUT", "PATCH", "DELETE") and "Content-Type" in headers:
        return "xmlhttprequest"

    accept = (headers.get("Accept") or "").lower()
    if accept.startswith("text/html") or "application/xhtml" in accept:
        return "document"
    if accept.startswith("text/css"):
        return "stylesheet"
    if accept.startswith("image/"):
        return "image"
    if accept.startswith("font/") or "font/woff" in accept:
        return "font"
    if accept.startswith("audio/") or accept.startswith("video/"):
        return "media"
    if "javascript" in accept:
        return "script"

    path = urlsplit(url).path
    match = _EXT_RE.search(path)
    if match:
        return _EXTENSIONS.get(match.group(1).lower(), "other")
    return "other"


def document_hostname(headers: Headers, request_type: str, hostname: str) -> str:
    """The hostname of the page the request belongs to (for $third-party)."""
    referer = headers.get("Referer") or headers.get("Origin") or ""
    if referer:
        host = urlsplit(referer).hostname
        if host:
            return host.lower()
    if request_type == "document":
        return hostname
    return ""


@dataclass(slots=True)
class Verdict:
    blocked: bool
    rule: str = ""
    request_type: str = "other"


class Filtering:
    """Owns the engine, the allowlist and the cosmetic CSS cache."""

    def __init__(self, config: Config, engine: Optional[FilterEngine] = None) -> None:
        self.config = config
        self.engine = engine or FilterEngine()
        self._cosmetic_cache: dict[str, bytes] = {}

    # ------------------------------------------------------------------ load

    def load_lists(self, force_refresh: bool = False) -> None:
        for source in self.config.lists:
            text, label = load_source(
                source, self.config.cache_dir, self.config.list_refresh_hours, force_refresh
            )
            if text:
                before = self.engine.stats.network
                self.engine.load_text(text, label)
                log.info(
                    "loaded %s (+%d network rules)",
                    label,
                    self.engine.stats.network - before,
                )
        if self.config.extra_rules:
            self.engine.load_text("\n".join(self.config.extra_rules), "<config>")
        self.engine.seal()
        self._cosmetic_cache.clear()
        log.info("filter engine ready: %s", self.engine.summary())

    # -------------------------------------------------------------- decisions

    def is_allowlisted(self, hostname: str) -> bool:
        hostname = (hostname or "").lower()
        for entry in self.config.allow_hosts:
            entry = entry.lower().lstrip("*.")
            if host_matches(hostname, entry):
                return True
        return False

    def check(self, url: str, method: str, headers: Headers, hostname: str) -> Verdict:
        request_type = infer_request_type(method, url, headers)
        if self.is_allowlisted(hostname):
            return Verdict(False, "allowlist", request_type)
        doc_host = document_hostname(headers, request_type, hostname)
        if doc_host and self.is_allowlisted(doc_host):
            return Verdict(False, "allowlist (page)", request_type)
        request = Request(url, request_type, doc_host, method, hostname=hostname)
        decision: Decision = self.engine.match(request)
        return Verdict(decision.blocked, decision.reason, request_type)

    def check_host(self, hostname: str, port: int = 443) -> Verdict:
        """Hostname-only verdict, used for HTTPS that is not decrypted.

        Without the URL the only rules that can fire are the type-agnostic
        ones, which is exactly what we want: ``||tracker.example^`` blocks the
        whole host, ``||example.com/ads.js$script`` does not.  The connection
        is assumed third-party since the page it belongs to is unknown.
        """
        if self.is_allowlisted(hostname):
            return Verdict(False, "allowlist", "other")
        url = f"https://{hostname}/" if port == 443 else f"https://{hostname}:{port}/"
        request = Request(url, "other", "", "CONNECT", hostname=hostname, third_party=True)
        decision = self.engine.match(request)
        return Verdict(decision.blocked, decision.reason, "other")

    # --------------------------------------------------------------- cosmetic

    def cosmetic_style(self, hostname: str) -> bytes:
        """``<style>`` block hiding the ad slots declared for *hostname*."""
        if not self.config.cosmetic_filtering:
            return b""
        cached = self._cosmetic_cache.get(hostname)
        if cached is not None:
            return cached
        selectors = self.engine.cosmetic_selectors(
            hostname, include_generic=self.config.generic_cosmetic_filtering
        )
        if not selectors:
            style = b""
        else:
            # Long selector lists are chunked: a single overlong rule is more
            # likely to trip a browser's parser limits.
            chunks = [selectors[i : i + 200] for i in range(0, len(selectors), 200)]
            body = "\n".join(
                ",".join(chunk) + "{display:none!important}" for chunk in chunks
            )
            style = (
                b"<style type=\"text/css\" id=\"ubproxy-cosmetic\">" + body.encode("utf-8") + b"</style>"
            )
        self._cosmetic_cache[hostname] = style
        return style
