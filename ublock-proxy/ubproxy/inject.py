"""Injection of the cosmetic ``<style>`` block into HTML responses."""

from __future__ import annotations

import re

_HEAD_END = re.compile(rb"</head\s*>", re.IGNORECASE)
_HEAD_START = re.compile(rb"<head[^>]*>", re.IGNORECASE)
_BODY_START = re.compile(rb"<body[^>]*>", re.IGNORECASE)


def inject_style(html: bytes, style: bytes) -> bytes:
    """Insert *style* as early as possible so slots never flash on screen."""
    if not style or not html:
        return html
    match = _HEAD_START.search(html, 0, 65536)
    if match:
        return html[: match.end()] + style + html[match.end() :]
    match = _HEAD_END.search(html, 0, 262144)
    if match:
        return html[: match.start()] + style + html[match.start() :]
    match = _BODY_START.search(html, 0, 262144)
    if match:
        return html[: match.end()] + style + html[match.end() :]
    return style + html


def is_html(content_type: str | None) -> bool:
    if not content_type:
        return False
    value = content_type.split(";", 1)[0].strip().lower()
    return value in ("text/html", "application/xhtml+xml")
