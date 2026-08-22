"""Responses returned in place of blocked content."""

from __future__ import annotations

from html import escape

# 1x1 transparent GIF.
_PIXEL = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04"
    b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D"
    b"\x01\x00;"
)

_PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Bloqué par ubproxy</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;background:#f6f7f9;color:#22262b;
      display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
 main{{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:28px 32px;max-width:34rem}}
 h1{{font-size:18px;margin:0 0 8px}}
 code{{background:#f0f2f5;border-radius:4px;padding:1px 5px;word-break:break-all}}
 p{{margin:8px 0 0;color:#5b6270}}
</style></head>
<body><main>
<h1>Requête bloquée</h1>
<p><code>{url}</code></p>
<p>Règle&nbsp;: <code>{rule}</code></p>
</main></body></html>
"""


def _response(status: int, phrase: str, content_type: str, body: bytes, rule: str) -> bytes:
    head = (
        f"HTTP/1.1 {status} {phrase}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-Ubproxy-Blocked: {rule[:180]}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("latin-1", "replace")
    return head + body


def blocked_response(request_type: str, url: str, rule: str) -> bytes:
    """Build the reply for a blocked request, shaped after its type.

    Empty stand-ins (a pixel, an empty stylesheet or script) break far fewer
    pages than an error would, which is what uBlock Origin's ``noop``
    redirections do as well.
    """
    if request_type == "image":
        return _response(200, "OK", "image/gif", _PIXEL, rule)
    if request_type == "stylesheet":
        return _response(200, "OK", "text/css", b"", rule)
    if request_type == "script":
        return _response(200, "OK", "application/javascript", b"", rule)
    if request_type in ("document", "subdocument"):
        body = _PAGE.format(url=escape(url[:300]), rule=escape(rule[:200])).encode("utf-8")
        return _response(403, "Forbidden", "text/html; charset=utf-8", body, rule)
    return _response(204, "No Content", "text/plain", b"", rule)


def bad_gateway(detail: str) -> bytes:
    body = f"ubproxy: {detail}".encode("utf-8", "replace")
    return _response(502, "Bad Gateway", "text/plain; charset=utf-8", body, "-")
