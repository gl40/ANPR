"""HTTP/1.x message parsing and body framing over asyncio streams."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

MAX_HEAD_BYTES = 64 * 1024
MAX_CHUNK_LINE = 1024


class HttpError(Exception):
    """Malformed message; the connection must be dropped."""


class Headers:
    """Ordered, case-insensitive header collection that keeps the wire order."""

    __slots__ = ("_items",)

    def __init__(self, items: Optional[list[tuple[str, str]]] = None) -> None:
        self._items: list[tuple[str, str]] = list(items or [])

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        lowered = name.lower()
        for key, value in self._items:
            if key.lower() == lowered:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self._items if k.lower() == lowered]

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self._items.append((name, value))

    def add(self, name: str, value: str) -> None:
        self._items.append((name, value))

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self._items = [(k, v) for k, v in self._items if k.lower() != lowered]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get(name) is not None

    def __iter__(self):
        return iter(self._items)

    def serialize(self) -> bytes:
        return b"".join(
            f"{k}: {v}\r\n".encode("latin-1", "replace") for k, v in self._items
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Headers({self._items!r})"


@dataclass(slots=True)
class RequestHead:
    method: str
    target: str
    version: str
    headers: Headers = field(default_factory=Headers)

    def serialize(self, target: Optional[str] = None) -> bytes:
        line = f"{self.method} {target or self.target} {self.version}\r\n"
        return line.encode("latin-1", "replace") + self.headers.serialize() + b"\r\n"


@dataclass(slots=True)
class ResponseHead:
    version: str
    status: int
    phrase: str
    headers: Headers = field(default_factory=Headers)

    def serialize(self) -> bytes:
        line = f"{self.version} {self.status} {self.phrase}\r\n"
        return line.encode("latin-1", "replace") + self.headers.serialize() + b"\r\n"


@dataclass(slots=True)
class Framing:
    """How the body of a message is delimited."""

    kind: str  # "none" | "length" | "chunked" | "until_close"
    length: int = 0

    @property
    def has_body(self) -> bool:
        return self.kind != "none" and not (self.kind == "length" and self.length == 0)


NO_BODY = Framing("none")


async def read_head(reader: asyncio.StreamReader, limit: int = MAX_HEAD_BYTES) -> Optional[bytes]:
    """Read up to the blank line ending a message head. ``None`` at clean EOF."""
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        # Tolerate bare-LF heads from sloppy clients.
        if b"\n\n" in exc.partial:
            return exc.partial
        raise HttpError("connection closed mid-header") from exc
    except asyncio.LimitOverrunError as exc:
        raise HttpError("header block too large") from exc
    if len(head) > limit:
        raise HttpError("header block too large")
    return head


def _split_head(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    text = raw.decode("latin-1")
    lines = text.replace("\r\n", "\n").rstrip("\n").split("\n")
    if not lines or not lines[0]:
        raise HttpError("empty message head")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and headers:  # obsolete line folding
            key, value = headers[-1]
            headers[-1] = (key, value + " " + line.strip())
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise HttpError(f"malformed header line: {line!r}")
        headers.append((name.strip(), value.strip()))
    return lines[0], headers


def parse_request(raw: bytes) -> RequestHead:
    start, headers = _split_head(raw)
    parts = start.split()
    if len(parts) != 3:
        raise HttpError(f"malformed request line: {start!r}")
    method, target, version = parts
    if not version.startswith("HTTP/"):
        raise HttpError(f"unsupported protocol: {version!r}")
    return RequestHead(method.upper(), target, version, Headers(headers))


def parse_response(raw: bytes) -> ResponseHead:
    start, headers = _split_head(raw)
    parts = start.split(None, 2)
    if len(parts) < 2:
        raise HttpError(f"malformed status line: {start!r}")
    version, status = parts[0], parts[1]
    phrase = parts[2] if len(parts) > 2 else ""
    try:
        code = int(status)
    except ValueError as exc:
        raise HttpError(f"malformed status code: {status!r}") from exc
    return ResponseHead(version, code, phrase, Headers(headers))


def request_framing(head: RequestHead) -> Framing:
    encoding = (head.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in encoding:
        return Framing("chunked")
    length = head.headers.get("Content-Length")
    if length is not None:
        try:
            return Framing("length", int(length.split(",")[0].strip()))
        except ValueError as exc:
            raise HttpError(f"bad Content-Length: {length!r}") from exc
    return NO_BODY


def response_framing(head: ResponseHead, request_method: str) -> Framing:
    if request_method == "HEAD" or head.status in (204, 304) or 100 <= head.status < 200:
        return NO_BODY
    encoding = (head.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in encoding:
        return Framing("chunked")
    length = head.headers.get("Content-Length")
    if length is not None:
        try:
            return Framing("length", int(length.split(",")[0].strip()))
        except ValueError as exc:
            raise HttpError(f"bad Content-Length: {length!r}") from exc
    return Framing("until_close")


async def iter_body(reader: asyncio.StreamReader, framing: Framing) -> AsyncIterator[bytes]:
    """Yield decoded body bytes (chunked framing removed)."""
    if framing.kind == "none":
        return
    if framing.kind == "length":
        remaining = framing.length
        while remaining > 0:
            chunk = await reader.read(min(65536, remaining))
            if not chunk:
                raise HttpError("connection closed before the body was complete")
            remaining -= len(chunk)
            yield chunk
        return
    if framing.kind == "until_close":
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            yield chunk
        return
    # chunked
    while True:
        line = await reader.readline()
        if not line:
            raise HttpError("connection closed inside a chunked body")
        if len(line) > MAX_CHUNK_LINE:
            raise HttpError("chunk header too long")
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise HttpError(f"bad chunk size: {size_text!r}") from exc
        if size == 0:
            while True:  # trailers
                trailer = await reader.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    return
            return
        remaining = size
        while remaining > 0:
            chunk = await reader.read(min(65536, remaining))
            if not chunk:
                raise HttpError("connection closed inside a chunk")
            remaining -= len(chunk)
            yield chunk
        await reader.readexactly(2)  # trailing CRLF


async def forward_body(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, framing: Framing
) -> int:
    """Copy a body across, preserving chunked framing. Returns bytes copied."""
    total = 0
    if framing.kind == "chunked":
        async for chunk in iter_body(reader, framing):
            total += len(chunk)
            writer.write(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
            await writer.drain()
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        return total
    async for chunk in iter_body(reader, framing):
        total += len(chunk)
        writer.write(chunk)
        await writer.drain()
    return total


async def read_body(reader: asyncio.StreamReader, framing: Framing, limit: int) -> Optional[bytes]:
    """Read a whole body into memory, or ``None`` when it exceeds *limit*."""
    buffer = bytearray()
    async for chunk in iter_body(reader, framing):
        buffer += chunk
        if len(buffer) > limit:
            return None
    return bytes(buffer)


async def drain_body(reader: asyncio.StreamReader, framing: Framing) -> None:
    async for _ in iter_body(reader, framing):
        pass


def connection_closes(headers: Headers, version: str) -> bool:
    connection = (headers.get("Connection") or "").lower()
    if "close" in connection:
        return True
    if version == "HTTP/1.0" and "keep-alive" not in connection:
        return True
    return False


#: Headers that must not be forwarded between the two sides of the proxy.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def strip_hop_by_hop(headers: Headers) -> None:
    named = {
        token.strip().lower()
        for value in headers.get_all("Connection")
        for token in value.split(",")
        if token.strip()
    }
    for name in list(HOP_BY_HOP) + list(named):
        if name in ("transfer-encoding", "upgrade", "connection"):
            continue  # handled explicitly by the caller
        headers.remove(name)
