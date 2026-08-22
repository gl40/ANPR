"""Minimal TLS ClientHello parser — just enough to read the SNI and ALPN."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

HANDSHAKE = 0x16
CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010


class NeedMoreData(Exception):
    """The buffer does not hold a complete ClientHello yet."""


class NotTLS(Exception):
    """The buffer is not a TLS handshake record."""


@dataclass(slots=True)
class ClientHello:
    sni: Optional[str] = None
    alpn: list[str] = field(default_factory=list)
    version: int = 0


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def need(self, count: int) -> None:
        if self.pos + count > len(self.data):
            raise NeedMoreData

    def u8(self) -> int:
        self.need(1)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self) -> int:
        self.need(2)
        value = int.from_bytes(self.data[self.pos : self.pos + 2], "big")
        self.pos += 2
        return value

    def u24(self) -> int:
        self.need(3)
        value = int.from_bytes(self.data[self.pos : self.pos + 3], "big")
        self.pos += 3
        return value

    def blob(self, count: int) -> bytes:
        self.need(count)
        value = self.data[self.pos : self.pos + count]
        self.pos += count
        return value


def _handshake_bytes(data: bytes) -> bytes:
    """Concatenate the handshake payload of all complete TLS records."""
    if not data:
        raise NeedMoreData
    if data[0] != HANDSHAKE:
        raise NotTLS(f"first byte {data[0]:#x} is not a handshake record")
    if len(data) < 5:
        raise NeedMoreData
    out = bytearray()
    pos = 0
    while pos + 5 <= len(data):
        if data[pos] != HANDSHAKE:
            break
        length = int.from_bytes(data[pos + 3 : pos + 5], "big")
        chunk = data[pos + 5 : pos + 5 + length]
        if len(chunk) < length:
            raise NeedMoreData
        out += chunk
        pos += 5 + length
    if not out:
        raise NeedMoreData
    return bytes(out)


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse a (possibly multi-record) ClientHello.

    Raises :class:`NeedMoreData` when more bytes are required and
    :class:`NotTLS` when the peer is clearly not speaking TLS.
    """
    body = _handshake_bytes(data)
    reader = _Reader(body)
    if reader.u8() != CLIENT_HELLO:
        raise NotTLS("handshake message is not a ClientHello")
    length = reader.u24()
    if len(body) - reader.pos < length:
        raise NeedMoreData

    hello = ClientHello()
    hello.version = reader.u16()
    reader.blob(32)  # random
    reader.blob(reader.u8())  # session id
    reader.blob(reader.u16())  # cipher suites
    reader.blob(reader.u8())  # compression methods

    try:
        extensions_length = reader.u16()
    except NeedMoreData:
        return hello  # no extensions at all: legal, just no SNI
    end = reader.pos + extensions_length
    while reader.pos < end:
        ext_type = reader.u16()
        ext_len = reader.u16()
        payload = _Reader(reader.blob(ext_len))
        if ext_type == EXT_SERVER_NAME:
            list_len = payload.u16()
            list_end = payload.pos + list_len
            while payload.pos < list_end:
                name_type = payload.u8()
                name = payload.blob(payload.u16())
                if name_type == 0:
                    hello.sni = name.decode("idna", errors="replace") if _is_idna(name) \
                        else name.decode("ascii", errors="replace")
                    hello.sni = hello.sni.lower().rstrip(".")
                    break
        elif ext_type == EXT_ALPN:
            payload.u16()  # protocol list length
            while payload.pos < len(payload.data):
                hello.alpn.append(payload.blob(payload.u8()).decode("ascii", "replace"))
    return hello


def _is_idna(name: bytes) -> bool:
    return name.startswith(b"xn--") or b".xn--" in name
