import asyncio

import pytest

from ubproxy.net import http1


def reader_from(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=1 << 20)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def test_parse_request():
    head = http1.parse_request(
        b"GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nX-A: 1\r\nx-a: 2\r\n\r\n"
    )
    assert head.method == "GET" and head.target == "/a?b=1"
    assert head.headers.get("host") == "example.com"
    assert head.headers.get_all("X-A") == ["1", "2"]
    assert head.serialize().startswith(b"GET /a?b=1 HTTP/1.1\r\n")
    assert head.serialize("/other").startswith(b"GET /other HTTP/1.1\r\n")


def test_parse_response_and_framing():
    response = http1.parse_response(b"HTTP/1.1 204 No Content\r\nX: y\r\n\r\n")
    assert response.status == 204
    assert http1.response_framing(response, "GET").kind == "none"

    chunked = http1.parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
    assert http1.response_framing(chunked, "GET").kind == "chunked"

    sized = http1.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
    framing = http1.response_framing(sized, "GET")
    assert (framing.kind, framing.length) == ("length", 5)
    assert http1.response_framing(sized, "HEAD").kind == "none"

    unbounded = http1.parse_response(b"HTTP/1.1 200 OK\r\n\r\n")
    assert http1.response_framing(unbounded, "GET").kind == "until_close"


def test_malformed_head():
    with pytest.raises(http1.HttpError):
        http1.parse_request(b"GARBAGE\r\n\r\n")
    with pytest.raises(http1.HttpError):
        http1.parse_request(b"GET / HTTP/1.1\r\nbroken\r\n\r\n")


def test_read_body_length():
    async def run():
        reader = reader_from(b"hello")
        return await http1.read_body(reader, http1.Framing("length", 5), 1024)

    assert asyncio.run(run()) == b"hello"


def test_read_body_chunked():
    async def run():
        reader = reader_from(b"5\r\nhello\r\n3\r\n123\r\n0\r\n\r\n")
        return await http1.read_body(reader, http1.Framing("chunked"), 1024)

    assert asyncio.run(run()) == b"hello123"


def test_read_body_limit_returns_none():
    async def run():
        reader = reader_from(b"x" * 100)
        return await http1.read_body(reader, http1.Framing("length", 100), 10)

    assert asyncio.run(run()) is None


def test_forward_body_preserves_chunking():
    async def run():
        reader = reader_from(b"4\r\nabcd\r\n0\r\n\r\n")
        out = asyncio.StreamReader()

        class W:
            def write(self, data):
                out.feed_data(data)

            async def drain(self):
                pass

        await http1.forward_body(reader, W(), http1.Framing("chunked"))
        out.feed_eof()
        return await out.read()

    assert asyncio.run(run()) == b"4\r\nabcd\r\n0\r\n\r\n"


def test_connection_closes():
    headers = http1.Headers([("Connection", "close")])
    assert http1.connection_closes(headers, "HTTP/1.1")
    assert not http1.connection_closes(http1.Headers(), "HTTP/1.1")
    assert http1.connection_closes(http1.Headers(), "HTTP/1.0")
    assert not http1.connection_closes(
        http1.Headers([("Connection", "keep-alive")]), "HTTP/1.0"
    )


def test_strip_hop_by_hop_keeps_framing_headers():
    headers = http1.Headers(
        [("Connection", "keep-alive, X-Custom"), ("Keep-Alive", "5"),
         ("X-Custom", "1"), ("Transfer-Encoding", "chunked")]
    )
    http1.strip_hop_by_hop(headers)
    assert headers.get("Keep-Alive") is None
    assert headers.get("X-Custom") is None
    assert headers.get("Transfer-Encoding") == "chunked"
