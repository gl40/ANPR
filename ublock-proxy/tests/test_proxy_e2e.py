"""End-to-end tests: a real client talking to the proxy talking to an origin."""

import asyncio
import ssl
import tempfile
from pathlib import Path

import pytest

from ubproxy.config import Config
from ubproxy.filtering import Filtering
from ubproxy.net.proxy import Proxy

HTML = (
    b"<!doctype html><html><head><title>t</title></head>"
    b"<body><div class='ad-slot'>ad</div>hello</body></html>"
)


async def start_origin(ssl_context=None):
    """A tiny HTTP origin server; keeps the connection alive."""

    async def handle(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                target = head.split(b" ")[1].decode()
                if target.startswith("/ads/"):
                    body, ctype = b"AD", "image/png"
                elif target == "/chunked":
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n"
                        b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
                    )
                    await writer.drain()
                    continue
                else:
                    body, ctype = HTML, "text/html; charset=utf-8"
                writer.write(
                    f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, IndexError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_context)
    return server, server.sockets[0].getsockname()[1]


def make_config(tmp: Path, **overrides) -> Config:
    config = Config(
        lists=[],
        extra_rules=[
            "/ads/banner",
            "127.0.0.1##.ad-slot",
            "||blocked.example^",
        ],
        http_port=0,
        tls_port=0,
        state_dir=str(tmp),
        cosmetic_filtering=True,
        **overrides,
    )
    return config


async def start_proxy(config):
    filtering = Filtering(config)
    filtering.load_lists()
    proxy = Proxy(config, filtering)
    await proxy.start()
    http_port = proxy._servers[0].sockets[0].getsockname()[1]
    tls_port = proxy._servers[1].sockets[0].getsockname()[1]
    return proxy, http_port, tls_port


async def read_response(reader):
    head = await reader.readuntil(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":")[1])
    body = await reader.readexactly(length) if length else b""
    return head.decode("latin-1"), body


def test_http_block_allow_and_cosmetics():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            origin, origin_port = await start_origin()
            proxy, http_port, _ = await start_proxy(make_config(Path(tmp)))
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)

            # 1. allowed HTML document, cosmetic CSS injected
            writer.write(
                f"GET http://127.0.0.1:{origin_port}/index.html HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\n"
                "Accept: text/html\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert head.startswith("HTTP/1.1 200")
            assert b"ubproxy-cosmetic" in body
            assert b".ad-slot{display:none!important}" in body
            assert b"hello" in body

            # 2. blocked image on the same keep-alive connection
            writer.write(
                f"GET http://127.0.0.1:{origin_port}/ads/banner.png HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\n"
                "Accept: image/png\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert head.startswith("HTTP/1.1 200")
            assert "X-Ubproxy-Blocked" in head
            assert body.startswith(b"GIF89a")
            assert proxy.stats.blocked == 1

            # 3. the connection still works afterwards
            writer.write(
                f"GET http://127.0.0.1:{origin_port}/other HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert head.startswith("HTTP/1.1 200")

            writer.close()
            await proxy.close()
            origin.close()

    asyncio.run(asyncio.wait_for(run(), 30))


def test_chunked_response_is_relayed():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            origin, origin_port = await start_origin()
            proxy, http_port, _ = await start_proxy(make_config(Path(tmp)))
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
            writer.write(
                f"GET http://127.0.0.1:{origin_port}/chunked HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\n\r\n".encode()
            )
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            assert b"chunked" in head.lower()
            body = await reader.readuntil(b"0\r\n\r\n")
            assert b"abc" in body and b"def" in body
            writer.close()
            await proxy.close()
            origin.close()

    asyncio.run(asyncio.wait_for(run(), 30))


def test_connect_to_blocked_host_is_refused():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            proxy, http_port, _ = await start_proxy(make_config(Path(tmp)))
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
            writer.write(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            await writer.drain()
            head, _ = await read_response(reader)
            assert head.startswith("HTTP/1.1 403")
            writer.close()
            await proxy.close()

    asyncio.run(asyncio.wait_for(run(), 30))


def _origin_tls_context(tmp: Path):
    from ubproxy.net.mitm import generate_ca

    cert, key = tmp / "origin.crt", tmp / "origin.key"
    generate_ca(cert, key, common_name="127.0.0.1")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def test_mitm_filters_inside_https():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            origin, origin_port = await start_origin(_origin_tls_context(tmp_path))
            config = make_config(tmp_path, mitm=True, upstream_verify=False)
            proxy, http_port, _ = await start_proxy(config)

            client_context = ssl.create_default_context(cafile=config.ca_cert)
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
            writer.write(
                f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin_port}\r\n\r\n".encode()
            )
            await writer.drain()
            established = await reader.readuntil(b"\r\n\r\n")
            assert b"200" in established

            await writer.start_tls(client_context, server_hostname="127.0.0.1")

            writer.write(
                f"GET /ads/banner.png HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n"
                "Accept: image/png\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert "X-Ubproxy-Blocked" in head
            assert body.startswith(b"GIF89a")

            writer.write(
                f"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n"
                "Accept: text/html\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert head.startswith("HTTP/1.1 200")
            assert b"ubproxy-cosmetic" in body
            assert proxy.stats.mitm_sessions == 1

            writer.close()
            await proxy.close()
            origin.close()

    asyncio.run(asyncio.wait_for(run(), 60))


def test_sni_filtering_without_mitm():
    """A TLS connection to a blocked host is dropped before it is established."""

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            proxy, _, tls_port = await start_proxy(config)
            client_context = ssl.create_default_context()
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            with pytest.raises((ConnectionError, ssl.SSLError, EOFError, OSError)):
                await asyncio.open_connection(
                    "127.0.0.1", tls_port, ssl=client_context, server_hostname="blocked.example"
                )
            assert proxy.stats.tls_blocked == 1
            await proxy.close()

    asyncio.run(asyncio.wait_for(run(), 30))


def test_origin_form_request_like_a_redirected_client():
    """Transparent mode shape: origin-form target plus a Host header."""

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            origin, origin_port = await start_origin()
            proxy, http_port, _ = await start_proxy(make_config(Path(tmp)))
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
            writer.write(
                f"GET /ads/banner.png HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n"
                "Accept: image/png\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert "X-Ubproxy-Blocked" in head

            writer.write(
                f"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n"
                "Accept: text/html\r\n\r\n".encode()
            )
            await writer.drain()
            head, body = await read_response(reader)
            assert head.startswith("HTTP/1.1 200") and b"hello" in body

            writer.close()
            await proxy.close()
            origin.close()

    asyncio.run(asyncio.wait_for(run(), 30))


def test_unreachable_upstream_returns_502():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            proxy, http_port, _ = await start_proxy(make_config(Path(tmp)))
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
            writer.write(
                b"GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
            )
            await writer.drain()
            head, _ = await read_response(reader)
            assert head.startswith("HTTP/1.1 502")
            writer.close()
            await proxy.close()

    asyncio.run(asyncio.wait_for(run(), 30))


def test_mitm_bypass_covers_the_bare_domain():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp), mitm=True, mitm_bypass_hosts=["*.apple.com"])
            proxy, _, _ = await start_proxy(config)
            assert proxy._bypasses_mitm("apple.com")
            assert proxy._bypasses_mitm("gs.apple.com")
            assert not proxy._bypasses_mitm("notapple.com")
            await proxy.close()

    asyncio.run(asyncio.wait_for(run(), 30))
