"""The proxy itself: transparent (iptables REDIRECT) and explicit modes."""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import logging
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from .. import blockpage, setuppage
from ..config import Config
from ..domains import host_matches
from ..filtering import Filtering
from ..inject import inject_style, is_html
from . import http1
from .mitm import CertificateAuthority, TLSSession, upstream_context, wrap_server_tls
from .origdst import original_destination
from .tlsinfo import NeedMoreData, NotTLS, parse_client_hello

log = logging.getLogger("ubproxy.proxy")
access_log = logging.getLogger("ubproxy.access")

MAX_CLIENT_HELLO = 16 * 1024


@dataclass(slots=True)
class Stats:
    connections: int = 0
    requests: int = 0
    blocked: int = 0
    tls_connections: int = 0
    tls_blocked: int = 0
    mitm_sessions: int = 0
    errors: int = 0

    def render(self) -> str:
        return (
            f"{self.connections} connections, {self.requests} requests "
            f"({self.blocked} blocked), {self.tls_connections} TLS "
            f"({self.tls_blocked} blocked, {self.mitm_sessions} decrypted), "
            f"{self.errors} errors"
        )


@dataclass(slots=True)
class ConnectionContext:
    """Everything the HTTP loop needs to know about one client connection."""

    scheme: str = "http"
    host: str = ""
    port: int = 80
    #: Fixed upstream endpoint for transparently redirected connections.
    destination: Optional[tuple[str, int]] = None
    upstream_tls: bool = False
    sni: str = ""
    peer: str = ""
    #: Address the client actually connected to, to recognise requests aimed
    #: at the proxy itself.
    local: Optional[tuple[str, int]] = None
    rewrite_html: bool = True
    _upstream: dict = field(default_factory=dict)


class Proxy:
    def __init__(self, config: Config, filtering: Filtering) -> None:
        self.config = config
        self.filtering = filtering
        self.stats = Stats()
        self.ca: Optional[CertificateAuthority] = None
        self._upstream_ssl = upstream_context(config.upstream_verify)
        self._servers: list[asyncio.base_events.Server] = []
        if config.mitm:
            self.ca = CertificateAuthority(
                Path(config.ca_cert), Path(config.ca_key), config.cert_dir
            )

    # --------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        http_server = await asyncio.start_server(
            self._handle_plain,
            self.config.listen_address,
            self.config.http_port,
            limit=1 << 20,
        )
        tls_server = await asyncio.start_server(
            self._handle_tls,
            self.config.listen_address,
            self.config.tls_port,
            limit=1 << 20,
        )
        self._servers = [http_server, tls_server]
        log.info(
            "listening on %s:%d (HTTP) and %s:%d (TLS)%s",
            self.config.listen_address,
            self.config.http_port,
            self.config.listen_address,
            self.config.tls_port,
            " with HTTPS interception" if self.config.mitm else " (SNI filtering only)",
        )

    async def serve_forever(self) -> None:
        await self.start()
        if self.config.stats_interval:
            asyncio.create_task(self._stats_loop())
        await asyncio.gather(*(server.serve_forever() for server in self._servers))

    async def _stats_loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.stats_interval)
            log.info("stats: %s", self.stats.render())

    async def close(self) -> None:
        for server in self._servers:
            server.close()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()

    def _is_direct_hit(self, request: http1.RequestHead, context: ConnectionContext) -> bool:
        """True when the client dialled the listener itself, unproxied.

        Redirected connections always carry an original destination, and a
        configured proxy client sends an absolute target or CONNECT — so an
        origin-form request with neither is somebody typing the proxy's address
        into a browser.
        """
        if (
            context.scheme != "http"
            or context.destination is not None
            or context.local is None
            or request.target.startswith("http://")
            or request.target.startswith("https://")
        ):
            return False
        authority = request.headers.get("Host") or ""
        host, _, port_text = authority.rpartition(":")
        if not port_text.isdigit():
            host, port_text = authority, "80"
        host = host.strip("[]").lower()
        local_host, local_port = context.local[0], context.local[1]
        if int(port_text) != local_port:
            return False
        return host == local_host or (
            host == "localhost" and local_host in ("127.0.0.1", "::1")
        )

    # ------------------------------------------------------------- entry points

    async def _handle_plain(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.stats.connections += 1
        peer = _peer_name(writer)
        destination = _destination(writer)
        local = writer.get_extra_info("sockname")
        context = ConnectionContext(
            scheme="http",
            host=destination[0] if destination else "",
            port=destination[1] if destination else 80,
            destination=destination,
            peer=peer,
            local=(local[0], local[1]) if local else None,
        )
        try:
            await self._serve_http(reader, writer, context)
        except (http1.HttpError, ConnectionError, asyncio.IncompleteReadError) as exc:
            log.debug("http connection from %s ended: %s", peer, exc)
        except asyncio.TimeoutError:
            log.debug("http connection from %s timed out", peer)
        except Exception:
            self.stats.errors += 1
            log.exception("unhandled error on http connection from %s", peer)
        finally:
            await _close(writer)

    async def _handle_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.stats.connections += 1
        self.stats.tls_connections += 1
        peer = _peer_name(writer)
        destination = _destination(writer)
        session: Optional[TLSSession] = None
        try:
            buffered, hello = await self._peek_client_hello(reader)
            if hello is None:
                log.debug("%s: not TLS on the TLS port", peer)
                return
            host = hello.sni or (destination[0] if destination else "")
            port = destination[1] if destination else 443
            if not host:
                log.debug("%s: no SNI and no original destination", peer)
                return

            verdict = self.filtering.check_host(host, port)
            if verdict.blocked:
                self.stats.tls_blocked += 1
                access_log.info("BLOCK tls  %s  [%s]", host, verdict.rule)
                return
            if self.config.log_allowed:
                access_log.debug("allow tls  %s", host)

            if self.ca is not None and not self._bypasses_mitm(host):
                session = await self._intercept(reader, writer, buffered, host, port, destination, peer)
                return
            await self._tunnel(reader, writer, buffered, host, port, destination)
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError) as exc:
            log.debug("tls connection from %s ended: %s", peer, exc)
        except asyncio.TimeoutError:
            log.debug("tls connection from %s timed out", peer)
        except Exception:
            self.stats.errors += 1
            log.exception("unhandled error on tls connection from %s", peer)
        finally:
            if session is not None:
                await session.close()
            await _close(writer)

    # ------------------------------------------------------------------- TLS

    async def _peek_client_hello(self, reader: asyncio.StreamReader):
        buffered = b""
        while len(buffered) < MAX_CLIENT_HELLO:
            chunk = await asyncio.wait_for(reader.read(4096), self.config.idle_timeout)
            if not chunk:
                break
            buffered += chunk
            try:
                return buffered, parse_client_hello(buffered)
            except NeedMoreData:
                continue
            except NotTLS:
                return buffered, None
        return buffered, None

    def _bypasses_mitm(self, host: str) -> bool:
        for pattern in self.config.mitm_bypass_hosts:
            pattern = pattern.lower()
            # ``*.apple.com`` is meant to cover ``apple.com`` itself too.
            if pattern.startswith("*.") and host_matches(host, pattern[2:]):
                return True
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    async def _intercept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        buffered: bytes,
        host: str,
        port: int,
        destination: Optional[tuple[str, int]],
        peer: str,
    ) -> Optional[TLSSession]:
        assert self.ca is not None
        try:
            session = await wrap_server_tls(
                reader, writer, self.ca.server_context(host), buffered
            )
        except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
            log.debug("TLS handshake with %s failed for %s: %s", peer, host, exc)
            return None
        self.stats.mitm_sessions += 1
        context = ConnectionContext(
            scheme="https",
            host=session.hostname or host,
            port=port,
            destination=destination,
            upstream_tls=True,
            sni=session.hostname or host,
            peer=peer,
        )
        try:
            await self._serve_http(session.reader, session.writer, context)
        except (http1.HttpError, ConnectionError, ssl.SSLError, asyncio.IncompleteReadError) as exc:
            log.debug("intercepted session with %s ended: %s", host, exc)
        except asyncio.TimeoutError:
            log.debug("intercepted session with %s timed out", host)
        return session

    async def _tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        buffered: bytes,
        host: str,
        port: int,
        destination: Optional[tuple[str, int]],
    ) -> None:
        """Blind byte relay for HTTPS we chose not to decrypt."""
        target = destination or (host, port)
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target[0], target[1]), self.config.connect_timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            log.debug("cannot reach %s:%s (%s)", target[0], target[1], exc)
            return
        try:
            if buffered:
                upstream_writer.write(buffered)
                await upstream_writer.drain()
            await _splice(reader, writer, upstream_reader, upstream_writer)
        finally:
            await _close(upstream_writer)

    # ------------------------------------------------------------------ HTTP

    async def _serve_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        context: ConnectionContext,
    ) -> None:
        upstream_key: Optional[tuple[str, int]] = None
        upstream_reader: Optional[asyncio.StreamReader] = None
        upstream_writer: Optional[asyncio.StreamWriter] = None

        try:
            while True:
                raw_head = await asyncio.wait_for(
                    http1.read_head(reader), self.config.idle_timeout
                )
                if raw_head is None:
                    return
                request = http1.parse_request(raw_head)
                self.stats.requests += 1

                if request.method == "CONNECT":
                    await self._handle_connect(reader, writer, request, context)
                    return

                if self._is_direct_hit(request, context):
                    # Someone opened the proxy's own port in a browser: answer
                    # locally instead of trying to relay the request to
                    # ourselves.
                    writer.write(
                        setuppage.handle(
                            request.target,
                            self.filtering.engine.rule_count,
                            self.config.mitm,
                            Path(self.config.ca_cert),
                        )
                    )
                    await writer.drain()
                    await http1.drain_body(reader, http1.request_framing(request))
                    if http1.connection_closes(request.headers, request.version):
                        return
                    continue

                url, host, port, path = _resolve_target(request, context)
                if not host:
                    writer.write(blockpage.bad_gateway("no Host header"))
                    await writer.drain()
                    return

                verdict = self.filtering.check(url, request.method, request.headers, host)
                body_framing = http1.request_framing(request)
                if verdict.blocked:
                    self.stats.blocked += 1
                    access_log.info(
                        "BLOCK %-14s %s  [%s]", verdict.request_type, _short(url), verdict.rule
                    )
                    await http1.drain_body(reader, body_framing)
                    writer.write(blockpage.blocked_response(verdict.request_type, url, verdict.rule))
                    await writer.drain()
                    if http1.connection_closes(request.headers, request.version):
                        return
                    continue
                if self.config.log_allowed:
                    access_log.debug("allow %-14s %s", verdict.request_type, _short(url))

                # (Re)connect upstream when the target changed, or when the
                # kept-alive connection was closed by the server meanwhile.
                if (
                    upstream_key != (host, port)
                    or upstream_writer is None
                    or upstream_writer.is_closing()
                    or (upstream_reader is not None and upstream_reader.at_eof())
                ):
                    if upstream_writer is not None:
                        await _close(upstream_writer)
                    try:
                        upstream_reader, upstream_writer = await self._connect_upstream(
                            context, host, port
                        )
                    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
                        log.debug("upstream %s:%d unreachable: %s", host, port, exc)
                        await http1.drain_body(reader, body_framing)
                        writer.write(blockpage.bad_gateway(f"cannot reach {host}:{port}"))
                        await writer.drain()
                        return
                    upstream_key = (host, port)

                keep_alive = await self._exchange(
                    reader,
                    writer,
                    upstream_reader,
                    upstream_writer,
                    request,
                    body_framing,
                    context,
                    host,
                    path,
                    verdict.request_type,
                )
                if not keep_alive:
                    return
        finally:
            if upstream_writer is not None:
                await _close(upstream_writer)

    async def _connect_upstream(self, context: ConnectionContext, host: str, port: int):
        target = context.destination or (host, port)
        if context.upstream_tls:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    target[0],
                    target[1],
                    ssl=self._upstream_ssl,
                    server_hostname=host,
                    limit=1 << 20,
                ),
                self.config.connect_timeout,
            )
        return await asyncio.wait_for(
            asyncio.open_connection(target[0], target[1], limit=1 << 20),
            self.config.connect_timeout,
        )

    async def _exchange(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        request: http1.RequestHead,
        body_framing: http1.Framing,
        context: ConnectionContext,
        host: str,
        path: str,
        request_type: str,
    ) -> bool:
        """Forward one request/response pair. Returns whether to keep going."""
        wants_upgrade = "upgrade" in (request.headers.get("Connection") or "").lower()
        rewrite = (
            self.config.cosmetic_filtering
            and context.rewrite_html
            and request_type in ("document", "subdocument")
        )

        outgoing = http1.Headers(list(request.headers))
        http1.strip_hop_by_hop(outgoing)
        outgoing.remove("Proxy-Connection")
        if rewrite:
            # Ask for an unencoded body so the CSS can be spliced in.
            outgoing.remove("Accept-Encoding")
        if not wants_upgrade:
            outgoing.set("Connection", "keep-alive")
        forwarded = http1.RequestHead(request.method, request.target, request.version, outgoing)
        upstream_writer.write(forwarded.serialize(path))
        await upstream_writer.drain()
        await http1.forward_body(reader, upstream_writer, body_framing)

        raw_response = await asyncio.wait_for(
            http1.read_head(upstream_reader), self.config.idle_timeout
        )
        if raw_response is None:
            writer.write(blockpage.bad_gateway("upstream closed before responding"))
            await writer.drain()
            return False
        response = http1.parse_response(raw_response)

        if response.status == 101:  # WebSocket / protocol upgrade
            writer.write(response.serialize())
            await writer.drain()
            await _splice(reader, writer, upstream_reader, upstream_writer)
            return False

        response_framing = http1.response_framing(response, request.method)
        if rewrite and is_html(response.headers.get("Content-Type")):
            handled = await self._rewrite_html(
                writer, upstream_reader, response, response_framing, context.sni or host
            )
            if handled:
                return not http1.connection_closes(response.headers, response.version) and \
                    not http1.connection_closes(request.headers, request.version)

        writer.write(response.serialize())
        await writer.drain()
        await http1.forward_body(upstream_reader, writer, response_framing)
        if response_framing.kind == "until_close":
            return False
        return not http1.connection_closes(response.headers, response.version) and \
            not http1.connection_closes(request.headers, request.version)

    async def _rewrite_html(
        self,
        writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        response: http1.ResponseHead,
        framing: http1.Framing,
        hostname: str,
    ) -> bool:
        """Buffer an HTML body and inject the cosmetic stylesheet into it."""
        style = self.filtering.cosmetic_style(hostname)
        if not style:
            return False
        encoding = (response.headers.get("Content-Encoding") or "").lower()
        if encoding and encoding != "identity":
            return False  # compressed despite our Accept-Encoding: leave it alone
        body = await http1.read_body(upstream_reader, framing, self.config.max_html_rewrite_bytes)
        if body is None:
            log.debug("html body from %s too large to rewrite", hostname)
            return False
        body = inject_style(body, style)
        response.headers.remove("Transfer-Encoding")
        response.headers.remove("Content-Length")
        response.headers.set("Content-Length", str(len(body)))
        writer.write(response.serialize())
        writer.write(body)
        await writer.drain()
        return True

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: http1.RequestHead,
        context: ConnectionContext,
    ) -> None:
        """Explicit-proxy CONNECT: tunnel, or decrypt when MITM is enabled."""
        host, _, port_text = request.target.rpartition(":")
        host = host.strip("[]").lower()
        try:
            port = int(port_text)
        except ValueError:
            host, port = request.target.lower(), 443

        verdict = self.filtering.check_host(host, port)
        if verdict.blocked:
            self.stats.blocked += 1
            self.stats.tls_blocked += 1
            access_log.info("BLOCK connect  %s:%d  [%s]", host, port, verdict.rule)
            writer.write(blockpage.blocked_response("document", f"https://{host}/", verdict.rule))
            await writer.drain()
            return

        if self.ca is not None and not self._bypasses_mitm(host):
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            session = None
            try:
                session = await wrap_server_tls(
                    reader, writer, self.ca.server_context(host), b""
                )
            except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
                log.debug("TLS handshake failed after CONNECT %s: %s", host, exc)
                return
            self.stats.mitm_sessions += 1
            inner = ConnectionContext(
                scheme="https",
                host=session.hostname or host,
                port=port,
                destination=None,
                upstream_tls=True,
                sni=session.hostname or host,
                peer=context.peer,
            )
            try:
                await self._serve_http(session.reader, session.writer, inner)
            except (http1.HttpError, ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
                pass
            finally:
                await session.close()
            return

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), self.config.connect_timeout
            )
        except (OSError, asyncio.TimeoutError):
            writer.write(blockpage.bad_gateway(f"cannot reach {host}:{port}"))
            await writer.drain()
            return
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        try:
            await _splice(reader, writer, upstream_reader, upstream_writer)
        finally:
            await _close(upstream_writer)


# --------------------------------------------------------------------- helpers


def _resolve_target(
    request: http1.RequestHead, context: ConnectionContext
) -> tuple[str, str, int, str]:
    """Return ``(absolute_url, host, port, origin_form_path)``."""
    target = request.target
    if target.startswith("http://") or target.startswith("https://"):
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        return target, host, port, path

    authority = request.headers.get("Host") or context.host
    host = authority
    port = context.port
    if authority.startswith("["):  # IPv6 literal
        close = authority.find("]")
        host = authority[1:close]
        if authority[close + 1 :].startswith(":"):
            port = int(authority[close + 2 :] or port)
    elif ":" in authority:
        name, _, port_text = authority.rpartition(":")
        if port_text.isdigit():
            host, port = name, int(port_text)
    host = host.lower()
    default_port = 443 if context.scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    url = f"{context.scheme}://{netloc}{target}"
    return url, host, port, target


def _destination(writer: asyncio.StreamWriter) -> Optional[tuple[str, int]]:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return None
    destination = original_destination(sock)
    if destination is None:
        return None
    local = writer.get_extra_info("sockname")
    if local and destination[0] == local[0] and destination[1] == local[1]:
        return None  # direct connection to the proxy, not a redirect
    return destination


def _peer_name(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if not peer:
        return "?"
    return f"{peer[0]}:{peer[1]}"


def _short(url: str, limit: int = 110) -> str:
    return url if len(url) <= limit else url[: limit - 1] + "…"


async def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        if not writer.is_closing():
            writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if writer.can_write_eof():
                writer.write_eof()


async def _splice(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(
        _pipe(client_reader, upstream_writer),
        _pipe(upstream_reader, client_writer),
        return_exceptions=True,
    )
