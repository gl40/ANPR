"""Local certificate authority and TLS interception plumbing.

Only used when ``mitm = true``: it is what allows filtering HTTPS requests by
full URL (and injecting cosmetic CSS) instead of by SNI hostname alone.  The
generated CA certificate has to be trusted by the client devices.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import os
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("ubproxy.mitm")

LEAF_VALIDITY_DAYS = 397  # the maximum modern clients accept
CA_VALIDITY_DAYS = 3650


class HostContext(ssl.SSLContext):
    """An ``SSLContext`` that remembers which hostname it was minted for.

    Server-side sockets do not expose the SNI after the handshake, so the
    hostname is carried on the context swapped in by ``sni_callback``.
    """

    host: str = ""


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def generate_ca(cert_path: Path, key_path: Path, common_name: str = "ubproxy local CA") -> None:
    """Create a fresh CA key pair at the given paths."""
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ubproxy"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(_pem(cert))
    key_path.write_bytes(_key_pem(key))
    os.chmod(key_path, 0o600)
    log.info("generated CA certificate at %s", cert_path)


def _expiry(cert: x509.Certificate) -> datetime.datetime:
    """``not_valid_after`` as an aware datetime, across cryptography versions."""
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


@dataclass(slots=True)
class _Leaf:
    cert_path: str
    key_path: str


class CertificateAuthority:
    """Signs (and caches) short-lived leaf certificates for intercepted hosts."""

    def __init__(self, cert_path: Path, key_path: Path, cache_dir: Path) -> None:
        if not cert_path.exists() or not key_path.exists():
            generate_ca(cert_path, key_path)
        self.cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        self.cert_path = cert_path
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # One key shared by every leaf: signing then costs ~1 ms instead of the
        # ~100 ms an RSA key generation would take per host.  It is kept on
        # disk so that certificates cached by a previous run stay usable.
        self._leaf_key_path = self.cache_dir / "leaf.key"
        self._leaf_key = self._load_or_create_leaf_key()
        self._contexts: dict[str, HostContext] = {}
        self._roots: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ certs

    def _load_or_create_leaf_key(self) -> rsa.RSAPrivateKey:
        if self._leaf_key_path.exists():
            try:
                key = serialization.load_pem_private_key(
                    self._leaf_key_path.read_bytes(), password=None
                )
                if isinstance(key, rsa.RSAPrivateKey):
                    return key
            except (ValueError, TypeError, OSError):
                log.warning("unusable leaf key at %s, regenerating", self._leaf_key_path)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._leaf_key_path.write_bytes(_key_pem(key))
        os.chmod(self._leaf_key_path, 0o600)
        return key

    def _cached_certificate_is_usable(self, cert: x509.Certificate) -> bool:
        """A cached leaf is only good for our current CA *and* leaf key."""
        if _expiry(cert) <= datetime.datetime.now(datetime.timezone.utc):
            return False
        if cert.public_key().public_numbers() != self._leaf_key.public_key().public_numbers():
            return False
        try:
            # Same CA name is not enough: a regenerated authority reuses it.
            self.cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception:
            return False
        return True

    def _issue(self, host: str) -> _Leaf:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)[:96]
        cert_file = self.cache_dir / f"{safe}.crt"
        if cert_file.exists():
            try:
                existing = x509.load_pem_x509_certificate(cert_file.read_bytes())
                if self._cached_certificate_is_usable(existing):
                    return _Leaf(str(cert_file), str(self._leaf_key_path))
            except (ValueError, OSError):
                pass

        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            alt_name: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            alt_name = x509.DNSName(host)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.cert.subject)
            .public_key(self._leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=LEAF_VALIDITY_DAYS))
            .add_extension(x509.SubjectAlternativeName([alt_name]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        cert = builder.sign(self.key, hashes.SHA256())
        chain = _pem(cert) + _pem(self.cert)
        cert_file.write_bytes(chain)
        return _Leaf(str(cert_file), str(self._leaf_key_path))

    def context_for(self, host: str) -> HostContext:
        host = (host or "").lower().strip(".") or "unknown.invalid"
        with self._lock:
            cached = self._contexts.get(host)
            if cached is not None:
                return cached
            leaf = self._issue(host)
            context = HostContext(ssl.PROTOCOL_TLS_SERVER)
            context.host = host
            context.load_cert_chain(leaf.cert_path, leaf.key_path)
            context.set_alpn_protocols(["http/1.1"])
            self._contexts[host] = context
            return context

    def server_context(self, default_host: str = "ubproxy.invalid") -> ssl.SSLContext:
        """Listener context that swaps in a per-SNI certificate.

        Clients connecting to a bare IP send no SNI at all, so the context is
        cached per *default_host*: the fallback certificate is then the one
        matching the address the client actually dialled.
        """
        default_host = (default_host or "ubproxy.invalid").lower().strip(".")
        with self._lock:
            cached = self._roots.get(default_host)
        if cached is not None:
            return cached
        leaf = self._issue(default_host)
        root = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        root.load_cert_chain(leaf.cert_path, leaf.key_path)
        root.set_alpn_protocols(["http/1.1"])

        def sni_callback(sslobj: ssl.SSLObject, server_name: Optional[str], _ctx) -> None:
            try:
                sslobj.context = self.context_for(server_name or default_host)
            except Exception:  # pragma: no cover - never fail the handshake here
                log.exception("could not mint a certificate for %r", server_name)

        root.sni_callback = sni_callback
        with self._lock:
            self._roots[default_host] = root
        return root


def upstream_context(verify: bool = True) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    return context


@dataclass(slots=True)
class TLSSession:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    hostname: str
    _pumps: tuple[asyncio.Task, asyncio.Task]
    _sockets: tuple[socket.socket, socket.socket]

    async def close(self, drain_timeout: float = 5.0) -> None:
        """Shut the session down without truncating the last response.

        Bytes written by the TLS transport are still travelling through the
        socketpair, so the writer is closed first and the pump feeding the
        client is given a chance to flush before anything is cancelled.
        """
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), drain_timeout)
        except (Exception, asyncio.CancelledError):
            pass
        try:
            await asyncio.wait_for(asyncio.shield(self._pumps[1]), drain_timeout)
        except (Exception, asyncio.CancelledError):
            pass
        for task in self._pumps:
            task.cancel()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass


async def wrap_server_tls(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    context: ssl.SSLContext,
    initial: bytes,
    handshake_timeout: float = 15.0,
) -> TLSSession:
    """Terminate TLS towards the client, replaying already-read bytes.

    The ClientHello has to be read before the handshake (to learn the SNI and
    decide what to do with the connection), so the raw stream is piped through
    a socketpair: asyncio drives the handshake on one end while we feed the
    buffered bytes plus the rest of the client stream into the other.
    """
    loop = asyncio.get_running_loop()
    tls_side, pump_side = socket.socketpair()
    tls_side.setblocking(False)
    pump_side.setblocking(False)

    async def client_to_tls() -> None:
        try:
            if initial:
                await loop.sock_sendall(pump_side, initial)
            while True:
                data = await client_reader.read(65536)
                if not data:
                    break
                await loop.sock_sendall(pump_side, data)
        except (OSError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                pump_side.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    async def tls_to_client() -> None:
        try:
            while True:
                data = await loop.sock_recv(pump_side, 65536)
                if not data:
                    break
                client_writer.write(data)
                await client_writer.drain()
        except (OSError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                client_writer.close()
            except Exception:
                pass

    pumps = (asyncio.create_task(client_to_tls()), asyncio.create_task(tls_to_client()))

    reader = asyncio.StreamReader(limit=1 << 20)
    protocol = asyncio.StreamReaderProtocol(reader)
    try:
        transport, _ = await asyncio.wait_for(
            loop.connect_accepted_socket(lambda: protocol, tls_side, ssl=context),
            timeout=handshake_timeout,
        )
    except (ssl.SSLError, OSError, asyncio.TimeoutError):
        for task in pumps:
            task.cancel()
        for sock in (tls_side, pump_side):
            try:
                sock.close()
            except OSError:
                pass
        raise

    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    ssl_object = transport.get_extra_info("ssl_object")
    hostname = getattr(getattr(ssl_object, "context", None), "host", "") or ""
    return TLSSession(reader, writer, hostname, pumps, (tls_side, pump_side))
