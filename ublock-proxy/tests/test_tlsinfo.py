import ssl

import pytest

from ubproxy.net.tlsinfo import NeedMoreData, NotTLS, parse_client_hello


def real_client_hello(hostname="www.example.com", alpn=None):
    """Grab a genuine ClientHello out of OpenSSL through a memory BIO."""
    context = ssl.create_default_context()
    if alpn:
        context.set_alpn_protocols(alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    sslobj = context.wrap_bio(incoming, outgoing, server_hostname=hostname)
    with pytest.raises(ssl.SSLWantReadError):
        sslobj.do_handshake()
    return outgoing.read()


def test_sni_from_real_client_hello():
    hello = parse_client_hello(real_client_hello("shop.example.org"))
    assert hello.sni == "shop.example.org"


def test_alpn_is_reported():
    hello = parse_client_hello(real_client_hello("a.example", alpn=["h2", "http/1.1"]))
    assert "h2" in hello.alpn


def test_partial_hello_asks_for_more():
    data = real_client_hello()
    with pytest.raises(NeedMoreData):
        parse_client_hello(data[:20])
    with pytest.raises(NeedMoreData):
        parse_client_hello(data[:-5])


def test_plain_http_is_not_tls():
    with pytest.raises(NotTLS):
        parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


def test_no_sni():
    hello = parse_client_hello(real_client_hello("1.2.3.4"))
    assert hello.sni is None
