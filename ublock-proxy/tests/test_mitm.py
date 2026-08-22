"""Certificate authority behaviour."""

import ssl
import tempfile
from pathlib import Path

from cryptography import x509

from ubproxy.net.mitm import CertificateAuthority, generate_ca


def test_leaf_key_survives_a_restart():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        first = CertificateAuthority(root / "ca.crt", root / "ca.key", root / "certs")
        first.context_for("example.com")
        cached = (root / "certs" / "example.com.crt").read_bytes()

        second = CertificateAuthority(root / "ca.crt", root / "ca.key", root / "certs")
        second.context_for("example.com")
        assert (root / "certs" / "example.com.crt").read_bytes() == cached
        # A context built from the cached file must still load, i.e. the leaf
        # key on disk still matches the certificate.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "certs" / "example.com.crt", root / "certs" / "leaf.key")


def test_cached_certificate_from_another_ca_is_reissued():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        first = CertificateAuthority(root / "ca.crt", root / "ca.key", root / "certs")
        first.context_for("example.com")
        stale = (root / "certs" / "example.com.crt").read_bytes()

        generate_ca(root / "ca.crt", root / "ca.key")  # brand new authority
        second = CertificateAuthority(root / "ca.crt", root / "ca.key", root / "certs")
        second.context_for("example.com")
        fresh = (root / "certs" / "example.com.crt").read_bytes()
        assert fresh != stale
        assert x509.load_pem_x509_certificate(fresh).issuer == second.cert.subject


def test_certificate_carries_the_hostname():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ca = CertificateAuthority(root / "ca.crt", root / "ca.key", root / "certs")
        context = ca.context_for("shop.example.org")
        assert context.host == "shop.example.org"
        cert = x509.load_pem_x509_certificate((root / "certs" / "shop.example.org.crt").read_bytes())
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert names.get_values_for_type(x509.DNSName) == ["shop.example.org"]


def test_ip_certificates_use_an_ip_san():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ca = CertificateAuthority(root / "ca.crt", root / "ca.key", root / "certs")
        ca.context_for("10.1.2.3")
        cert = x509.load_pem_x509_certificate((root / "certs" / "10.1.2.3.crt").read_bytes())
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert str(names.get_values_for_type(x509.IPAddress)[0]) == "10.1.2.3"
