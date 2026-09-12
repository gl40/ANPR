"""Small self-serve page: what the proxy is doing, and the CA to install.

A client that opens the listening port directly in a browser (rather than
sending it proxied traffic) lands here.  On iOS in particular this is the only
practical way to get the certificate authority onto the device: Safari has to
download the ``.crt`` for the system to offer installing it as a profile.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Optional

CA_PATH = "/ubproxy-ca.crt"

_PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ubproxy</title>
<style>
 body{{font:16px/1.55 -apple-system,system-ui,sans-serif;background:#f6f7f9;
      color:#22262b;margin:0;padding:24px}}
 main{{background:#fff;border:1px solid #dfe3e8;border-radius:12px;
      padding:22px;max-width:38rem;margin:0 auto}}
 h1{{font-size:19px;margin:0 0 4px}}
 h2{{font-size:15px;margin:22px 0 6px}}
 p,li{{color:#4a515c;margin:6px 0}}
 .state{{font-weight:600;color:#22262b}}
 a.button{{display:inline-block;margin-top:10px;background:#2f6fed;color:#fff;
      text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600}}
 code{{background:#f0f2f5;border-radius:4px;padding:1px 5px}}
 ol{{padding-left:20px}}
</style></head>
<body><main>
<h1>ubproxy</h1>
<p>Le proxy fonctionne&nbsp;: <span class="state">{rules}</span>.</p>
<p>Filtrage HTTPS&nbsp;: <span class="state">{https_mode}</span>.</p>
{ca_section}
<h2>Vérifier que le filtrage s'applique</h2>
<p>Ouvrez une page web&nbsp;: les requêtes bloquées apparaissent dans le journal
du proxy (<code>ubproxy run --log-allowed</code> pour tout voir).</p>
</main></body></html>
"""

_CA_SECTION = """<h2>Certificat à installer</h2>
<p>Nécessaire uniquement pour le déchiffrement HTTPS (<code>mitm</code>).</p>
<p><a class="button" href="{path}">Télécharger le certificat</a></p>
<ol>
<li>iOS&nbsp;: installez le profil téléchargé dans <em>Réglages → Profil
téléchargé</em>, puis activez-le dans <em>Réglages → Général → Informations →
Réglages de confiance des certificats</em> (cette seconde étape est
obligatoire).</li>
<li>macOS&nbsp;: ouvrez le fichier dans Trousseau d'accès et passez-le sur
« Toujours approuver ».</li>
<li>Android&nbsp;: <em>Paramètres → Sécurité → Installer un certificat →
Certificat CA</em>.</li>
</ol>
"""

_NO_CA_SECTION = """<h2>Certificat</h2>
<p>Aucune autorité de certification n'a encore été créée&nbsp;; elle n'est utile
que pour le déchiffrement HTTPS. Lancez <code>ubproxy gen-ca</code>, puis
démarrez le proxy avec <code>mitm = true</code>.</p>
"""


def _response(status: int, phrase: str, content_type: str, body: bytes, extra: str = "") -> bytes:
    head = (
        f"HTTP/1.1 {status} {phrase}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{extra}"
        "Cache-Control: no-store\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("latin-1", "replace")
    return head + body


def setup_page(rule_count: int, mitm: bool, ca_available: bool) -> bytes:
    body = _PAGE.format(
        rules=f"{rule_count} règles chargées",
        https_mode="déchiffré et filtré par URL" if mitm else "filtré par nom d'hôte (SNI)",
        ca_section=_CA_SECTION.format(path=escape(CA_PATH)) if ca_available else _NO_CA_SECTION,
    ).encode("utf-8")
    return _response(200, "OK", "text/html; charset=utf-8", body)


def certificate_response(ca_cert: Path) -> bytes:
    """Serve the CA in the form iOS and Android expect for installation."""
    try:
        body = ca_cert.read_bytes()
    except OSError:
        return not_found()
    return _response(
        200,
        "OK",
        "application/x-x509-ca-cert",
        body,
        'Content-Disposition: attachment; filename="ubproxy-ca.crt"\r\n',
    )


def not_found() -> bytes:
    body = b"ubproxy: not found\n"
    return _response(404, "Not Found", "text/plain; charset=utf-8", body)


def handle(path: str, rule_count: int, mitm: bool, ca_cert: Optional[Path]) -> bytes:
    """Answer a request aimed at the proxy's own listening port."""
    path = path.split("?", 1)[0]
    if path == CA_PATH:
        if ca_cert is None or not ca_cert.exists():
            return not_found()
        return certificate_response(ca_cert)
    if path in ("/", "/index.html"):
        return setup_page(rule_count, mitm, ca_cert is not None and ca_cert.exists())
    return not_found()
