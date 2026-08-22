"""Domain helpers: registrable domain (eTLD+1) and hostname matching.

A full Public Suffix List would be more accurate, but it is a 200 kB moving
target and the proxy only needs it to answer "are these two hostnames the same
site?".  The table below covers the multi-label suffixes that actually show up
in ad/tracker traffic; everything else falls back to the last two labels.
"""

from __future__ import annotations

# Second-level suffixes: "<anything>.<entry>" is a public suffix, so the
# registrable domain has three labels (e.g. bbc.co.uk).
_MULTI_LABEL_SUFFIXES = frozenset(
    """
    co.uk org.uk me.uk ltd.uk plc.uk net.uk sch.uk ac.uk gov.uk nhs.uk
    com.au net.au org.au edu.au gov.au id.au asn.au
    co.nz net.nz org.nz govt.nz ac.nz school.nz
    co.za org.za net.za web.za gov.za ac.za
    com.br net.br org.br gov.br edu.br
    com.ar net.ar org.ar gob.ar
    com.mx org.mx gob.mx
    co.jp ne.jp or.jp ac.jp go.jp ad.jp lg.jp
    co.kr or.kr ne.kr go.kr re.kr pe.kr
    com.cn net.cn org.cn gov.cn edu.cn ac.cn
    com.hk org.hk net.hk edu.hk gov.hk idv.hk
    com.tw net.tw org.tw idv.tw gov.tw edu.tw
    com.sg net.sg org.sg edu.sg gov.sg
    com.my net.my org.my gov.my edu.my
    co.in net.in org.in gen.in firm.in ind.in gov.in ac.in edu.in res.in
    com.tr net.tr org.tr gov.tr edu.tr
    com.ua net.ua org.ua gov.ua in.ua kiev.ua
    com.ru net.ru org.ru msk.ru spb.ru
    com.pl net.pl org.pl gov.pl edu.pl waw.pl
    com.es org.es nom.es gob.es edu.es
    co.il org.il net.il ac.il gov.il muni.il
    com.pt org.pt gov.pt edu.pt
    com.gr net.gr org.gr edu.gr gov.gr
    co.id or.id go.id ac.id web.id my.id
    co.th in.th ac.th go.th or.th
    com.vn net.vn org.vn edu.vn gov.vn
    com.ph net.ph org.ph gov.ph edu.ph
    com.pe org.pe net.pe gob.pe
    com.co net.co org.co gov.co edu.co
    com.ve net.ve org.ve
    com.uy org.uy gub.uy
    com.ec fin.ec gob.ec
    co.ke or.ke ne.ke go.ke ac.ke
    com.ng org.ng net.ng gov.ng edu.ng
    com.eg org.eg net.eg gov.eg edu.eg
    com.sa net.sa org.sa gov.sa edu.sa
    ae.org uk.com us.com eu.com br.com cn.com de.com gb.com jp.com no.com
    qc.com ru.com sa.com se.com uy.com za.com
    github.io gitlab.io pages.dev workers.dev netlify.app vercel.app
    herokuapp.com appspot.com cloudfront.net s3.amazonaws.com
    blogspot.com wordpress.com tumblr.com
    """.split()
)


def is_ip_literal(host: str) -> bool:
    """True for 1.2.3.4 style hosts and bracket-less IPv6 literals."""
    if not host:
        return False
    if host.count(":") >= 2:
        return True
    if host[0].isdigit() and host.replace(".", "").isdigit() and host.count(".") == 3:
        return True
    return False


def registrable_domain(host: str) -> str:
    """Return the eTLD+1 of *host* (``a.b.example.co.uk`` -> ``example.co.uk``)."""
    if not host:
        return ""
    host = host.strip(".").lower()
    if is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(a: str, b: str) -> bool:
    """First-party test used for ``$third-party`` / ``$first-party``."""
    if not a or not b:
        return False
    if a == b:
        return True
    return registrable_domain(a) == registrable_domain(b)


def host_and_parents(host: str):
    """Yield ``sub.example.com``, ``example.com``, ``com`` — used by $domain=."""
    host = host.strip(".").lower()
    if not host:
        return
    if is_ip_literal(host):
        yield host
        return
    labels = host.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def host_matches(candidate: str, rule_domain: str) -> bool:
    """``sub.example.com`` matches the rule domain ``example.com``."""
    if not candidate or not rule_domain:
        return False
    if candidate == rule_domain:
        return True
    return candidate.endswith("." + rule_domain)
