from ubproxy.config import Config
from ubproxy.filtering import Filtering, document_hostname, infer_request_type
from ubproxy.net.http1 import Headers
from ubproxy.net.proxy import ConnectionContext, _resolve_target
from ubproxy.net import http1


def headers(**kwargs):
    return Headers([(k.replace("_", "-"), v) for k, v in kwargs.items()])


def test_type_from_sec_fetch_dest():
    assert infer_request_type("GET", "https://x/y", headers(Sec_Fetch_Dest="script")) == "script"
    assert infer_request_type("GET", "https://x/y", headers(Sec_Fetch_Dest="iframe")) == "subdocument"
    assert infer_request_type("GET", "https://x/y", headers(Sec_Fetch_Dest="empty")) == "xmlhttprequest"


def test_type_from_accept_then_extension():
    assert infer_request_type("GET", "https://x/y", headers(Accept="text/html,*/*")) == "document"
    assert infer_request_type("GET", "https://x/a.js", Headers()) == "script"
    assert infer_request_type("GET", "https://x/a.woff2?v=3", Headers()) == "font"
    assert infer_request_type("GET", "https://x/unknown", Headers()) == "other"


def test_document_hostname_from_referer():
    assert document_hostname(headers(Referer="https://Page.EXAMPLE/x"), "script", "cdn.net") == "page.example"
    assert document_hostname(Headers(), "document", "site.org") == "site.org"
    assert document_hostname(Headers(), "script", "cdn.net") == ""


def make_filtering(**overrides):
    config = Config(lists=[], state_dir="/tmp/ubproxy-test", **overrides)
    filtering = Filtering(config)
    filtering.engine.load_text(
        "||tracker.example^\n"
        "||cdn.example/ads.js$script\n"
        "@@||cdn.example/ads.js$script,domain=partner.example\n"
    )
    filtering.engine.seal()
    return filtering


def test_check_uses_referer_for_third_party():
    filtering = make_filtering()
    verdict = filtering.check(
        "https://cdn.example/ads.js", "GET", headers(Referer="https://news.example/"), "cdn.example"
    )
    assert verdict.blocked and verdict.request_type == "script"

    allowed = filtering.check(
        "https://cdn.example/ads.js", "GET", headers(Referer="https://partner.example/"), "cdn.example"
    )
    assert not allowed.blocked


def test_allowlist_wins():
    filtering = make_filtering(allow_hosts=["tracker.example"])
    assert not filtering.check("https://tracker.example/a", "GET", Headers(), "tracker.example").blocked


def test_check_host_only_uses_type_agnostic_rules():
    filtering = make_filtering()
    assert filtering.check_host("tracker.example").blocked
    # ``$script`` rules must not take down a whole host through SNI filtering
    assert not filtering.check_host("cdn.example").blocked


def test_cosmetic_style_is_cached_and_scoped():
    filtering = make_filtering()
    filtering.engine.load_text("site.example##.ad\nsite.example##.promo")
    filtering.engine.seal()
    style = filtering.cosmetic_style("www.site.example")
    assert b".ad" in style and b"display:none!important" in style
    assert filtering.cosmetic_style("www.site.example") is style
    assert filtering.cosmetic_style("other.example") == b""


def test_resolve_target_origin_form():
    request = http1.parse_request(b"GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    url, host, port, path = _resolve_target(request, ConnectionContext(scheme="http", port=80))
    assert (url, host, port, path) == ("http://example.com/a?b=1", "example.com", 80, "/a?b=1")


def test_resolve_target_with_port_and_https():
    request = http1.parse_request(b"GET /a HTTP/1.1\r\nHost: example.com:8443\r\n\r\n")
    url, host, port, _ = _resolve_target(request, ConnectionContext(scheme="https", port=443))
    assert (url, host, port) == ("https://example.com:8443/a", "example.com", 8443)


def test_resolve_target_absolute_form():
    request = http1.parse_request(b"GET http://example.com:8080/x HTTP/1.1\r\nHost: nope\r\n\r\n")
    url, host, port, path = _resolve_target(request, ConnectionContext())
    assert (url, host, port, path) == ("http://example.com:8080/x", "example.com", 8080, "/x")


def test_resolve_target_falls_back_to_destination():
    """Transparent mode without a Host header: the redirect target is used."""
    request = http1.parse_request(b"GET /x HTTP/1.0\r\n\r\n")
    context = ConnectionContext(scheme="http", host="10.0.0.5", port=80)
    url, host, port, _ = _resolve_target(request, context)
    assert (url, host, port) == ("http://10.0.0.5/x", "10.0.0.5", 80)
