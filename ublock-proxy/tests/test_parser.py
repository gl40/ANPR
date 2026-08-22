import pytest

from ubproxy.filters.parser import (
    UnsupportedRule,
    parse_cosmetic_rule,
    parse_network_rule,
)
from ubproxy.filters.rules import Request


def rule(line):
    parsed, bad = parse_network_rule(line)
    assert not bad
    return parsed


def test_domain_anchor_matches_subdomains():
    r = rule("||ads.example.com^")
    assert r.hostname_anchor == "ads.example.com"
    assert r.matches(Request("https://ads.example.com/banner.png", "image"))
    assert r.matches(Request("https://a.b.ads.example.com/x", "image"))
    assert not r.matches(Request("https://notads.example.com/x", "image"))


def test_domain_anchor_regex_equivalent():
    r = rule("||example.com/track")
    assert r.hostname_anchor == ""
    assert r.matches(Request("https://example.com/track?id=1"))
    assert r.matches(Request("https://cdn.example.com/track"))
    assert not r.matches(Request("https://example.com.evil.net/track"))


def test_separator_and_wildcard():
    r = rule("/banner/*/img^")
    assert r.matches(Request("http://example.com/banner/foo/img?x=1"))
    assert r.matches(Request("http://example.com/banner/foo/img"))
    assert not r.matches(Request("http://example.com/banner/foo/imgraph"))


def test_anchors():
    start = rule("|http://example.com/")
    assert start.matches(Request("http://example.com/a"))
    assert not start.matches(Request("https://cdn.net/?u=http://example.com/a"))
    end = rule("/ads.js|")
    assert end.matches(Request("http://x.com/ads.js"))
    assert not end.matches(Request("http://x.com/ads.js?v=2"))


def test_type_options():
    r = rule("||example.com/x$script,third-party")
    assert r.types == frozenset({"script"})
    assert r.third_party is True
    assert r.matches(Request("https://example.com/x", "script", "other.org"))
    assert not r.matches(Request("https://example.com/x", "image", "other.org"))
    assert not r.matches(Request("https://example.com/x", "script", "example.com"))


def test_negated_type_and_first_party():
    r = rule("||example.com/x$~script,1p")
    assert r.excluded_types == frozenset({"script"})
    assert r.third_party is False
    assert r.matches(Request("https://example.com/x", "image", "example.com"))
    assert not r.matches(Request("https://example.com/x", "script", "example.com"))


def test_domain_option():
    r = rule("||cdn.net/a$domain=site.com|~sub.site.com")
    assert r.matches(Request("https://cdn.net/a", "script", "site.com"))
    assert r.matches(Request("https://cdn.net/a", "script", "www.site.com"))
    assert not r.matches(Request("https://cdn.net/a", "script", "sub.site.com"))
    assert not r.matches(Request("https://cdn.net/a", "script", "other.com"))


def test_regex_rule():
    r = rule("/^https?:\\/\\/ads[0-9]{1,3}\\./")
    assert r.matches(Request("https://ads42.example.com/x"))
    assert not r.matches(Request("https://adsx.example.com/x"))


def test_exception_and_important():
    exc, _ = parse_network_rule("@@||example.com/ok$document")
    assert exc.is_exception and "document" in exc.types
    imp = rule("||example.com/x$important")
    assert imp.important


def test_badfilter_flag():
    _, bad = parse_network_rule("||example.com/x$badfilter")
    assert bad


def test_unsupported_option():
    with pytest.raises(UnsupportedRule):
        parse_network_rule("||example.com^$redirect=noopjs")
    with pytest.raises(UnsupportedRule):
        parse_network_rule("||example.com^$removeparam=utm_source")


def test_match_case():
    r = rule("/Banner$match-case")
    assert r.matches(Request("http://x.com/Banner"))
    assert not r.matches(Request("http://x.com/banner"))


def test_cosmetic_rules():
    generic = parse_cosmetic_rule("##.ad-banner")
    assert generic.is_generic and generic.selector == ".ad-banner"
    specific = parse_cosmetic_rule("example.com,~sub.example.com##div#promo")
    assert specific.domains == frozenset({"example.com"})
    assert specific.excluded_domains == frozenset({"sub.example.com"})
    assert specific.applies_to("www.example.com")
    assert not specific.applies_to("sub.example.com")
    exception = parse_cosmetic_rule("example.com#@#.ad-banner")
    assert exception.is_exception


def test_cosmetic_procedural_unsupported():
    with pytest.raises(UnsupportedRule):
        parse_cosmetic_rule("example.com##div:has-text(Ad)")
