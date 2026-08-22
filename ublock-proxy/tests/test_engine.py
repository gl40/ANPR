from ubproxy.filters.engine import FilterEngine
from ubproxy.filters.rules import Request

LIST = """
! title: test list
||ads.example.com^
||tracker.net^$third-party
||cdn.example.com/ads/*$script
@@||cdn.example.com/ads/allowed.js$script
||paywall.example^$important
@@||paywall.example^
/pixel.gif|$image
0.0.0.0 hosts-blocked.example
plain-host-blocked.example
##.generic-ad
example.com##.sidebar-ad
example.com,~shop.example.com##.promo
example.com#@#.generic-ad
||typo.example^$badfilter
||typo.example^
"""


def engine():
    e = FilterEngine()
    e.load_text(LIST)
    e.seal()
    return e


def test_basic_block_and_allow():
    e = engine()
    assert e.match(Request("https://ads.example.com/x.png", "image")).blocked
    assert not e.match(Request("https://example.com/x.png", "image")).blocked


def test_third_party_only():
    e = engine()
    assert e.match(Request("https://tracker.net/t.gif", "image", "site.org")).blocked
    assert not e.match(Request("https://tracker.net/t.gif", "image", "tracker.net")).blocked


def test_type_restriction_and_exception():
    e = engine()
    assert e.match(Request("https://cdn.example.com/ads/a.js", "script")).blocked
    assert not e.match(Request("https://cdn.example.com/ads/a.png", "image")).blocked
    assert not e.match(Request("https://cdn.example.com/ads/allowed.js", "script")).blocked


def test_important_beats_exception():
    e = engine()
    assert e.match(Request("https://paywall.example/x", "script")).blocked


def test_hosts_and_plain_host_syntax():
    e = engine()
    assert e.match(Request("https://hosts-blocked.example/a", "image")).blocked
    assert e.match(Request("https://www.plain-host-blocked.example/a", "image")).blocked


def test_badfilter_removes_rule():
    e = engine()
    assert not e.match(Request("https://typo.example/a", "image")).blocked


def test_end_anchor_with_type():
    e = engine()
    assert e.match(Request("https://any.site/pixel.gif", "image")).blocked
    assert not e.match(Request("https://any.site/pixel.gif?x=1", "image")).blocked


def test_cosmetics():
    e = engine()
    selectors = e.cosmetic_selectors("www.example.com", include_generic=True)
    assert ".sidebar-ad" in selectors
    assert ".promo" in selectors
    # the #@# exception removes the generic rule on this domain
    assert ".generic-ad" not in selectors
    assert ".promo" not in e.cosmetic_selectors("shop.example.com", include_generic=True)
    assert ".generic-ad" in e.cosmetic_selectors("other.org", include_generic=True)
    assert e.cosmetic_selectors("other.org", include_generic=False) == []


def test_document_whitelist():
    e = FilterEngine()
    e.load_text("@@||safe.example^$document\n||safe.example^")
    assert e.is_document_whitelisted("safe.example")
    assert not e.is_document_whitelisted("other.example")


def test_token_index_is_used():
    e = FilterEngine()
    e.load_text("\n".join(f"||host{i}.example^" for i in range(5000)))
    e.seal()
    assert e.match(Request("https://host4999.example/a", "image")).blocked
    assert not e.match(Request("https://hostnope.example/a", "image")).blocked


def test_bare_filename_is_not_treated_as_a_hostname():
    e = FilterEngine()
    e.load_text("ads.js\nads.example")
    e.seal()
    # ``ads.js`` is a substring rule...
    assert e.match(Request("https://site.test/static/ads.js", "script")).blocked
    # ...while ``ads.example`` is a hostname rule and only blocks that host.
    assert e.match(Request("https://cdn.ads.example/x", "script")).blocked
    assert not e.match(Request("https://site.test/ads.example.txt", "other")).blocked
