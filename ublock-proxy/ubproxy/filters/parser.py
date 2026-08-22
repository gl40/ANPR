"""Parser for the Adblock Plus / uBlock Origin filter syntax.

Supported:
  * network rules: ``||host^``, ``|http://x``, ``x|``, ``a*b``, ``/regexp/``
  * exceptions: ``@@...``
  * options: type filters (and their ``~`` negations), ``third-party``/``1p``,
    ``domain=``, ``denyallow=``, ``important``, ``match-case``, ``all``,
    ``badfilter``
  * cosmetic element hiding: ``##sel``, ``dom##sel``, ``#@#sel``

Deliberately unsupported (the line is counted and skipped, never guessed at):
  ``$redirect``, ``$csp``, ``$removeparam``, ``$replace``, scriptlet
  injections (``#%#``, ``#$#``) and procedural cosmetic filters (``#?#``,
  ``:has-text()``, ``:xpath()`` ...).
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .rules import (
    BAD_TOKENS,
    CosmeticRule,
    NetworkRule,
    REQUEST_TYPES,
    TYPE_ALIASES,
    tokenize,
)


class UnsupportedRule(Exception):
    """Raised for syntax the engine cannot honour faithfully."""


_OPTIONS_WITHOUT_VALUE = {
    "third-party", "3p", "first-party", "1p", "important", "match-case",
    "badfilter", "all", "document", "popup", "strict1p", "strict3p",
}

_PROCEDURAL_MARKERS = (
    ":has-text(", ":matches-css", ":xpath(", ":upward(", ":remove(",
    ":style(", ":matches-path(", ":min-text-length(", ":watch-attr(",
    ":others(", ":matches-attr(", ":matches-prop(",
)

# Characters that have a special meaning inside a filter pattern.
_SPECIAL = set("*^|")


def compile_pattern(pattern: str, match_case: bool) -> re.Pattern[str]:
    flags = 0 if match_case else re.IGNORECASE
    if len(pattern) > 2 and pattern.startswith("/") and pattern.endswith("/"):
        try:
            return re.compile(pattern[1:-1], flags)
        except re.error as exc:  # pragma: no cover - depends on list content
            raise UnsupportedRule(f"bad regexp: {exc}") from exc

    out: list[str] = []
    i = 0
    n = len(pattern)
    if pattern.startswith("||"):
        # Start of domain name, subdomains included.
        out.append(r"^[a-z][a-z0-9+.-]*://(?:[^/?#]*@)?(?:[^/?#]*\.)?")
        i = 2
    elif pattern.startswith("|"):
        out.append("^")
        i = 1
    while i < n:
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            # ABP separator: anything that is not a letter, digit, _, -, . or %
            out.append(r"(?:[^a-zA-Z0-9_.%-]|$)")
        elif ch == "|" and i == n - 1:
            out.append("$")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("".join(out), flags)


def _hostname_anchor(pattern: str) -> str:
    """Return the host for plain ``||example.com^`` rules, else ``''``.

    Such rules are by far the most common shape in real lists and can be
    answered with a suffix comparison instead of a regexp.
    """
    if not pattern.startswith("||"):
        return ""
    body = pattern[2:]
    if body.endswith("^"):
        body = body[:-1]
    if not body or any(c in _SPECIAL for c in body) or "/" in body:
        return ""
    if not re.fullmatch(r"[a-z0-9._-]+", body, re.IGNORECASE):
        return ""
    return body.lower()


def candidate_tokens(pattern: str) -> tuple[str, ...]:
    """Literal runs of the pattern, any of which must appear in a match.

    Wildcards and separators only ever *add* freedom, so every literal run of
    a pattern is a substring of every URL it matches — which makes each one a
    usable index key.  The engine then keeps the rarest.
    """
    if len(pattern) > 2 and pattern.startswith("/") and pattern.endswith("/"):
        return ()  # regexps go to the catch-all bucket
    found = tokenize(pattern.lower())
    if not found:
        return ()
    good = tuple(t for t in found if t not in BAD_TOKENS and len(t) >= 3)
    return good or tuple(found)


def _split_domains(value: str) -> tuple[frozenset[str], frozenset[str]]:
    included: set[str] = set()
    excluded: set[str] = set()
    for part in value.split("|"):
        part = part.strip().lower().lstrip(".")
        if not part:
            continue
        if part.startswith("~"):
            excluded.add(part[1:])
        else:
            included.add(part)
    return frozenset(included), frozenset(excluded)


def _split_options(line: str) -> tuple[str, str]:
    """Split ``pattern$options`` while leaving ``/regex$with$dollars/`` alone."""
    if line.startswith("/"):
        end = line.rfind("/")
        if end > 0:
            tail = line[end + 1 :]
            if tail.startswith("$"):
                return line[: end + 1], tail[1:]
            if tail == "":
                return line, ""
    idx = line.find("$")
    if idx == -1:
        return line, ""
    return line[:idx], line[idx + 1 :]


def parse_network_rule(line: str) -> tuple[NetworkRule, bool]:
    """Parse one network rule. Returns ``(rule, is_badfilter)``."""
    is_exception = line.startswith("@@")
    if is_exception:
        line = line[2:]
    pattern, options = _split_options(line)
    if not pattern:
        raise UnsupportedRule("empty pattern")

    important = False
    match_case = False
    badfilter = False
    third_party: Optional[bool] = None
    types: set[str] = set()
    excluded_types: set[str] = set()
    domains: frozenset[str] = frozenset()
    excluded_domains: frozenset[str] = frozenset()
    denyallow: frozenset[str] = frozenset()

    if options:
        for opt in options.split(","):
            opt = opt.strip()
            if not opt:
                continue
            name, _, value = opt.partition("=")
            negated = name.startswith("~")
            if negated:
                name = name[1:]
            name = name.lower()
            canonical = TYPE_ALIASES.get(name, name)

            if canonical in REQUEST_TYPES:
                (excluded_types if negated else types).add(canonical)
            elif name in ("third-party", "3p"):
                third_party = not negated
            elif name in ("first-party", "1p"):
                third_party = negated
            elif name == "important":
                important = True
            elif name == "match-case":
                match_case = True
            elif name == "badfilter":
                badfilter = True
            elif name == "all":
                pass  # every type, i.e. the default
            elif name == "domain" or name == "from":
                domains, excluded_domains = _split_domains(value)
            elif name == "denyallow" or name == "to":
                denyallow, _ = _split_domains(value)
            else:
                raise UnsupportedRule(f"option {name!r}")

    # ``document`` as an option on an exception means "whitelist the page";
    # it is handled by the engine through the document request type.
    return (
        NetworkRule(
            raw=line,
            pattern=pattern,
            is_exception=is_exception,
            important=important,
            match_case=match_case,
            third_party=third_party,
            types=frozenset(types),
            excluded_types=frozenset(excluded_types),
            domains=domains,
            excluded_domains=excluded_domains,
            denyallow=denyallow,
            hostname_anchor=_hostname_anchor(pattern) if not types and not match_case else "",
            candidate_tokens=candidate_tokens(pattern),
        ),
        badfilter,
    )


_COSMETIC_RE = re.compile(r"^(?P<domains>[^#]*)#(?P<sep>@?)#(?P<selector>.+)$")


def parse_cosmetic_rule(line: str) -> CosmeticRule:
    match = _COSMETIC_RE.match(line)
    if not match:
        raise UnsupportedRule("not an element-hiding rule")
    selector = match.group("selector").strip()
    if not selector:
        raise UnsupportedRule("empty selector")
    if any(marker in selector for marker in _PROCEDURAL_MARKERS):
        raise UnsupportedRule("procedural cosmetic filter")
    if selector.startswith("+js(") or selector.startswith("script:"):
        raise UnsupportedRule("scriptlet injection")
    domains, excluded = _split_domains(match.group("domains").replace(",", "|"))
    return CosmeticRule(
        selector=selector,
        domains=domains,
        excluded_domains=excluded,
        is_exception=match.group("sep") == "@",
    )


def is_comment(line: str) -> bool:
    return line.startswith("!") or line.startswith("[Adblock") or line.startswith("#\t") or line == "#"


def looks_cosmetic(line: str) -> bool:
    return "##" in line or "#@#" in line or "#?#" in line or "#$#" in line or "#%#" in line


def iter_lines(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            yield line
