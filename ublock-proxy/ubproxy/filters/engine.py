"""The filtering engine: a token-indexed rule set, matched per request."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Optional

from ..domains import host_matches
from .parser import (
    UnsupportedRule,
    is_comment,
    iter_lines,
    looks_cosmetic,
    parse_cosmetic_rule,
    parse_network_rule,
)
from .rules import CosmeticRule, NetworkRule, ParseStats, Request

_HOSTS_LINE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(?P<host>[a-z0-9._-]+)\s*$", re.IGNORECASE
)
_PLAIN_HOST = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", re.IGNORECASE)
#: Endings that make a dotted line a substring pattern rather than a hostname
#: (``ads.js`` is a rule about a file name, ``ads.example`` about a host).
_FILE_ENDINGS = frozenset(
    """js css png gif jpg jpeg webp svg ico html htm php asp aspx jsp json
    xml txt swf gz zip mp4 webm woff woff2""".split()
)


@dataclass(slots=True)
class Decision:
    blocked: bool
    rule: Optional[NetworkRule] = None

    @property
    def reason(self) -> str:
        if self.rule is None:
            return "no rule"
        return self.rule.raw


ALLOW = Decision(False, None)


class FilterEngine:
    """Holds network + cosmetic rules and answers block/allow questions."""

    def __init__(self) -> None:
        self._block_index: dict[str, list[NetworkRule]] = defaultdict(list)
        self._block_fallback: list[NetworkRule] = []
        self._allow_index: dict[str, list[NetworkRule]] = defaultdict(list)
        self._allow_fallback: list[NetworkRule] = []
        self._badfilters: set[str] = set()
        self._pending: list[NetworkRule] = []
        self.generic_cosmetics: list[CosmeticRule] = []
        self.specific_cosmetics: dict[str, list[CosmeticRule]] = defaultdict(list)
        self.cosmetic_exceptions: list[CosmeticRule] = []
        self.stats = ParseStats()
        self._sealed = False

    # ------------------------------------------------------------------ load

    def load_text(self, text: str, source: str = "<memory>") -> None:
        """Parse a filter list. Hosts-file syntax is accepted as well."""
        self._sealed = False
        for line in iter_lines(text):
            if is_comment(line) or (line.startswith("#") and not looks_cosmetic(line)):
                self.stats.comments += 1
                continue

            hosts = _HOSTS_LINE.match(line)
            if hosts:
                self._add_network(f"||{hosts.group('host').lower()}^")
                continue

            if looks_cosmetic(line):
                try:
                    rule = parse_cosmetic_rule(line)
                except UnsupportedRule:
                    self.stats.note_unsupported(line)
                    continue
                self._add_cosmetic(rule)
                self.stats.cosmetic += 1
                continue

            if _PLAIN_HOST.match(line) and line.rsplit(".", 1)[1].lower() not in _FILE_ENDINGS:
                self._add_network(f"||{line.lower()}^")
                continue

            self._add_network(line)

    def _add_network(self, line: str) -> None:
        try:
            rule, badfilter = parse_network_rule(line)
        except UnsupportedRule:
            self.stats.note_unsupported(line)
            return
        except re.error:  # pragma: no cover - malformed regexp in a list
            self.stats.note_unsupported(line)
            return
        if badfilter:
            self._badfilters.add(rule.raw.replace("$badfilter", "").replace(",badfilter", ""))
            self.stats.badfilters += 1
            return
        self._pending.append(rule)
        self.stats.network += 1

    def _add_cosmetic(self, rule: CosmeticRule) -> None:
        if rule.is_exception:
            self.cosmetic_exceptions.append(rule)
        elif rule.is_generic:
            self.generic_cosmetics.append(rule)
        else:
            for domain in rule.domains:
                self.specific_cosmetics[domain].append(rule)

    def seal(self) -> None:
        """Build the token index. Called automatically on the first match.

        Each rule is filed under its *rarest* literal token rather than its
        longest one: indexing 20 000 rules under a token as common as
        ``example`` would make every URL containing it walk the whole bucket.
        """
        if self._sealed:
            return
        self._block_index.clear()
        self._block_fallback.clear()
        self._allow_index.clear()
        self._allow_fallback.clear()

        live = [rule for rule in self._pending if rule.raw not in self._badfilters]
        frequency: Counter[str] = Counter()
        for rule in live:
            frequency.update(set(rule.candidate_tokens))

        for rule in live:
            index, fallback = (
                (self._allow_index, self._allow_fallback)
                if rule.is_exception
                else (self._block_index, self._block_fallback)
            )
            if rule.candidate_tokens:
                rule.token = min(
                    rule.candidate_tokens, key=lambda t: (frequency[t], -len(t))
                )
                index[rule.token].append(rule)
            else:
                fallback.append(rule)
        self._sealed = True

    # --------------------------------------------------------------- matching

    def _candidates(
        self, index: dict[str, list[NetworkRule]], fallback: list[NetworkRule], request: Request
    ) -> Iterable[NetworkRule]:
        seen_buckets: set[str] = set()
        for token in request.tokens:
            if token in seen_buckets:
                continue
            seen_buckets.add(token)
            bucket = index.get(token)
            if bucket:
                yield from bucket
        yield from fallback

    def match(self, request: Request) -> Decision:
        """Return the block/allow decision for *request* (uBlock precedence)."""
        self.seal()
        blocking: Optional[NetworkRule] = None
        for rule in self._candidates(self._block_index, self._block_fallback, request):
            if rule.matches(request):
                if rule.important:
                    return Decision(True, rule)
                if blocking is None:
                    blocking = rule
        if blocking is None:
            return ALLOW
        for rule in self._candidates(self._allow_index, self._allow_fallback, request):
            if rule.matches(request):
                return Decision(False, rule)
        return Decision(True, blocking)

    def is_document_whitelisted(self, hostname: str) -> bool:
        """True when ``@@||host^$document`` (or similar) exempts a whole page."""
        self.seal()
        request = Request(
            f"https://{hostname}/",
            request_type="document",
            document_hostname=hostname,
            hostname=hostname,
        )
        for rule in self._candidates(self._allow_index, self._allow_fallback, request):
            if "document" in rule.types and rule.matches(request):
                return True
        return False

    # --------------------------------------------------------------- cosmetic

    def cosmetic_selectors(self, hostname: str, include_generic: bool = True) -> list[str]:
        """CSS selectors to hide on *hostname*, exceptions already removed."""
        hostname = (hostname or "").lower()
        selected: list[CosmeticRule] = []
        if include_generic:
            selected.extend(r for r in self.generic_cosmetics if r.applies_to(hostname))
        for domain, rules in self.specific_cosmetics.items():
            if host_matches(hostname, domain):
                selected.extend(r for r in rules if r.applies_to(hostname))
        if not selected:
            return []
        excluded = {
            r.selector for r in self.cosmetic_exceptions if r.applies_to(hostname)
        }
        out: list[str] = []
        seen: set[str] = set()
        for rule in selected:
            if rule.selector in excluded or rule.selector in seen:
                continue
            seen.add(rule.selector)
            out.append(rule.selector)
        return out

    # ------------------------------------------------------------------ misc

    @property
    def rule_count(self) -> int:
        self.seal()
        return sum(len(b) for b in self._block_index.values()) + len(self._block_fallback) + \
            sum(len(b) for b in self._allow_index.values()) + len(self._allow_fallback)

    def summary(self) -> str:
        self.seal()
        return (
            f"{self.stats.network} network rules, {self.stats.cosmetic} cosmetic rules, "
            f"{self.stats.unsupported} unsupported lines skipped"
        )
