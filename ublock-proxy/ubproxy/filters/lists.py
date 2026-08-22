"""Fetching and caching of filter lists."""

from __future__ import annotations

import hashlib
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("ubproxy.lists")

USER_AGENT = "ubproxy/1.0 (+filter list fetcher)"


def _cache_path(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode()).hexdigest()[:16]
    name = url.rstrip("/").rsplit("/", 1)[-1] or "list"
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:48]
    return cache_dir / f"{safe}.{digest}.txt"


def fetch(url: str, cache_dir: Path, max_age_hours: int = 24, force: bool = False) -> str:
    """Return the list body, downloading it only when the cache is stale."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _cache_path(cache_dir, url)
    if path.exists() and not force:
        age_hours = (time.time() - path.stat().st_mtime) / 3600
        if age_hours < max_age_hours:
            return path.read_text(encoding="utf-8", errors="replace")

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if path.exists():
            log.warning("could not refresh %s (%s), using cached copy", url, exc)
            return path.read_text(encoding="utf-8", errors="replace")
        log.error("could not download %s: %s", url, exc)
        return ""
    path.write_text(body, encoding="utf-8")
    log.info("downloaded %s (%d KiB)", url, len(body) // 1024)
    return body


def load_source(source: str, cache_dir: Path, max_age_hours: int = 24, force: bool = False) -> tuple[str, str]:
    """Load a list from a URL or a local path. Returns ``(text, label)``."""
    if source.startswith("http://") or source.startswith("https://"):
        return fetch(source, cache_dir, max_age_hours, force), source
    path = Path(source).expanduser()
    if not path.exists():
        log.error("filter list not found: %s", path)
        return "", str(path)
    return path.read_text(encoding="utf-8", errors="replace"), str(path)
