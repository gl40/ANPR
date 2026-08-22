"""Configuration loading (TOML) with sane defaults."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

DEFAULT_LISTS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://ublockorigin.github.io/uAssets/filters/filters.txt",
    "https://ublockorigin.github.io/uAssets/filters/privacy.txt",
    "https://ublockorigin.github.io/uAssets/filters/badware.txt",
]


def _default_state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "ubproxy"


@dataclass(slots=True)
class Config:
    # --- listeners ---------------------------------------------------------
    listen_address: str = "0.0.0.0"
    http_port: int = 8080
    tls_port: int = 8443

    # --- filtering ---------------------------------------------------------
    lists: list[str] = field(default_factory=lambda: list(DEFAULT_LISTS))
    extra_rules: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)
    cosmetic_filtering: bool = True
    generic_cosmetic_filtering: bool = False
    max_html_rewrite_bytes: int = 4 * 1024 * 1024

    # --- TLS ---------------------------------------------------------------
    #: Decrypt HTTPS to filter by URL path and inject cosmetic CSS.  When
    #: false the proxy only filters HTTPS by SNI hostname (no CA needed).
    mitm: bool = False
    ca_cert: str = ""
    ca_key: str = ""
    mitm_bypass_hosts: list[str] = field(
        default_factory=lambda: [
            # Certificate pinning / non-HTTP traffic: never decrypt these.
            "*.apple.com",
            "*.icloud.com",
            "*.mozilla.org",
            "*.windowsupdate.com",
            "*.whatsapp.net",
            "*.signal.org",
        ]
    )
    upstream_verify: bool = True

    # --- plumbing ----------------------------------------------------------
    state_dir: str = ""
    list_refresh_hours: int = 24
    connect_timeout: float = 10.0
    idle_timeout: float = 120.0
    log_level: str = "info"
    log_allowed: bool = False
    stats_interval: int = 0

    def __post_init__(self) -> None:
        if not self.state_dir:
            self.state_dir = str(_default_state_dir())
        state = Path(self.state_dir)
        if not self.ca_cert:
            self.ca_cert = str(state / "ca" / "ubproxy-ca.crt")
        if not self.ca_key:
            self.ca_key = str(state / "ca" / "ubproxy-ca.key")

    # ---------------------------------------------------------------- paths

    @property
    def cache_dir(self) -> Path:
        return Path(self.state_dir) / "lists"

    @property
    def cert_dir(self) -> Path:
        return Path(self.state_dir) / "certs"

    # ---------------------------------------------------------------- load

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None) -> "Config":
        if not path:
            return cls()
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
        return cls(**data)
