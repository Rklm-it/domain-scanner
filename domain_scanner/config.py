"""Runtime configuration: API keys, timeouts, thresholds."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("domain_scanner.config")

DATA_DIR = Path(__file__).parent / "data"


def _load_json(name: str, default: Any) -> Any:
    path = DATA_DIR / name
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def strip_inline_comment(value: str) -> str:
    """Drop a trailing ``# comment`` from an unquoted value.

    Docker Compose does not strip these when reading env_file, so a line like
    ``SCANNER_WORKERS=8   # threads`` arrives as the literal string
    ``8   # threads``. Anything quoted is left alone -- a token may legitimately
    contain a '#'.
    """
    text = value.strip()
    if text[:1] in ("'", '"'):
        quote = text[0]
        end = text.find(quote, 1)
        if end != -1:
            return text[1:end]
        return text[1:]
    # Only treat '#' as a comment when it is preceded by whitespace, so
    # values that merely contain '#' survive.
    for i, ch in enumerate(text):
        if ch == "#" and (i == 0 or text[i - 1].isspace()):
            return text[:i].strip()
    return text


def env_str(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = strip_inline_comment(raw)
    return value if value else default


def env_int(name: str, default: int) -> int:
    """Read an int from the environment, surviving a malformed value.

    A bad number must not put the process into a restart loop: log it, use the
    default, keep serving.
    """
    raw = env_str(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning("%s=%r is not a whole number; using %s", name, raw, default)
        return default


def env_float(name: str, default: float) -> float:
    raw = env_str(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        log.warning("%s=%r is not a number; using %s", name, raw, default)
        return default


def env_bool(name: str, default: bool) -> bool:
    raw = env_str(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal .env loader so the tool works without extra dependencies."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        value = strip_inline_comment(value)
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass
class Config:
    # --- credentials (all optional; checks self-skip when missing) ---
    safe_browsing_key: str | None = None
    virustotal_key: str | None = None
    ipinfo_token: str | None = None

    # --- networking ---
    http_timeout: float = 12.0
    dns_timeout: float = 6.0
    nameservers: list[str] | None = None
    proxy: str | None = None
    workers: int = 8
    max_redirects: int = 10

    # --- thresholds ---
    fresh_domain_days: int = 30
    young_domain_days: int = 90
    established_domain_days: int = 365
    expiry_soon_days: int = 60
    # A domain whose Wayback history predates registration by more than this is
    # treated as a re-registered ("recycled") domain.
    recycle_gap_days: int = 180
    # Reverse-IP neighbour counts that suggest cheap shared/bulk hosting.
    crowded_ip_domains: int = 200

    # Refuse to fetch anything that resolves to a private/loopback/link-local
    # address. Keep this on for anything network-facing: it is what stops a
    # hostile domain from pointing the scanner at 169.254.169.254.
    block_private_targets: bool = True

    # --- connectivity (set by the CLI preflight) ---
    http_available: bool = True
    dns_available: bool = True

    # --- toggles ---
    enabled_checks: set[str] = field(default_factory=set)
    disabled_checks: set[str] = field(default_factory=set)

    # --- reference data ---
    tld_risk: dict[str, Any] = field(default_factory=dict)
    keywords: dict[str, Any] = field(default_factory=dict)
    registrars: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, **overrides: Any) -> "Config":
        cfg = cls(
            safe_browsing_key=env_str("GOOGLE_SAFE_BROWSING_API_KEY") or None,
            virustotal_key=env_str("VIRUSTOTAL_API_KEY") or None,
            ipinfo_token=env_str("IPINFO_TOKEN") or None,
            proxy=env_str("SCANNER_PROXY") or None,
        )
        cfg.tld_risk = _load_json("tld_risk.json", {"tiers": {}, "default_tier": 2})
        cfg.keywords = _load_json("keywords.json", {})
        cfg.registrars = _load_json("registrars.json", {"high_abuse": []})
        for key, value in overrides.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg

    def is_enabled(self, name: str) -> bool:
        if name in self.disabled_checks:
            return False
        if self.enabled_checks:
            return name in self.enabled_checks
        return True
