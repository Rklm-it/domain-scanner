"""Runtime configuration: API keys, timeouts, thresholds."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).parent / "data"


def _load_json(name: str, default: Any) -> Any:
    path = DATA_DIR / name
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


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
        value = value.strip().strip("\"'")
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
            safe_browsing_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None,
            virustotal_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
            ipinfo_token=os.getenv("IPINFO_TOKEN") or None,
            proxy=os.getenv("SCANNER_PROXY") or None,
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
