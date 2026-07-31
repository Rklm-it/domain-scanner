"""Check registry and the shared per-domain context."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import dns.resolver
import requests

from ..config import Config
from ..models import CheckResult


@dataclass
class ScanContext:
    """Shared state for all checks running against one domain.

    Checks store intermediate results here (resolved IPs, the fetched
    homepage, ...) so later checks do not repeat the same network work.
    """

    domain: str
    sld: str
    suffix: str
    config: Config
    resolver: dns.resolver.Resolver
    session: requests.Session
    shared: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.shared.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.shared[key] = value


CheckFn = Callable[[ScanContext], CheckResult]

_REGISTRY: dict[str, "Check"] = {}


@dataclass
class Check:
    name: str
    fn: CheckFn
    order: int
    description: str
    # Which transport the check depends on: "none", "dns" or "http". Used to
    # skip checks whose transport this machine cannot reach, instead of
    # reporting the resulting failures as problems with the domain.
    transport: str = "http"
    requires: tuple[str, ...] = ()  # names of config attributes that must be set


def register(
    name: str,
    order: int = 50,
    description: str = "",
    transport: str = "http",
    requires: tuple[str, ...] = (),
) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        _REGISTRY[name] = Check(name, fn, order, description or (fn.__doc__ or "").strip(),
                                transport, requires)
        return fn

    return deco


def all_checks() -> list[Check]:
    return sorted(_REGISTRY.values(), key=lambda c: (c.order, c.name))


def get_check(name: str) -> Check | None:
    return _REGISTRY.get(name)


def run_check(check: Check, ctx: ScanContext) -> CheckResult:
    """Execute a check, converting any exception into an ``error`` result."""
    started = time.monotonic()
    # Opting out of a check (no API key) is reported before connectivity, so an
    # unconfigured check never shows up as a gap in coverage.
    for attr in check.requires:
        if not getattr(ctx.config, attr, None):
            result = CheckResult(name=check.name)
            result.skip(f"missing config: {attr}", kind="config")
            return result
    if check.transport == "http" and not ctx.config.http_available:
        result = CheckResult(name=check.name)
        result.skip("no outbound HTTP from this machine", kind="transport")
        return result
    if check.transport == "dns" and not ctx.config.dns_available:
        result = CheckResult(name=check.name)
        result.skip("no DNS resolution from this machine", kind="transport")
        return result
    try:
        result = check.fn(ctx)
    except Exception as exc:  # noqa: BLE001 - a broken check must not kill the scan
        result = CheckResult(name=check.name)
        result.fail(f"{type(exc).__name__}: {exc}")
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result
