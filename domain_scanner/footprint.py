"""Cross-domain footprint analysis.

Individually clean domains still die together when they are obviously the same
operation from the outside: one IP, one registrar, registered the same
afternoon, same GA property, byte-identical landers. This module finds the
attributes a batch of domains has in common, so a shared point of failure is
visible before it costs an account.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import DomainReport


@dataclass
class Link:
    """One attribute shared by two or more domains in the batch."""

    kind: str
    value: str
    domains: list[str]
    severity: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "domains": sorted(self.domains),
            "severity": self.severity,
            "message": self.message,
            "detail": self.detail,
        }


def _group(pairs: list[tuple[str, str]]) -> dict[str, list[str]]:
    """[(value, domain)] -> {value: [domains]} keeping only shared values."""
    buckets: dict[str, set[str]] = defaultdict(set)
    for value, domain in pairs:
        if value:
            buckets[value].add(domain)
    return {v: sorted(d) for v, d in buckets.items() if len(d) > 1}


def analyze(reports: list[DomainReport]) -> list[Link]:
    """Find attributes shared across a batch of scanned domains."""
    usable = [r for r in reports if r.verdict not in ("INVALID", "ERROR")]
    if len(usable) < 2:
        return []

    total = len(usable)
    links: list[Link] = []

    def add(kind: str, value: str, domains: list[str], severity: str,
            message: str, detail: dict | None = None) -> None:
        links.append(Link(kind, value, domains, severity, message, detail or {}))

    def escalate(base: str, domains: list[str]) -> str:
        """A link covering the whole batch is worse than one covering a pair."""
        order = ["low", "medium", "high", "critical"]
        if len(domains) == total and total > 2:
            return order[min(order.index(base) + 1, len(order) - 1)]
        return base

    # --- hosting ---
    ip_pairs = [(ip, r.domain) for r in usable for ip in (r.data("dns", "a") or [])]
    for ip, domains in _group(ip_pairs).items():
        add("ip", ip, domains, escalate("high", domains),
            f"{len(domains)}/{total} domains resolve to the same IP {ip}")

    asn_pairs = [
        (str(n.get("asn")), r.domain)
        for r in usable
        for n in (r.data("hosting", "networks") or [])
        if n.get("asn")
    ]
    for asn, domains in _group(asn_pairs).items():
        if len(domains) == total and total > 2:
            add("asn", f"AS{asn}", domains, "low",
                f"all {total} domains sit in AS{asn} — same hosting network")

    ns_pairs = [
        (provider, r.domain)
        for r in usable
        for provider in (r.data("dns", "ns_provider") or [])
    ]
    for provider, domains in _group(ns_pairs).items():
        if len(domains) == total and total > 2 and provider not in (
            "cloudflare.com", "awsdns-01.org", "googledomains.com"
        ):
            add("ns", provider, domains, "low",
                f"all {total} domains use the same nameserver operator ({provider})")

    # --- registration ---
    reg_pairs = [
        (str(r.data("rdap", "registrar")), r.domain)
        for r in usable
        if r.data("rdap", "registrar")
    ]
    for registrar, domains in _group(reg_pairs).items():
        if len(domains) == total and total > 2:
            add("registrar", registrar, domains, "low",
                f"all {total} domains were bought from {registrar}")

    day_pairs = []
    for r in usable:
        created = r.data("rdap", "created")
        if created:
            day = datetime.fromtimestamp(created, timezone.utc).strftime("%Y-%m-%d")
            day_pairs.append((day, r.domain))
    for day, domains in _group(day_pairs).items():
        add("registration_date", day, domains, escalate("medium", domains),
            f"{len(domains)}/{total} domains were registered on the same day ({day})")

    # --- content and tracking ---
    fp_pairs = [
        (str(r.data("http", "fingerprint")), r.domain)
        for r in usable
        if r.data("http", "fingerprint")
    ]
    for fingerprint, domains in _group(fp_pairs).items():
        add("content", fingerprint, domains, escalate("high", domains),
            f"{len(domains)}/{total} domains serve a byte-identical landing page")

    title_pairs = [
        (str(r.data("http", "title")), r.domain)
        for r in usable
        if r.data("http", "title")
    ]
    for title, domains in _group(title_pairs).items():
        if not any(l.kind == "content" and set(domains) <= set(l.domains) for l in links):
            add("title", title, domains, "medium",
                f"{len(domains)}/{total} domains share the page title \"{title[:60]}\"")

    tracker_pairs = []
    for r in usable:
        for network, ids in (r.data("http", "trackers") or {}).items():
            for tracker_id in ids:
                tracker_pairs.append((f"{network}:{tracker_id}", r.domain))
    for tracker, domains in _group(tracker_pairs).items():
        add("tracker", tracker, domains, escalate("high", domains),
            f"{len(domains)}/{total} domains share the tracking ID {tracker} — "
            "an explicit link between the properties")

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    links.sort(key=lambda l: (severity_rank.get(l.severity, 9), -len(l.domains)))
    return links


def summarize(links: list[Link], reports: list[DomainReport]) -> str:
    if not links:
        return "No shared footprint detected across the batch."
    worst = links[0]
    return f"{len(links)} shared attribute(s); strongest link: {worst.message}"
