"""DNS-based domain blocklists (DBL/URIBL style).

These are the same lists mail and security vendors consult. A hit does not
prove Google knows about the domain, but a domain that is already on public
blocklists is one that has been used for something before.
"""

from __future__ import annotations

import threading
import time

from ..models import CheckResult
from ..utils import dns_query_quiet
from .base import ScanContext, register

# Every list publishes a test point that resolves whenever the zone is
# answering you. Without checking it there is no way to tell "not listed" from
# "your resolver is not allowed to ask" -- Spamhaus answers the latter with
# NXDOMAIN, which is indistinguishable from a clean domain. Reporting that as
# clean is exactly the kind of unearned reassurance this tool exists to avoid.
TEST_POINTS: dict[str, str] = {
    "dbl.spamhaus.org": "dbltest.com",
    "multi.surbl.org": "test.surbl.org",
    "multi.uribl.com": "test.uribl.com",
}

# Zone availability is a property of the resolver, not of the domain being
# scanned, so it is probed once and cached for the whole batch.
_ZONE_HEALTH_TTL = 600.0
_zone_health: dict[str, tuple[bool, float]] = {}
_zone_lock = threading.Lock()

# zone -> (label, {return code prefix: meaning})
ZONES: dict[str, tuple[str, dict[str, str]]] = {
    "dbl.spamhaus.org": (
        "Spamhaus DBL",
        {
            "127.0.1.2": "spam domain",
            "127.0.1.4": "phishing domain",
            "127.0.1.5": "malware domain",
            "127.0.1.6": "botnet C&C domain",
            "127.0.1.102": "abused legit spam",
            "127.0.1.103": "abused spammed redirector",
            "127.0.1.104": "abused legit phish",
            "127.0.1.105": "abused legit malware",
            "127.0.1.106": "abused legit botnet",
        },
    ),
    "multi.surbl.org": (
        "SURBL",
        {
            "127.0.0.8": "phishing (PH)",
            "127.0.0.16": "malware (MW)",
            "127.0.0.64": "abuse (ABUSE)",
            "127.0.0.128": "cracked (CR)",
        },
    ),
    "multi.uribl.com": (
        "URIBL",
        {
            "127.0.0.2": "black",
            "127.0.0.4": "grey",
            "127.0.0.8": "red",
        },
    ),
    "uribl.spameatingmonkey.net": ("SEM URIBL", {"127.0.0.2": "listed"}),
    "fresh.spameatingmonkey.net": ("SEM FRESH", {"127.0.0.2": "registered in the last days"}),
}

# Codes that mean "your query was rejected", not "listed".
#
# These must be matched exactly, never by prefix: 127.0.0.14 is a perfectly
# valid URIBL answer (black+grey+red = 2+4+8) and startswith("127.0.0.1")
# would swallow it, along with everything from .10 to .19.
ERROR_CODES = {"127.0.0.1", "127.0.0.255"}
ERROR_PREFIXES = ("127.255.255.",)
BLOCKED_CODES = ERROR_CODES


def zone_is_answering(ctx: ScanContext, zone: str) -> bool | None:
    """Is this blocklist replying to us at all?

    Returns None when the zone publishes no test point we can use.
    """
    test_host = TEST_POINTS.get(zone)
    if not test_host:
        return None
    now = time.monotonic()
    with _zone_lock:
        cached = _zone_health.get(zone)
        if cached and now - cached[1] < _ZONE_HEALTH_TTL:
            return cached[0]
    answers = dns_query_quiet(ctx.resolver, f"{test_host}.{zone}", "A")
    healthy = bool(answers) and not any(
        a in ERROR_CODES or a.startswith(ERROR_PREFIXES) for a in answers
    )
    with _zone_lock:
        _zone_health[zone] = (healthy, now)
    return healthy


def reset_zone_health_cache() -> None:
    with _zone_lock:
        _zone_health.clear()


def _decode(zone: str, answers: list[str]) -> tuple[list[str], bool]:
    """Return (reasons, query_rejected)."""
    label, codes = ZONES[zone]
    reasons: list[str] = []
    rejected = False
    for ans in answers:
        if ans in ERROR_CODES or ans.startswith(ERROR_PREFIXES):
            rejected = True
            continue
        if ans in codes:
            reasons.append(codes[ans])
        else:
            # SURBL packs multiple bits into the last octet.
            if zone == "multi.surbl.org":
                try:
                    bits = int(ans.rsplit(".", 1)[-1])
                except ValueError:
                    bits = 0
                for code, meaning in codes.items():
                    bit = int(code.rsplit(".", 1)[-1])
                    if bits & bit:
                        reasons.append(meaning)
            if not reasons:
                reasons.append(f"listed ({ans})")
    return sorted(set(reasons)), rejected


@register("blocklists", order=20, description="Public DNS blocklists (Spamhaus DBL, SURBL, URIBL)", transport="dns")
def check_blocklists(ctx: ScanContext) -> CheckResult:
    """Query public domain blocklists over DNS."""
    result = CheckResult(name="blocklists")
    listings: dict[str, list[str]] = {}
    rejected_zones: list[str] = []
    unavailable: list[str] = []
    # Zones whose test point resolved: silence from these genuinely means
    # "not listed", so only these license a clean verdict.
    verified: list[str] = []
    # Zones that publish no test point. A hit is still worth reporting, but
    # silence proves nothing -- they might not be answering us at all.
    opportunistic: list[str] = []

    for zone, (label, _codes) in ZONES.items():
        health = zone_is_answering(ctx, zone)
        if health is False:
            unavailable.append(label)
            continue
        (verified if health else opportunistic).append(label)
        answers = dns_query_quiet(ctx.resolver, f"{ctx.domain}.{zone}", "A")
        if not answers:
            continue
        reasons, rejected = _decode(zone, answers)
        if rejected:
            rejected_zones.append(label)
        if reasons:
            listings[label] = reasons

    result.data = {
        "listings": listings,
        "rejected_zones": rejected_zones,
        "unavailable_zones": unavailable,
        "zones_verified": verified,
        "zones_opportunistic": opportunistic,
    }

    for label, reasons in listings.items():
        fresh_only = label == "SEM FRESH"
        severity = "low" if fresh_only else ("critical" if len(listings) > 1 else "high")
        result.add(
            "blocklist.fresh" if fresh_only else "blocklist.listed",
            severity,
            f"listed on {label}: {', '.join(reasons)}",
            {"zone": label, "reasons": reasons},
        )

    stale = sorted(set(rejected_zones) | set(unavailable))
    if stale:
        result.add(
            "blocklist.unavailable", "info",
            f"no answer from {', '.join(stale)} — these lists refuse queries from public "
            "resolvers (8.8.8.8, 1.1.1.1). Point --nameserver (or SCANNER_NAMESERVER) at "
            "your ISP/local resolver, otherwise these lists are not being consulted at all.",
            {"zones": stale},
        )

    if not listings:
        if verified:
            result.add("blocklist.clean", "info",
                       f"not listed on {', '.join(verified)}")
        else:
            # No zone was confirmed to be answering. Saying "clean" here would
            # mean "we did not look".
            result.add("blocklist.no_data", "info",
                       "no blocklist could be confirmed as answering — this domain "
                       "was not actually checked against any list")
    return result
