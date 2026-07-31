"""DNS-based domain blocklists (DBL/URIBL style).

These are the same lists mail and security vendors consult. A hit does not
prove Google knows about the domain, but a domain that is already on public
blocklists is one that has been used for something before.
"""

from __future__ import annotations

from ..models import CheckResult
from ..utils import dns_query_quiet
from .base import ScanContext, register

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

# Codes every zone uses to signal "your query was rejected", not "listed".
ERROR_PREFIXES = ("127.255.255.", "127.0.0.1")
BLOCKED_CODES = {"127.0.0.255"}


def _decode(zone: str, answers: list[str]) -> tuple[list[str], bool]:
    """Return (reasons, query_rejected)."""
    label, codes = ZONES[zone]
    reasons: list[str] = []
    rejected = False
    for ans in answers:
        if ans in BLOCKED_CODES or ans.startswith(ERROR_PREFIXES):
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

    for zone, (label, _codes) in ZONES.items():
        answers = dns_query_quiet(ctx.resolver, f"{ctx.domain}.{zone}", "A")
        if not answers:
            continue
        reasons, rejected = _decode(zone, answers)
        if rejected:
            rejected_zones.append(label)
        if reasons:
            listings[label] = reasons

    result.data = {"listings": listings, "rejected_zones": rejected_zones}

    for label, reasons in listings.items():
        fresh_only = label == "SEM FRESH"
        severity = "low" if fresh_only else ("critical" if len(listings) > 1 else "high")
        result.add(
            "blocklist.fresh" if fresh_only else "blocklist.listed",
            severity,
            f"listed on {label}: {', '.join(reasons)}",
            {"zone": label, "reasons": reasons},
        )

    if rejected_zones:
        result.add(
            "blocklist.query_rejected", "info",
            f"{', '.join(sorted(set(rejected_zones)))} refused the query — public resolvers "
            "(8.8.8.8, 1.1.1.1) are blocked by these lists. Use your ISP/local resolver "
            "or --nameserver for meaningful results.",
            {"zones": sorted(set(rejected_zones))},
        )

    if not listings and not rejected_zones:
        result.add("blocklist.clean", "info", "not on any queried blocklist")
    return result
