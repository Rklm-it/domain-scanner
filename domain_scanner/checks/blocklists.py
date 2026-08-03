"""DNS-based domain blocklists (DBL/URIBL style).

These are the same lists mail and security vendors consult. A hit does not
prove Google knows about the domain, but a domain that is already on public
blocklists is one that has been used for something before.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from ..config import env_str
from ..models import CheckResult
from ..utils import dns_query_quiet
from .base import ScanContext, register


@dataclass(frozen=True)
class Zone:
    """One blocklist, and how to reach it.

    ``key_env`` names an environment variable holding a subscriber key. The
    free public zones of Spamhaus and URIBL refuse queries from large public
    resolvers, which is most cloud hosts by default; a key routes the query
    through the provider's subscriber service instead, where it is answered
    reliably. Both offer a free tier.
    """

    label: str
    zone: str
    codes: dict[str, str]
    # Host that must resolve inside this zone whenever the zone is answering
    # us. Without it there is no way to tell "not listed" from "not allowed
    # to ask" -- Spamhaus answers the latter with NXDOMAIN, which is
    # byte-for-byte what a clean domain looks like.
    test_point: str | None = None
    key_env: str | None = None
    keyed_zone: str | None = None

    def resolve_zone(self) -> tuple[str, bool]:
        """Return (zone to query, whether a subscriber key is in use)."""
        if self.key_env and self.keyed_zone:
            key = env_str(self.key_env)
            if key:
                return self.keyed_zone.format(key=key), True
        return self.zone, False


ZONES: tuple[Zone, ...] = (
    Zone(
        label="Spamhaus DBL",
        zone="dbl.spamhaus.org",
        # Free DQS key: https://www.spamhaus.com/free-trial/
        key_env="SPAMHAUS_DQS_KEY",
        keyed_zone="{key}.dbl.dq.spamhaus.net",
        test_point="dbltest.com",
        codes={
            "127.0.1.2": "спам",
            "127.0.1.4": "фишинг",
            "127.0.1.5": "малварь",
            "127.0.1.6": "управляющий сервер ботнета",
            "127.0.1.102": "взломанный легальный, спам",
            "127.0.1.103": "взломанный редиректор",
            "127.0.1.104": "взломанный легальный, фишинг",
            "127.0.1.105": "взломанный легальный, малварь",
            "127.0.1.106": "взломанный легальный, ботнет",
        },
    ),
    Zone(
        label="SURBL",
        zone="multi.surbl.org",
        test_point="test.surbl.org",
        codes={
            "127.0.0.8": "фишинг (PH)",
            "127.0.0.16": "малварь (MW)",
            "127.0.0.64": "абуз (ABUSE)",
            "127.0.0.128": "взломан (CR)",
        },
    ),
    Zone(
        label="URIBL",
        zone="multi.uribl.com",
        key_env="URIBL_KEY",
        keyed_zone="{key}.multi.uribl.com",
        test_point="test.uribl.com",
        codes={
            "127.0.0.2": "чёрный список",
            "127.0.0.4": "серый список",
            "127.0.0.8": "красный список",
        },
    ),
    Zone(label="SEM URIBL", zone="uribl.spameatingmonkey.net",
         codes={"127.0.0.2": "числится"}),
    Zone(label="SEM FRESH", zone="fresh.spameatingmonkey.net",
         codes={"127.0.0.2": "зарегистрирован на днях"}),
)

# Zone availability depends on the resolver, not on the domain being scanned,
# so it is probed once and cached for the whole batch.
_ZONE_HEALTH_TTL = 600.0
_zone_health: dict[str, tuple[bool, float]] = {}
_zone_lock = threading.Lock()

# Codes that mean "your query was rejected", not "listed".
#
# These must be matched exactly, never by prefix: 127.0.0.14 is a perfectly
# valid URIBL answer (black+grey+red = 2+4+8) and startswith("127.0.0.1")
# would swallow it, along with everything from .10 to .19.
ERROR_CODES = {"127.0.0.1", "127.0.0.255"}
ERROR_PREFIXES = ("127.255.255.",)
BLOCKED_CODES = ERROR_CODES


def zone_is_answering(ctx: ScanContext, zone: Zone) -> bool | None:
    """Is this blocklist replying to us at all?

    Returns None when the zone publishes no test point we can use.
    """
    if not zone.test_point:
        return None
    query_zone, _keyed = zone.resolve_zone()
    now = time.monotonic()
    with _zone_lock:
        cached = _zone_health.get(query_zone)
        if cached and now - cached[1] < _ZONE_HEALTH_TTL:
            return cached[0]
    answers = dns_query_quiet(ctx.resolver, f"{zone.test_point}.{query_zone}", "A")
    healthy = bool(answers) and not any(
        a in ERROR_CODES or a.startswith(ERROR_PREFIXES) for a in answers
    )
    with _zone_lock:
        _zone_health[query_zone] = (healthy, now)
    return healthy


def reset_zone_health_cache() -> None:
    with _zone_lock:
        _zone_health.clear()


def _decode(zone: Zone, answers: list[str]) -> tuple[list[str], bool]:
    """Return (reasons, query_rejected)."""
    reasons: list[str] = []
    rejected = False
    for ans in answers:
        if ans in ERROR_CODES or ans.startswith(ERROR_PREFIXES):
            rejected = True
            continue
        if ans in zone.codes:
            reasons.append(zone.codes[ans])
        else:
            # SURBL packs multiple bits into the last octet.
            if zone.label == "SURBL":
                try:
                    bits = int(ans.rsplit(".", 1)[-1])
                except ValueError:
                    bits = 0
                for code, meaning in zone.codes.items():
                    if bits & int(code.rsplit(".", 1)[-1]):
                        reasons.append(meaning)
            if not reasons:
                reasons.append(f"числится ({ans})")
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

    keyed: list[str] = []

    for zone in ZONES:
        health = zone_is_answering(ctx, zone)
        if health is False:
            unavailable.append(zone.label)
            continue
        (verified if health else opportunistic).append(zone.label)
        query_zone, using_key = zone.resolve_zone()
        if using_key:
            keyed.append(zone.label)
        answers = dns_query_quiet(ctx.resolver, f"{ctx.domain}.{query_zone}", "A")
        if not answers:
            continue
        reasons, rejected = _decode(zone, answers)
        if rejected:
            rejected_zones.append(zone.label)
        if reasons:
            listings[zone.label] = reasons

    result.data = {
        "listings": listings,
        "rejected_zones": rejected_zones,
        "unavailable_zones": unavailable,
        "zones_verified": verified,
        "zones_opportunistic": opportunistic,
        "zones_using_key": keyed,
    }

    for label, reasons in listings.items():
        fresh_only = label == "SEM FRESH"
        severity = "low" if fresh_only else ("critical" if len(listings) > 1 else "high")
        result.add(
            "blocklist.fresh" if fresh_only else "blocklist.listed",
            severity,
            f"числится в {label}: {', '.join(reasons)}",
            {"zone": label, "reasons": reasons},
        )

    stale = sorted(set(rejected_zones) | set(unavailable))
    if stale:
        result.add(
            "blocklist.unavailable", "info",
            f"нет ответа от {', '.join(stale)} — эти списки не отвечают публичным резолверам "
            "(8.8.8.8, 1.1.1.1). Нужен либо свой рекурсивный резолвер в SCANNER_NAMESERVER, "
            "либо бесплатный ключ (SPAMHAUS_DQS_KEY / URIBL_KEY). Пока их нет, эти списки "
            "не опрашиваются вообще.",
            {"zones": stale},
        )

    if not listings:
        if verified:
            result.add("blocklist.clean", "info",
                       f"не числится в {', '.join(verified)}")
        else:
            # No zone was confirmed to be answering. Saying "clean" here would
            # mean "we did not look".
            result.add("blocklist.no_data", "info",
                       "ни один блоклист не подтвердил, что отвечает — по спискам домен "
                       "фактически не проверялся")
    return result
