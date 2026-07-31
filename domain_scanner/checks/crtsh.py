"""Certificate Transparency logs via crt.sh.

CT logs give a public, tamper-evident record of when a domain first had a
certificate issued — in practice, when it first went live. That date is much
harder to reset than a WHOIS record, and the subdomain list often exposes
infrastructure a previous owner left behind.
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timezone

from ..models import CheckResult
from ..utils import days_between
from .base import ScanContext, register

CRTSH_URL = "https://crt.sh/"


def parse_ct_time(value: str) -> float | None:
    if not value:
        return None
    text = value.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


@register("crtsh", order=28, description="Certificate Transparency history (crt.sh)")
def check_crtsh(ctx: ScanContext) -> CheckResult:
    """Pull the CT log history for the domain and all its subdomains."""
    result = CheckResult(name="crtsh")
    resp = ctx.session.get(
        CRTSH_URL,
        params={"q": f"%.{ctx.domain}", "output": "json", "exclude": "expired"},
        timeout=max(25.0, ctx.config.http_timeout),
    )
    if resp.status_code >= 400:
        return result.fail(f"crt.sh returned HTTP {resp.status_code}")
    text = resp.text.strip()
    if not text:
        result.data = {"certificates": 0}
        result.add("crtsh.none", "info", "no certificates in CT logs")
        return result
    try:
        entries = resp.json()
    except ValueError:
        return result.fail("crt.sh returned non-JSON (usually rate limiting)")

    if not entries:
        result.data = {"certificates": 0}
        result.add("crtsh.none", "low",
                   "no certificate in CT logs — the domain has never served HTTPS")
        return result

    names: set[str] = set()
    issuers: Counter[str] = Counter()
    times: list[float] = []
    for entry in entries:
        for name in (entry.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            if name:
                names.add(name)
        issuer = (entry.get("issuer_name") or "")
        if "O=" in issuer:
            issuer = issuer.split("O=", 1)[1].split(",")[0].strip('"')
        issuers[issuer or "unknown"] += 1
        ts = parse_ct_time(entry.get("not_before") or "")
        if ts:
            times.append(ts)

    if not times:
        return result.fail("no parsable not_before dates in CT entries")

    first_ts = min(times)
    subdomains = sorted(n for n in names if n.endswith(ctx.domain) and n != ctx.domain)
    now = time.time()

    result.data = {
        "certificates": len(entries),
        "first_cert": first_ts,
        "first_cert_date": datetime.fromtimestamp(first_ts, timezone.utc).strftime("%Y-%m-%d"),
        "days_since_first_cert": days_between(now, first_ts),
        "issuers": dict(issuers.most_common(5)),
        "subdomain_count": len(subdomains),
        "subdomains_sample": subdomains[:25],
    }

    created = ctx.get("created_ts")
    if created:
        gap = days_between(created, first_ts)
        result.data["cert_before_registration_days"] = gap
        if gap > ctx.config.recycle_gap_days:
            result.add(
                "crtsh.predates_registration", "high",
                f"certificates exist from {result.data['first_cert_date']}, {gap} days before "
                "the current registration — the domain was live under a previous owner",
                {"gap_days": gap},
            )

    days_live = result.data["days_since_first_cert"]
    if days_live <= 7:
        result.add("crtsh.just_went_live", "medium",
                   f"first certificate issued {days_live} days ago — the domain went live "
                   "this week", {"days": days_live})

    if len(subdomains) >= 40:
        result.add("crtsh.many_subdomains", "medium",
                   f"{len(subdomains)} distinct subdomains in CT logs — typical of a domain "
                   "used to spin up many landers",
                   {"count": len(subdomains), "sample": subdomains[:15]})

    if not result.findings:
        result.add("crtsh.ok", "info",
                   f"{len(entries)} certificates since {result.data['first_cert_date']}, "
                   f"{len(subdomains)} subdomains")
    return result
