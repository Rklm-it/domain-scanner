"""Archive.org history — the recycled-domain detector.

The pattern that burns media buyers: a domain shows a recent registration date,
but archive.org has snapshots going back years. That means it was used before,
dropped, and re-registered. Whatever reputation the previous owner earned is
attached to the name, not to your registration.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from datetime import datetime, timezone

from ..models import CheckResult
from ..utils import days_between
from .base import ScanContext, register

CDX_URL = "http://web.archive.org/cdx/search/cdx"
SNAPSHOT_URL = "https://web.archive.org/web/{timestamp}/{url}"
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Titles that mean "parked", not "a real previous business".
PARKED_TITLE_HINTS = (
    "domain is for sale", "buy this domain", "parked", "domain for sale",
    "under construction", "coming soon", "default web page", "index of /",
    "apache2", "nginx", "welcome to nginx", "future home",
)

SUSPECT_TITLE_HINTS = (
    "casino", "poker", "slots", "bet", "gambling", "porn", "xxx", "escort",
    "viagra", "cialis", "pharmacy", "pills", "replica", "essay writing",
    "payday", "loan", "crypto", "bitcoin", "forex", "binary option",
    "hacked", "warez", "torrent", "streaming free", "watch free",
)


def parse_ts(value: str) -> float | None:
    try:
        return datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(
            tzinfo=timezone.utc
        ).timestamp()
    except (ValueError, TypeError):
        return None


def fetch_cdx(ctx: ScanContext) -> list[list[str]]:
    params = {
        "url": f"{ctx.domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "collapse": "timestamp:6",  # at most one row per month
        "filter": "mimetype:text/html",
        "limit": "3000",
    }
    resp = ctx.session.get(CDX_URL, params=params, timeout=max(20.0, ctx.config.http_timeout))
    resp.raise_for_status()
    if not resp.text.strip():
        return []
    rows = resp.json()
    return rows[1:] if rows else []


def snapshot_title(ctx: ScanContext, timestamp: str) -> str | None:
    """Fetch one archived page and pull its <title>. ``id_`` = raw, no toolbar."""
    url = SNAPSHOT_URL.format(timestamp=f"{timestamp}id_", url=f"http://{ctx.domain}/")
    try:
        resp = ctx.session.get(url, timeout=max(20.0, ctx.config.http_timeout))
        if resp.status_code >= 400:
            return None
        match = TITLE_RE.search(resp.text[:200_000])
    except Exception:  # noqa: BLE001
        return None
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:160] or None


def classify_title(title: str | None) -> str:
    if not title:
        return "unknown"
    low = title.lower()
    if any(h in low for h in PARKED_TITLE_HINTS):
        return "parked"
    if any(h in low for h in SUSPECT_TITLE_HINTS):
        return "suspect"
    return "content"


@register("wayback", order=25, description="archive.org history / recycled-domain detection")
def check_wayback(ctx: ScanContext) -> CheckResult:
    """Look for a prior life the current registration does not account for."""
    result = CheckResult(name="wayback")
    rows = fetch_cdx(ctx)
    now = time.time()

    if not rows:
        result.data = {"snapshots": 0}
        result.add("wayback.no_history", "info",
                   "в archive.org пусто — на домене раньше ничего не публиковали")
        return result

    stamps = [r[0] for r in rows if r and r[0]]
    times = [t for t in (parse_ts(s) for s in stamps) if t]
    if not times:
        return result.fail("could not parse CDX timestamps")

    first_ts, last_ts = min(times), max(times)
    years = sorted({datetime.fromtimestamp(t, timezone.utc).year for t in times})
    status_counts = Counter(r[2] for r in rows if len(r) > 2)

    result.data = {
        "snapshots": len(rows),
        "first_seen": first_ts,
        "first_seen_date": datetime.fromtimestamp(first_ts, timezone.utc).strftime("%Y-%m-%d"),
        "last_seen_date": datetime.fromtimestamp(last_ts, timezone.utc).strftime("%Y-%m-%d"),
        "years_covered": years,
        "span_days": days_between(last_ts, first_ts),
        "status_counts": dict(status_counts),
    }

    created = ctx.get("created_ts")
    gap_days = days_between(created, first_ts) if created else None
    result.data["history_before_registration_days"] = gap_days

    recycled = gap_days is not None and gap_days > ctx.config.recycle_gap_days
    result.data["recycled"] = bool(recycled)

    if recycled:
        # Inspect what used to be here: oldest snapshot plus the last one before
        # the current registration.
        pre_stamps = [s for s, t in zip(stamps, times) if t < (created or 0)]
        probes = []
        if pre_stamps:
            probes.append(min(pre_stamps))
            if len(pre_stamps) > 1 and max(pre_stamps) != min(pre_stamps):
                probes.append(max(pre_stamps))
        titles = []
        for stamp in probes[:2]:
            title = snapshot_title(ctx, stamp)
            if title:
                titles.append({"timestamp": stamp, "title": title,
                               "kind": classify_title(title)})
        result.data["previous_titles"] = titles

        kinds = {t["kind"] for t in titles}
        years_txt = f"{years[0]}–{years[-1]}" if len(years) > 1 else str(years[0])
        if "suspect" in kinds:
            sample = next(t for t in titles if t["kind"] == "suspect")
            result.add(
                "wayback.recycled_suspect", "critical",
                f"домен перерегистрирован, а в прошлой жизни был в палёной вертикали "
                f"({years_txt}): «{sample['title']}»",
                {"gap_days": gap_days, "titles": titles},
            )
        elif kinds == {"parked"}:
            result.add(
                "wayback.recycled_parked", "medium",
                f"домен перерегистрирован, раньше на нём была только парковка ({years_txt}) — "
                f"история старше текущей регистрации на {gap_days} дн.",
                {"gap_days": gap_days, "titles": titles},
            )
        else:
            result.add(
                "wayback.recycled", "high",
                f"домен перерегистрирован: в archive.org есть контент за {years_txt}, "
                f"это на {gap_days} дн. раньше текущей регистрации",
                {"gap_days": gap_days, "titles": titles},
            )
    else:
        age_days = days_between(now, first_ts)
        if len(rows) >= 20 and age_days > 730:
            result.add("wayback.long_history", "info",
                       f"{len(rows)} снимков в архиве с {result.data['first_seen_date']} — "
                       "история ровная")
        else:
            result.add("wayback.short_history", "info",
                       f"{len(rows)} снимков в архиве с {result.data['first_seen_date']}")

    # A history made almost entirely of redirects is a doorway-domain pattern.
    redirects = sum(v for k, v in status_counts.items() if k.startswith("3"))
    if len(rows) >= 10 and redirects / len(rows) > 0.6:
        result.add("wayback.mostly_redirects", "medium",
                   f"{redirects} из {len(rows)} снимков — редиректы. Домен в основном "
                   "использовали, чтобы перебрасывать трафик дальше",
                   {"redirects": redirects, "total": len(rows)})

    return result
