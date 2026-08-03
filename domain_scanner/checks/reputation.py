"""Keyed reputation APIs: Google Safe Browsing and VirusTotal.

Safe Browsing is the one list here that is unambiguously Google's own view of
the domain. A hit means Google has already made a decision about it.
"""

from __future__ import annotations

from ..models import CheckResult
from ..utils import RateLimiter
from .base import ScanContext, register

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# VirusTotal's public tier allows 4 requests per minute.
_vt_limiter = RateLimiter(calls=4, period=60.0)


@register("safebrowsing", order=22, description="Google Safe Browsing v4",
          requires=("safe_browsing_key",))
def check_safe_browsing(ctx: ScanContext) -> CheckResult:
    """Ask Google directly whether it considers the domain harmful."""
    result = CheckResult(name="safebrowsing")
    urls = [f"http://{ctx.domain}/", f"https://{ctx.domain}/", f"http://www.{ctx.domain}/"]
    payload = {
        "client": {"clientId": "domain-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    resp = ctx.session.post(
        SAFE_BROWSING_URL,
        params={"key": ctx.config.safe_browsing_key},
        json=payload,
        timeout=ctx.config.http_timeout,
    )
    if resp.status_code == 400:
        return result.fail("Safe Browsing rejected the request (check the API key)")
    if resp.status_code == 403:
        return result.fail("Safe Browsing returned 403 — key invalid or API not enabled")
    resp.raise_for_status()
    matches = resp.json().get("matches", []) or []
    threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    result.data = {"matches": len(matches), "threat_types": threats}

    if matches:
        result.add("safebrowsing.flagged", "critical",
                   f"Google Safe Browsing помечает домен: {', '.join(threats)}",
                   {"threat_types": threats})
    else:
        result.add("safebrowsing.clean", "info", "в Google Safe Browsing чисто")
    return result


@register("virustotal", order=24, description="VirusTotal domain reputation",
          requires=("virustotal_key",))
def check_virustotal(ctx: ScanContext) -> CheckResult:
    """Aggregate ~90 security vendors' verdicts on the domain."""
    result = CheckResult(name="virustotal")
    _vt_limiter.acquire()
    resp = ctx.session.get(
        VT_URL.format(domain=ctx.domain),
        headers={"x-apikey": ctx.config.virustotal_key},
        timeout=ctx.config.http_timeout,
    )
    if resp.status_code == 404:
        result.data = {"known": False}
        result.add("virustotal.unknown", "info", "в VirusTotal домена нет")
        return result
    if resp.status_code == 401:
        return result.fail("VirusTotal rejected the API key")
    if resp.status_code == 429:
        return result.fail("VirusTotal rate limit reached")
    resp.raise_for_status()

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    reputation = int(attrs.get("reputation", 0) or 0)
    categories = attrs.get("categories", {}) or {}
    votes = attrs.get("total_votes", {}) or {}

    result.data = {
        "known": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": int(stats.get("harmless", 0)),
        "reputation": reputation,
        "categories": categories,
        "votes": votes,
        "created": attrs.get("creation_date"),
    }

    if malicious >= 3:
        result.add("virustotal.malicious", "critical",
                   f"{malicious} антивирусных вендоров считают домен вредоносным",
                   {"malicious": malicious, "categories": categories})
    elif malicious >= 1:
        result.add("virustotal.some_detections", "high",
                   f"домен помечен вендорами: {malicious}",
                   {"malicious": malicious})
    elif suspicious >= 2:
        result.add("virustotal.suspicious", "medium",
                   f"{suspicious} вендоров считают домен подозрительным")

    if reputation <= -10:
        result.add("virustotal.bad_reputation", "medium",
                   f"репутация по оценкам сообщества: {reputation}", {"reputation": reputation})

    flagged_cats = {
        k: v for k, v in categories.items()
        if any(w in str(v).lower() for w in
               ("malicious", "phishing", "spam", "suspicious", "gambling", "adult"))
    }
    if flagged_cats:
        result.data["flagged_categories"] = flagged_cats
        result.add("virustotal.category", "low",
                   f"категории: {', '.join(sorted(set(flagged_cats.values())))}",
                   {"categories": flagged_cats})

    if not [f for f in result.findings if (f.weight or 0) > 0]:
        result.add("virustotal.clean", "info",
                   f"чисто у всех вендоров ({sum(stats.values())})")
    return result
