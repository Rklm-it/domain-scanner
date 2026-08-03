"""Registration data (RDAP, the machine-readable successor to WHOIS).

Domain age is the single strongest predictor here: a domain registered days
before it starts spending is exactly the pattern automated review looks for.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from ..models import CheckResult
from ..utils import days_between, human_days
from .base import ScanContext, register

RDAP_ENDPOINTS = [
    "https://rdap.org/domain/{domain}",
    "https://rdap.verisign.com/com/v1/domain/{domain}",
]

# RDAP EPP statuses that mean the registry/registrar has acted against the domain.
BAD_STATUSES = {
    "client hold": "critical",
    "server hold": "critical",
    "pending delete": "high",
    "redemption period": "high",
    "client suspended": "critical",
    "inactive": "medium",
}


def parse_rdap_time(value: str) -> float | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d"):
        try:
            if fmt is None:
                dt = datetime.fromisoformat(text)
            else:
                dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def extract_registrar(payload: dict) -> str | None:
    for entity in payload.get("entities", []) or []:
        roles = [r.lower() for r in entity.get("roles", []) or []]
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    return str(item[3])
        if entity.get("handle"):
            return str(entity["handle"])
    return None


def extract_events(payload: dict) -> dict[str, float]:
    events: dict[str, float] = {}
    for event in payload.get("events", []) or []:
        action = (event.get("eventAction") or "").lower()
        ts = parse_rdap_time(event.get("eventDate") or "")
        if action and ts:
            events[action] = ts
    return events


def fetch_rdap(ctx: ScanContext) -> dict | None:
    last_error: Exception | None = None
    for template in RDAP_ENDPOINTS:
        url = template.format(domain=ctx.domain)
        try:
            resp = ctx.session.get(
                url,
                timeout=ctx.config.http_timeout,
                headers={"Accept": "application/rdap+json"},
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
        if resp.status_code == 404:
            return {"_not_found": True}
        if resp.status_code >= 400:
            last_error = RuntimeError(f"HTTP {resp.status_code}")
            continue
        try:
            return resp.json()
        except ValueError as exc:
            last_error = exc
    if last_error:
        raise last_error
    return None


@register("rdap", order=15, description="Registration date, registrar, expiry, EPP status")
def check_rdap(ctx: ScanContext) -> CheckResult:
    """Look up registration data over RDAP."""
    result = CheckResult(name="rdap")
    payload = fetch_rdap(ctx)
    if payload is None:
        return result.fail("no RDAP endpoint answered")
    if payload.get("_not_found"):
        result.data = {"registered": False}
        result.add("rdap.not_registered", "info",
                   "нет записи RDAP — домен либо не зарегистрирован, либо у зоны нет RDAP")
        return result

    events = extract_events(payload)
    registrar = extract_registrar(payload)
    statuses = [s.lower() for s in payload.get("status", []) or []]
    now = time.time()

    created = events.get("registration")
    expires = events.get("expiration")
    changed = events.get("last changed") or events.get("last update of rdap database")

    age_days = days_between(now, created) if created else None
    expires_in = days_between(expires, now) if expires else None

    result.data = {
        "registered": True,
        "registrar": registrar,
        "created": created,
        "expires": expires,
        "last_changed": changed,
        "age_days": age_days,
        "expires_in_days": expires_in,
        "statuses": statuses,
        "nameservers": [
            (ns.get("ldhName") or "").lower()
            for ns in payload.get("nameservers", []) or []
        ],
    }
    ctx.set("created_ts", created)
    ctx.set("age_days", age_days)

    if age_days is None:
        result.add("rdap.no_created_date", "info", "реестр не отдал дату регистрации")
    elif age_days <= ctx.config.fresh_domain_days:
        result.add("rdap.brand_new", "high",
                   f"зарегистрирован {age_days} дн. назад — совсем свежий",
                   {"age_days": age_days})
    elif age_days <= ctx.config.young_domain_days:
        result.add("rdap.young", "medium",
                   f"зарегистрирован {human_days(age_days)} назад — ещё молодой",
                   {"age_days": age_days})
    elif age_days <= ctx.config.established_domain_days:
        result.add("rdap.under_a_year", "low",
                   f"зарегистрирован {human_days(age_days)} назад — меньше года",
                   {"age_days": age_days})
    else:
        result.add("rdap.established", "info",
                   f"зарегистрирован {human_days(age_days)} назад", {"age_days": age_days})

    if expires_in is not None:
        if expires_in < 0:
            result.add("rdap.expired", "critical",
                       f"регистрация истекла {abs(expires_in)} дн. назад")
        elif expires_in <= ctx.config.expiry_soon_days:
            result.add("rdap.expiring_soon", "medium",
                       f"регистрация кончается через {expires_in} дн. — если домен отвалится посреди "
                       "залива, ляжет не только сайт, но и аккаунт",
                       {"expires_in_days": expires_in})
        if created and expires:
            term_days = days_between(expires, created)
            result.data["term_days"] = term_days
            if term_days <= 400 and (age_days or 0) < 400:
                result.add("rdap.one_year_term", "low",
                           "оплачен ровно на год — так берут одноразовые домены")

    for status in statuses:
        severity = BAD_STATUSES.get(status)
        if severity:
            result.add("rdap.bad_status", severity,
                       f"статус в реестре: {status}", {"status": status})

    if registrar:
        low = registrar.lower()
        hits = [r for r in ctx.config.registrars.get("high_abuse", []) if r in low]
        if hits:
            result.add("rdap.abused_registrar", "low",
                       f"регистратор ({registrar}) часто светится в абуз-отчётах",
                       {"registrar": registrar})
    return result
