"""DNS records: resolution, nameservers, mail and email-auth footprint."""

from __future__ import annotations

from ..models import CheckResult
from ..utils import dns_query, dns_query_quiet, unquote_txt
from .base import ScanContext, register


@register("dns", order=10, description="DNS records, nameservers, mail setup", transport="dns")
def check_dns(ctx: ScanContext) -> CheckResult:
    """Resolve the domain and inspect its DNS footprint."""
    result = CheckResult(name="dns")
    r = ctx.resolver
    domain = ctx.domain

    a_records = dns_query_quiet(r, domain, "A")
    aaaa_records = dns_query_quiet(r, domain, "AAAA")
    try:
        ns_records = [n.rstrip(".").lower() for n in dns_query(r, domain, "NS")]
    except Exception as exc:
        return result.fail(f"NS lookup failed: {type(exc).__name__}")
    mx_records = [m.split()[-1].rstrip(".").lower() for m in dns_query_quiet(r, domain, "MX")]
    txt_records = [unquote_txt(t) for t in dns_query_quiet(r, domain, "TXT")]
    dmarc = [unquote_txt(t) for t in dns_query_quiet(r, f"_dmarc.{domain}", "TXT")]

    ips = sorted(set(a_records))
    ns_base = sorted({".".join(n.split(".")[-2:]) for n in ns_records})
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]

    result.data = {
        "a": ips,
        "aaaa": sorted(set(aaaa_records)),
        "ns": sorted(ns_records),
        "ns_provider": ns_base,
        "mx": sorted(set(mx_records)),
        "txt": txt_records,
        "spf": spf,
        "dmarc": dmarc,
        "resolves": bool(ips or aaaa_records),
    }
    ctx.set("ips", ips)
    ctx.set("ns", ns_records)

    if not ns_records:
        result.add("dns.no_ns", "high", "у домена нет NS-серверов — он не делегирован")
        return result

    if not ips and not aaaa_records:
        result.add("dns.no_address", "high",
                   "домен делегирован, но A-записи нет — на нём ничего не размещено")

    parking = [
        p for p in ctx.config.registrars.get("parking_ns", [])
        if any(p in n for n in ns_records)
    ]
    if parking:
        result.add("dns.parked", "high",
                   f"NS-серверы принадлежат парковочному сервису ({parking[0]})",
                   {"ns": ns_records})

    free_host = [
        p for p in ctx.config.registrars.get("free_hosting_ns", [])
        if any(p in n for n in ns_records)
    ]
    if free_host:
        result.add("dns.free_hosting", "medium",
                   f"NS-серверы указывают на бесплатный хостинг ({free_host[0]})", {"ns": ns_records})

    if len(ns_records) == 1:
        result.add("dns.single_ns", "low",
                   "всего один NS-сервер — для настоящего бизнеса нетипично")

    if not mx_records:
        result.add("dns.no_mx", "low",
                   "нет MX-записи — на домене не настроена почта. По этому признаку "
                   "отличают работающий бизнес от чистого ленда")
    if not spf:
        result.add("dns.no_spf", "info", "нет SPF-записи")
    if not dmarc:
        result.add("dns.no_dmarc", "info", "нет DMARC-записи")

    # A domain with mail, SPF and DMARC configured reads as an operating business.
    if mx_records and spf and dmarc:
        result.add("dns.business_email", "info",
                   "MX, SPF и DMARC на месте — похоже на работающий бизнес")

    return result
