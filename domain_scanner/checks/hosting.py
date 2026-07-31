"""Hosting network: ASN/owner via Team Cymru DNS, plus reverse-IP neighbours."""

from __future__ import annotations

from ..models import CheckResult
from ..utils import dns_query_quiet, reverse_ip, unquote_txt
from .base import ScanContext, register

CDN_ASNS = {
    "13335": "Cloudflare",
    "16509": "AWS",
    "14618": "AWS",
    "15169": "Google",
    "396982": "Google Cloud",
    "8075": "Microsoft/Azure",
    "20940": "Akamai",
    "16625": "Akamai",
    "54113": "Fastly",
    "13414": "Twitter",
    "54994": "QuickPacket",
}

# Networks that repeatedly host abuse. A hit is a soft signal, not a verdict.
SUSPECT_ASN_NAMES = (
    "bulletproof", "offshore", "flokinet", "ddos-guard", "stark industries",
    "aeza", "chang way", "pq hosting", "mivocloud", "greenfloid", "hostkey",
    "vdsina", "ihor", "selectel", "timeweb", "cloud9", "alexhost", "hostinger",
    "shinjiru", "kaopu", "amarutu", "iomart",
)

HACKERTARGET_REVERSE = "https://api.hackertarget.com/reverseiplookup/"


def cymru_lookup(ctx: ScanContext, ip: str) -> dict:
    """Team Cymru's DNS interface: free, keyless, no rate limit worth worrying about."""
    origin = dns_query_quiet(ctx.resolver, f"{reverse_ip(ip)}.origin.asn.cymru.com", "TXT")
    if not origin:
        return {}
    parts = [p.strip() for p in unquote_txt(origin[0]).split("|")]
    if len(parts) < 3:
        return {}
    asn = parts[0].split()[0]
    info = {"asn": asn, "prefix": parts[1], "country": parts[2]}
    name = dns_query_quiet(ctx.resolver, f"AS{asn}.asn.cymru.com", "TXT")
    if name:
        name_parts = [p.strip() for p in unquote_txt(name[0]).split("|")]
        if len(name_parts) >= 5:
            info["as_name"] = name_parts[4]
    return info


def reverse_ip_neighbours(ctx: ScanContext, ip: str) -> list[str] | None:
    try:
        resp = ctx.session.get(
            HACKERTARGET_REVERSE, params={"q": ip}, timeout=ctx.config.http_timeout
        )
    except Exception:  # noqa: BLE001
        return None
    text = resp.text.strip()
    if resp.status_code >= 400 or not text or "error" in text.lower() or "API count exceeded" in text:
        return None
    return [line.strip() for line in text.splitlines() if line.strip()]


@register("hosting", order=30, description="ASN / hosting network and IP neighbourhood", transport="dns")
def check_hosting(ctx: ScanContext) -> CheckResult:
    """Identify who hosts the domain and who else lives on the same IP."""
    result = CheckResult(name="hosting")
    ips: list[str] = ctx.get("ips") or []
    if not ips:
        return result.skip("no A records to inspect")

    networks = []
    for ip in ips[:3]:
        info = cymru_lookup(ctx, ip)
        if info:
            info["ip"] = ip
            networks.append(info)

    result.data = {"ips": ips, "networks": networks}
    if not networks:
        return result.fail("Team Cymru ASN lookup returned nothing")

    asns = {n.get("asn") for n in networks}
    names = [n.get("as_name", "") for n in networks]
    behind_cdn = any(a in CDN_ASNS for a in asns if a)
    result.data["behind_cdn"] = behind_cdn
    result.data["cdn"] = sorted({CDN_ASNS[a] for a in asns if a in CDN_ASNS})
    ctx.set("behind_cdn", behind_cdn)

    for name in names:
        low = (name or "").lower()
        hit = next((s for s in SUSPECT_ASN_NAMES if s in low), None)
        if hit:
            result.add("hosting.suspect_network", "medium",
                       f"hosted on a network with a heavy abuse history ({name})",
                       {"as_name": name})
            break

    countries = {n.get("country") for n in networks if n.get("country")}
    result.data["countries"] = sorted(c for c in countries if c)

    if behind_cdn:
        result.add("hosting.behind_cdn", "info",
                   f"behind {', '.join(result.data['cdn'])} — origin network is hidden")
    else:
        # Only meaningful when the IP is the real origin.
        neighbours = (
            reverse_ip_neighbours(ctx, ips[0]) if ctx.config.http_available else None
        )
        if neighbours is not None:
            result.data["neighbour_count"] = len(neighbours)
            result.data["neighbours_sample"] = neighbours[:15]
            if len(neighbours) >= ctx.config.crowded_ip_domains:
                result.add("hosting.crowded_ip", "medium",
                           f"{len(neighbours)} other domains share {ips[0]} — bulk shared "
                           "hosting, so you inherit the neighbours' reputation",
                           {"count": len(neighbours), "ip": ips[0]})
            elif len(neighbours) > 1:
                result.add("hosting.shared_ip", "info",
                           f"{len(neighbours)} domains share {ips[0]}",
                           {"count": len(neighbours)})

    if not result.findings:
        as_label = names[0] if names else ", ".join(sorted(a for a in asns if a))
        result.add("hosting.ok", "info", f"hosted on {as_label}")
    return result
