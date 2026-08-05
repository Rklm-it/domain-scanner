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

HACKERTARGET_REVERSE = "https://api.hackertarget.com/reverseiplookup/"

# The free reverse-IP tier truncates. A result sitting exactly on a round
# number is a truncated list, not a count, and must not be reported as one.
LIKELY_TRUNCATION_POINTS = (100, 250, 500, 1000)

# There used to be a hand-written list of "abusive" hosting networks here, and
# a medium-severity finding fired off it. It was opinion with no measurement
# behind it -- on one real batch it was the sole reason three domains scored
# 22/WATCH. Who hosts a domain is now reported as fact at info level; whether
# a given network predicts trouble is for the calibration view to answer from
# recorded outcomes, not for this list to assert.


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


# Ahead of archive.org and crt.sh: the ASN and prefix this returns are what the
# cross-domain footprint analysis clusters on, so it has to survive a domain
# that runs long.
@register("hosting", order=23, description="ASN / hosting network and IP neighbourhood", transport="dns")
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

    countries = {n.get("country") for n in networks if n.get("country")}
    result.data["countries"] = sorted(c for c in countries if c)

    if behind_cdn:
        result.add("hosting.behind_cdn", "info",
                   f"за {', '.join(result.data['cdn'])} — реальный хостинг скрыт")
    else:
        # Only meaningful when the IP is the real origin.
        neighbours = (
            reverse_ip_neighbours(ctx, ips[0]) if ctx.config.http_available else None
        )
        if neighbours is not None:
            count = len(neighbours)
            truncated = count in LIKELY_TRUNCATION_POINTS
            shown = f"{count}+" if truncated else str(count)
            result.data["neighbour_count"] = count
            result.data["neighbour_count_truncated"] = truncated
            result.data["neighbours_sample"] = neighbours[:15]
            if count >= ctx.config.crowded_ip_domains:
                note = " (столько отдал бесплатный лимит API, реально может быть больше)" \
                    if truncated else ""
                result.add("hosting.crowded_ip", "medium",
                           f"на {ips[0]} сидит ещё {shown} доменов{note} — массовый "
                           "шаред-хостинг, репутация соседей переходит на тебя",
                           {"count": count, "truncated": truncated, "ip": ips[0]})
            elif count > 1:
                result.add("hosting.shared_ip", "info",
                           f"на {ips[0]} сидит доменов: {shown}",
                           {"count": count, "truncated": truncated})

    # Who hosts it, stated as fact and weighted at zero.
    as_label = names[0] if names else ", ".join(sorted(a for a in asns if a))
    if as_label:
        result.add("hosting.network", "info", f"хостится в {as_label}",
                   {"as_name": as_label, "asns": sorted(a for a in asns if a)})
    return result
