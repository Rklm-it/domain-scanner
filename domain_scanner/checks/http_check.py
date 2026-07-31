"""Live HTTP behaviour of the landing page.

Everything here maps to something Google's automated review actually looks at:
does the destination load, does it redirect off-domain, does it carry the trust
pages a real business has, and does it serve the crawler the same page it
serves a user.
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from ..models import CheckResult
from ..utils import (
    USER_AGENTS,
    BlockedTargetError,
    assert_public_host,
    days_between,
    parse_domain,
)
from .base import ScanContext, register

class TooManyRedirects(Exception):
    """The redirect chain never settled."""


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)
LINK_RE = re.compile(r"""<a\b[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""",
                     re.IGNORECASE | re.DOTALL)
TAG_STRIP_RE = re.compile(r"<(script|style)\b.*?</\1>|<[^>]+>", re.IGNORECASE | re.DOTALL)
JS_REDIRECT_RE = re.compile(
    r"(?:window\.)?location(?:\.href|\.replace\(|\s*=)\s*['\"]?(https?://[^'\"\s)]+)",
    re.IGNORECASE,
)

# Trust pages, in the languages a buyer is likely to be running.
POLICY_PATTERNS = {
    "privacy": ("privacy", "конфиденциальн", "приватност", "datenschutz", "privacidad",
                "confidentialit", "privacidade", "gizlilik", "prywatno"),
    "terms": ("terms", "tos", "условия", "соглашение", "agb", "nutzungsbedingungen",
              "terminos", "términos", "conditions", "regulamin", "kullanim"),
    "contact": ("contact", "контакт", "связаться", "kontakt", "contacto", "contato",
                "iletisim", "impressum"),
    "about": ("about", "о нас", "о компании", "uber-uns", "über uns", "sobre", "acerca",
              "hakkimizda", "o-nas"),
    "refund": ("refund", "return", "возврат", "widerruf", "reembolso", "zwrot"),
}

TRACKER_PATTERNS = {
    "google_ads": (r"googleadservices\.com", r"gtag/js\?id=AW-", r"AW-\d{9,}"),
    "google_analytics": (r"google-analytics\.com", r"gtag/js\?id=G-", r"G-[A-Z0-9]{8,}"),
    "gtm": (r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]{4,}"),
    "facebook": (r"connect\.facebook\.net", r"fbq\("),
    "tiktok": (r"analytics\.tiktok\.com",),
}

ID_RE = {
    "google_ads": re.compile(r"AW-\d{9,}"),
    "google_analytics": re.compile(r"G-[A-Z0-9]{8,10}"),
    "gtm": re.compile(r"GTM-[A-Z0-9]{4,8}"),
    "facebook": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,})['\"]"),
}


def visible_text(html: str) -> str:
    return re.sub(r"\s+", " ", TAG_STRIP_RE.sub(" ", html)).strip()


def content_fingerprint(html: str) -> str:
    """Hash of visible text only, so cache-busters and nonces do not create noise."""
    text = visible_text(html).lower()
    text = re.sub(r"\d", "", text)
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]


def tls_info(host: str, timeout: float) -> dict:
    ctx_ssl = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx_ssl.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    not_after = cert.get("notAfter")
    expires = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            ).timestamp()
        except ValueError:
            expires = None
    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "expires": expires,
        "subject_alt_names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
    }


def fetch(ctx: ScanContext, url: str, ua: str) -> dict:
    """Fetch a URL, validating every redirect hop.

    Redirects are followed by hand rather than by requests, so a destination
    cannot bounce the scanner onto a private address. That matters as soon as
    this runs anywhere with an instance-metadata endpoint.
    """
    headers = {"User-Agent": USER_AGENTS[ua]}
    chain: list[str] = []
    current = url
    resp = None

    for _hop in range(ctx.config.max_redirects + 1):
        if ctx.config.block_private_targets:
            host = urlparse(current).hostname or ""
            try:
                assert_public_host(host)
            except BlockedTargetError as exc:
                raise BlockedTargetError(f"refusing to fetch {current}: {exc}") from exc
        chain.append(current)
        resp = ctx.session.get(
            current,
            headers=headers,
            timeout=ctx.config.http_timeout,
            allow_redirects=False,
        )
        if resp.status_code not in (301, 302, 303, 307, 308):
            break
        location = resp.headers.get("Location")
        if not location:
            break
        current = urljoin(current, location)
    else:
        raise TooManyRedirects(f"more than {ctx.config.max_redirects} redirects from {url}")

    body = resp.text if "text" in resp.headers.get("Content-Type", "text/html") else ""
    return {
        "status": resp.status_code,
        "final_url": chain[-1],
        "chain": chain,
        "headers": dict(resp.headers),
        "body": body,
        "length": len(body),
        "fingerprint": content_fingerprint(body),
    }


def find_policy_pages(html: str, base_url: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for href, label in LINK_RE.findall(html):
        haystack = f"{href} {visible_text(label)}".lower()
        for kind, patterns in POLICY_PATTERNS.items():
            if kind in found:
                continue
            if any(p in haystack for p in patterns):
                found[kind] = urljoin(base_url, href)
    return found


def detect_trackers(html: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, patterns in TRACKER_PATTERNS.items():
        if any(re.search(p, html, re.IGNORECASE) for p in patterns):
            ids = []
            id_re = ID_RE.get(name)
            if id_re:
                ids = sorted(set(m if isinstance(m, str) else m[0]
                                 for m in id_re.findall(html)))[:5]
            out[name] = ids
    return out


@register("http", order=40, description="Live page: reachability, redirects, trust pages, cloaking")
def check_http(ctx: ScanContext) -> CheckResult:
    """Fetch the landing page the way a user and the way Google would."""
    result = CheckResult(name="http")
    data: dict = {}

    https_error = None
    try:
        primary = fetch(ctx, f"https://{ctx.domain}/", "browser")
    except Exception as exc:  # noqa: BLE001
        https_error = f"{type(exc).__name__}: {exc}"
        try:
            primary = fetch(ctx, f"http://{ctx.domain}/", "browser")
        except Exception as exc2:  # noqa: BLE001
            result.data = {"https_error": https_error, "http_error": str(exc2)}
            result.add("http.unreachable", "critical",
                       f"the site does not load over HTTPS or HTTP ({https_error})")
            return result
        result.add("http.no_https", "high",
                   f"HTTPS fails ({https_error}) — Google Ads will not run traffic to a "
                   "destination without working TLS")
    data["https_error"] = https_error

    body = primary["body"]
    data.update({
        "status": primary["status"],
        "final_url": primary["final_url"],
        "redirect_chain": primary["chain"],
        "content_length": primary["length"],
        "server": primary["headers"].get("Server"),
        "fingerprint": primary["fingerprint"],
    })

    title_match = TITLE_RE.search(body[:200_000])
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:160] if title_match else None
    data["title"] = title
    ctx.set("fingerprint", primary["fingerprint"])

    if primary["status"] >= 500:
        result.add("http.server_error", "critical",
                   f"server error: HTTP {primary['status']}")
    elif primary["status"] >= 400:
        result.add("http.client_error", "critical",
                   f"the page returns HTTP {primary['status']} — a broken destination "
                   "is an automatic policy problem")

    # --- redirects off the advertised domain ---
    try:
        final_domain = parse_domain(primary["final_url"])[0]
    except Exception:  # noqa: BLE001
        final_domain = None
    data["final_domain"] = final_domain
    if final_domain and final_domain != ctx.domain:
        result.add("http.offsite_redirect", "high",
                   f"redirects to a different domain ({final_domain}) — the advertised "
                   "domain and the destination must match",
                   {"final": final_domain, "chain": primary["chain"]})
    if len(primary["chain"]) > 4:
        result.add("http.long_redirect_chain", "low",
                   f"{len(primary['chain']) - 1} redirects before the page loads",
                   {"chain": primary["chain"]})

    meta_refresh = META_REFRESH_RE.search(body[:100_000])
    js_redirect = JS_REDIRECT_RE.search(body[:200_000])
    if meta_refresh:
        data["meta_refresh"] = meta_refresh.group(1)[:200]
        result.add("http.meta_refresh", "medium",
                   "page uses a meta-refresh redirect", {"content": data["meta_refresh"]})
    if js_redirect:
        target = js_redirect.group(1)
        try:
            target_domain = parse_domain(target)[0]
        except Exception:  # noqa: BLE001
            target_domain = None
        data["js_redirect"] = target[:200]
        if target_domain and target_domain != ctx.domain:
            result.add("http.js_offsite_redirect", "high",
                       f"JavaScript redirects users to {target_domain}",
                       {"target": target[:200]})

    # --- thin content ---
    text_len = len(visible_text(body))
    data["visible_text_length"] = text_len
    if primary["status"] < 400:
        if text_len < 200:
            result.add("http.thin_content", "high",
                       f"almost no visible text ({text_len} chars) — reads as a blank or "
                       "placeholder page")
        elif text_len < 800:
            result.add("http.light_content", "low",
                       f"very little content ({text_len} chars of visible text)")

    if not title:
        result.add("http.no_title", "low", "page has no <title>")

    # --- trust pages ---
    policies = find_policy_pages(body, primary["final_url"])
    data["policy_pages"] = policies
    missing = [k for k in ("privacy", "terms", "contact") if k not in policies]
    if primary["status"] < 400:
        if len(missing) == 3:
            result.add("http.no_trust_pages", "high",
                       "no privacy policy, terms or contact page — the exact gap that "
                       "sends an account into business verification",
                       {"missing": missing})
        elif missing:
            result.add("http.missing_trust_pages", "medium",
                       f"missing trust pages: {', '.join(missing)}", {"missing": missing})

    # --- ad/analytics tags (used later for cross-domain footprint linking) ---
    trackers = detect_trackers(body)
    data["trackers"] = trackers
    ctx.set("trackers", trackers)

    # --- TLS ---
    if https_error is None:
        try:
            tls = tls_info(ctx.domain, ctx.config.http_timeout)
            data["tls"] = {
                "issuer": tls["issuer"],
                "expires_in_days": days_between(tls["expires"], time.time())
                if tls["expires"] else None,
                "san_count": len(tls["subject_alt_names"]),
            }
            if tls["expires"] and tls["expires"] < time.time():
                result.add("http.tls_expired", "critical", "TLS certificate has expired")
            if len(tls["subject_alt_names"]) > 50:
                result.add("http.shared_cert", "low",
                           f"certificate covers {len(tls['subject_alt_names'])} hostnames — "
                           "a shared hosting certificate",
                           {"san_count": len(tls["subject_alt_names"])})
        except Exception as exc:  # noqa: BLE001
            data["tls_error"] = f"{type(exc).__name__}: {exc}"

    result.data = data
    if not [f for f in result.findings if (f.weight or 0) > 0]:
        result.add("http.ok", "info",
                   f"loads over HTTPS ({primary['status']}), "
                   f"{len(policies)} trust pages found")
    return result


@register("cloaking", order=45,
          description="Does the page serve Google something different from a user?")
def check_cloaking(ctx: ScanContext) -> CheckResult:
    """Compare the page as served to a browser, to Googlebot and to AdsBot.

    Serving different content to Google's crawlers than to users is what
    triggers automated review. This check tells you whether your destination
    looks consistent from the outside — run it on your own domains before you
    scale spend on them.
    """
    result = CheckResult(name="cloaking")
    baseline_fp = ctx.get("fingerprint")
    if baseline_fp is None:
        return result.skip("http check did not produce a baseline")

    variants: dict[str, dict] = {}
    for ua in ("googlebot", "adsbot", "mobile"):
        try:
            resp = fetch(ctx, f"https://{ctx.domain}/", ua)
        except Exception as exc:  # noqa: BLE001
            variants[ua] = {"error": f"{type(exc).__name__}: {exc}"}
            continue
        variants[ua] = {
            "status": resp["status"],
            "fingerprint": resp["fingerprint"],
            "length": resp["length"],
            "final_url": resp["final_url"],
        }

    baseline_len = ctx.get("baseline_length") or 0
    result.data = {"baseline_fingerprint": baseline_fp, "variants": variants}

    for ua, info in variants.items():
        if "error" in info:
            if ua in ("googlebot", "adsbot"):
                result.add(f"cloaking.{ua}_blocked", "high",
                           f"the site fails to respond to the {ua} user-agent "
                           f"({info['error']}) — Google cannot crawl the destination",
                           {"ua": ua})
            continue
        if ua == "mobile":
            continue
        if info["status"] >= 400:
            result.add(f"cloaking.{ua}_error", "high",
                       f"returns HTTP {info['status']} to {ua} but loads for a browser",
                       {"ua": ua, "status": info["status"]})
        elif info["fingerprint"] != baseline_fp:
            result.add("cloaking.content_differs", "high",
                       f"serves different content to {ua} than to a browser — this is the "
                       "pattern automated review flags",
                       {"ua": ua, "browser_fp": baseline_fp, "crawler_fp": info["fingerprint"]})

    if not [f for f in result.findings if (f.weight or 0) > 0]:
        result.add("cloaking.consistent", "info",
                   "browser, Googlebot and AdsBot all receive the same page")
    return result
