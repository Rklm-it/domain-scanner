import time

import pytest
from conftest import FakeRdata, FakeResolver, FakeResponse, FakeSession, redirect_to

from domain_scanner.checks.blocklists import (
    ZONES,
    check_blocklists,
    reset_zone_health_cache,
    zone_is_answering,
)
from domain_scanner.checks.crtsh import check_crtsh
from domain_scanner.checks.dns_check import check_dns
from domain_scanner.checks.hosting import check_hosting
from domain_scanner.checks.http_check import (
    check_cloaking,
    check_http,
    content_fingerprint,
    detect_trackers,
    find_policy_pages,
)
from domain_scanner.checks.naming import check_naming, looks_random
from domain_scanner.checks.rdap import check_rdap, parse_rdap_time
from domain_scanner.checks.reputation import check_safe_browsing, check_virustotal
from domain_scanner.checks.tld import check_tld, tier_for
from domain_scanner.checks.wayback import check_wayback

DAY = 86400


def codes(result):
    return {f.code for f in result.findings}


# --------------------------------------------------------------------------- tld


def test_tier_lookup(config):
    assert tier_for("com", config.tld_risk) == 0
    assert tier_for("top", config.tld_risk) == 3
    assert tier_for("online", config.tld_risk) == 2
    # Unknown multi-label suffix falls back to its last label.
    assert tier_for("shop.example", config.tld_risk) == config.tld_risk["default_tier"]


def test_tld_flags_high_abuse(ctx_factory):
    result = check_tld(ctx_factory("lander.top"))
    assert "tld.high_abuse" in codes(result)
    assert result.risk_points > 0


def test_tld_clean_for_com(ctx_factory):
    result = check_tld(ctx_factory("example.com"))
    assert result.risk_points == 0


# ------------------------------------------------------------------------ naming


def test_looks_random():
    assert looks_random("x7kqpzvvbb")
    assert not looks_random("bestcoffee")


def test_naming_flags_brand_lookalike(ctx_factory):
    result = check_naming(ctx_factory("paypal-secure-login.top"))
    assert "naming.brand_lookalike" in codes(result)
    assert "naming.spammy_words" in codes(result)


def test_naming_flags_typosquat(ctx_factory):
    result = check_naming(ctx_factory("binnance.com"))
    assert "naming.typosquat" in codes(result)


def test_naming_clean_domain(ctx_factory):
    result = check_naming(ctx_factory("northwindcoffee.com"))
    assert result.risk_points == 0


def test_naming_counts_hyphens(ctx_factory):
    result = check_naming(ctx_factory("get-the-best-deal.xyz"))
    assert "naming.many_hyphens" in codes(result)


# --------------------------------------------------------------------------- dns


def test_dns_collects_records(ctx_factory):
    resolver = FakeResolver({
        ("example.com", "A"): ["93.184.216.34"],
        ("example.com", "NS"): ["ns1.example-dns.com.", "ns2.example-dns.com."],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"'],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none"'],
    })
    ctx = ctx_factory(resolver=resolver)
    result = check_dns(ctx)
    assert result.status == "ok"
    assert result.data["a"] == ["93.184.216.34"]
    assert result.data["ns_provider"] == ["example-dns.com"]
    assert "dns.business_email" in codes(result)
    assert ctx.get("ips") == ["93.184.216.34"]


def test_dns_flags_parked_nameservers(ctx_factory):
    resolver = FakeResolver({
        ("example.com", "NS"): ["ns1.sedoparking.com."],
        ("example.com", "A"): ["1.2.3.4"],
    })
    result = check_dns(ctx_factory(resolver=resolver))
    assert "dns.parked" in codes(result)
    assert "dns.no_mx" in codes(result)


def test_dns_no_nameservers(ctx_factory):
    result = check_dns(ctx_factory(resolver=FakeResolver({})))
    assert "dns.no_ns" in codes(result)


# -------------------------------------------------------------------- blocklists


HEALTHY_ZONES = {
    ("dbltest.com.dbl.spamhaus.org", "A"): ["127.0.1.2"],
    ("test.surbl.org.multi.surbl.org", "A"): ["127.0.0.254"],
    ("test.uribl.com.multi.uribl.com", "A"): ["127.0.0.2"],
}


@pytest.fixture(autouse=True)
def _clear_zone_cache():
    reset_zone_health_cache()
    yield
    reset_zone_health_cache()


def test_blocklists_decodes_spamhaus(ctx_factory):
    resolver = FakeResolver({
        **HEALTHY_ZONES,
        ("example.com.dbl.spamhaus.org", "A"): ["127.0.1.4"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "blocklist.listed" in codes(result)
    assert result.data["listings"]["Spamhaus DBL"] == ["фишинг"]


def test_blocklists_multiple_hits_are_critical(ctx_factory):
    resolver = FakeResolver({
        **HEALTHY_ZONES,
        ("example.com.dbl.spamhaus.org", "A"): ["127.0.1.2"],
        ("example.com.multi.uribl.com", "A"): ["127.0.0.2"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert any(f.severity == "critical" for f in result.findings)


def test_blocklists_clean(ctx_factory):
    """Clean only counts when the zones actually answered."""
    result = check_blocklists(ctx_factory(resolver=FakeResolver(dict(HEALTHY_ZONES))))
    assert "blocklist.clean" in codes(result)
    assert set(result.data["zones_verified"]) == {"Spamhaus DBL", "SURBL", "URIBL"}


def test_blocklists_silent_zone_is_not_reported_clean(ctx_factory):
    """Spamhaus answers NXDOMAIN to unauthorised resolvers.

    That is indistinguishable from "not listed", so a zone whose test point
    does not resolve must be reported as unchecked, never as clean.
    """
    resolver = FakeResolver({})  # nothing answers, not even the test points
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "blocklist.clean" not in codes(result)
    assert "blocklist.no_data" in codes(result)
    assert "blocklist.unavailable" in codes(result)
    assert result.data["zones_verified"] == []


def test_blocklists_partial_availability(ctx_factory):
    """One dead zone must not stop the others being consulted."""
    resolver = FakeResolver({
        ("test.uribl.com.multi.uribl.com", "A"): ["127.0.0.2"],
        ("example.com.multi.uribl.com", "A"): ["127.0.0.2"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert result.data["zones_verified"] == ["URIBL"]
    assert "Spamhaus DBL" in result.data["unavailable_zones"]
    assert "blocklist.listed" in codes(result)


def _zone(label):
    return next(z for z in ZONES if z.label == label)


def test_zone_health_is_cached(ctx_factory):
    resolver = FakeResolver(dict(HEALTHY_ZONES))
    ctx = ctx_factory(resolver=resolver)
    spamhaus = _zone("Spamhaus DBL")
    assert zone_is_answering(ctx, spamhaus) is True
    before = len(resolver.queries)
    assert zone_is_answering(ctx, spamhaus) is True
    assert len(resolver.queries) == before  # served from cache


def test_subscriber_key_switches_to_the_dqs_zone(ctx_factory, monkeypatch):
    """A free DQS key is the supported way past the public-resolver block."""
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "secretkey")
    resolver = FakeResolver({
        ("dbltest.com.secretkey.dbl.dq.spamhaus.net", "A"): ["127.0.1.2"],
        ("example.com.secretkey.dbl.dq.spamhaus.net", "A"): ["127.0.1.4"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "Spamhaus DBL" in result.data["zones_using_key"]
    assert result.data["listings"]["Spamhaus DBL"] == ["фишинг"]


def test_no_key_uses_the_public_zone(ctx_factory, monkeypatch):
    monkeypatch.delenv("SPAMHAUS_DQS_KEY", raising=False)
    resolver = FakeResolver(dict(HEALTHY_ZONES))
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert result.data["zones_using_key"] == []
    assert "Spamhaus DBL" in result.data["zones_verified"]


def test_uribl_key_is_supported(ctx_factory, monkeypatch):
    monkeypatch.setenv("URIBL_KEY", "abc123")
    resolver = FakeResolver({
        ("test.uribl.com.abc123.multi.uribl.com", "A"): ["127.0.0.2"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "URIBL" in result.data["zones_using_key"]
    assert "URIBL" in result.data["zones_verified"]


def test_zone_without_test_point_is_queried_but_does_not_prove_clean(ctx_factory):
    """A hit still counts; silence from such a zone does not mean clean."""
    resolver = FakeResolver({
        ("example.com.uribl.spameatingmonkey.net", "A"): ["127.0.0.2"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "SEM URIBL" in result.data["zones_opportunistic"]
    assert "blocklist.listed" in codes(result)

    # Same zone, nothing listed and no verified zone -> not "clean".
    reset_zone_health_cache()
    quiet = check_blocklists(ctx_factory(resolver=FakeResolver({})))
    assert "blocklist.clean" not in codes(quiet)


# -------------------------------------------------------------------------- rdap


def test_parse_rdap_time():
    assert parse_rdap_time("2020-01-02T03:04:05Z") > 0
    assert parse_rdap_time("2020-01-02") > 0
    assert parse_rdap_time("") is None


def rdap_payload(created_days_ago=800, expires_in_days=400, statuses=None,
                 registrar="Example Registrar, Inc."):
    now = time.time()
    return {
        "objectClassName": "domain",
        "status": statuses or ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration",
             "eventDate": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(now - created_days_ago * DAY))},
            {"eventAction": "expiration",
             "eventDate": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(now + expires_in_days * DAY))},
        ],
        "entities": [
            {"roles": ["registrar"],
             "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                      ["fn", {}, "text", registrar]]]},
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
    }


def test_rdap_established_domain(ctx_factory):
    session = FakeSession({"rdap": FakeResponse(json_data=rdap_payload())})
    ctx = ctx_factory(session=session)
    result = check_rdap(ctx)
    assert result.status == "ok"
    assert "rdap.established" in codes(result)
    assert result.risk_points == 0
    assert ctx.get("age_days") == 800


def test_rdap_brand_new_domain(ctx_factory):
    session = FakeSession({
        "rdap": FakeResponse(json_data=rdap_payload(created_days_ago=5, expires_in_days=360)),
    })
    result = check_rdap(ctx_factory(session=session))
    assert "rdap.brand_new" in codes(result)
    assert "rdap.one_year_term" in codes(result)


def test_rdap_client_hold_is_critical(ctx_factory):
    payload = rdap_payload(statuses=["client hold"])
    session = FakeSession({"rdap": FakeResponse(json_data=payload)})
    result = check_rdap(ctx_factory(session=session))
    assert any(f.severity == "critical" for f in result.findings)


def test_rdap_expiring_soon(ctx_factory):
    session = FakeSession({"rdap": FakeResponse(json_data=rdap_payload(expires_in_days=10))})
    result = check_rdap(ctx_factory(session=session))
    assert "rdap.expiring_soon" in codes(result)


def test_rdap_not_found(ctx_factory):
    session = FakeSession({"rdap": FakeResponse(status_code=404)})
    result = check_rdap(ctx_factory(session=session))
    assert "rdap.not_registered" in codes(result)


# ----------------------------------------------------------------------- wayback


def cdx_rows(years, status="200"):
    return [["timestamp", "original", "statuscode", "mimetype", "digest"]] + [
        [f"{y}0601120000", f"http://example.com/", status, "text/html", f"D{y}"]
        for y in years
    ]


def test_wayback_detects_recycled_domain(ctx_factory):
    created = time.time() - 60 * DAY
    session = FakeSession({
        "cdx": FakeResponse(json_data=cdx_rows([2013, 2014, 2015, 2016])),
        "web.archive.org/web/": FakeResponse(
            text="<html><head><title>Lucky Star Casino - Play Slots</title></head></html>"
        ),
    })
    ctx = ctx_factory(session=session, shared={"created_ts": created})
    result = check_wayback(ctx)
    assert result.data["recycled"] is True
    assert "wayback.recycled_suspect" in codes(result)
    assert any(f.severity == "critical" for f in result.findings)


def test_wayback_recycled_but_only_parked(ctx_factory):
    created = time.time() - 60 * DAY
    session = FakeSession({
        "cdx": FakeResponse(json_data=cdx_rows([2015, 2016])),
        "web.archive.org/web/": FakeResponse(
            text="<title>This domain is for sale</title>"
        ),
    })
    result = check_wayback(ctx_factory(session=session, shared={"created_ts": created}))
    assert "wayback.recycled_parked" in codes(result)


def test_wayback_no_history(ctx_factory):
    session = FakeSession({"cdx": FakeResponse(json_data=[], text="")})
    result = check_wayback(ctx_factory(session=session))
    assert "wayback.no_history" in codes(result)
    assert result.risk_points == 0


def test_wayback_mostly_redirects(ctx_factory):
    created = time.time() - 8000 * DAY  # predates the archive history -> not recycled
    rows = cdx_rows(list(range(2005, 2020)), status="301")
    session = FakeSession({"cdx": FakeResponse(json_data=rows)})
    result = check_wayback(ctx_factory(session=session, shared={"created_ts": created}))
    assert result.data["recycled"] is False
    assert "wayback.mostly_redirects" in codes(result)


# ------------------------------------------------------------------------- crtsh


def test_crtsh_detects_certs_before_registration(ctx_factory):
    created = time.time() - 30 * DAY
    entries = [
        {"name_value": "example.com\nwww.example.com", "not_before": "2016-05-01T00:00:00",
         "issuer_name": "C=US, O=Let's Encrypt, CN=R3"},
        {"name_value": "example.com", "not_before": "2026-01-01T00:00:00",
         "issuer_name": "C=US, O=Let's Encrypt, CN=R3"},
    ]
    session = FakeSession({"crt.sh": FakeResponse(json_data=entries, text="[...]")})
    result = check_crtsh(ctx_factory(session=session, shared={"created_ts": created}))
    assert "crtsh.predates_registration" in codes(result)


def test_crtsh_many_subdomains(ctx_factory):
    entries = [
        {"name_value": f"lp{i}.example.com", "not_before": "2024-01-01T00:00:00",
         "issuer_name": "O=Let's Encrypt"}
        for i in range(50)
    ]
    session = FakeSession({"crt.sh": FakeResponse(json_data=entries, text="[...]")})
    result = check_crtsh(ctx_factory(session=session))
    assert "crtsh.many_subdomains" in codes(result)


def test_crtsh_no_certificates(ctx_factory):
    session = FakeSession({"crt.sh": FakeResponse(json_data=[], text="[]")})
    result = check_crtsh(ctx_factory(session=session))
    assert "crtsh.none" in codes(result)


# ----------------------------------------------------------------------- hosting


def test_hosting_identifies_asn(ctx_factory):
    resolver = FakeResolver({
        ("4.3.2.1.origin.asn.cymru.com", "TXT"): ['"13335 | 1.2.3.0/24 | US | arin | 2011-08-11"'],
        ("AS13335.asn.cymru.com", "TXT"): ['"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"'],
    })
    result = check_hosting(ctx_factory(resolver=resolver, shared={"ips": ["1.2.3.4"]}))
    assert result.data["behind_cdn"] is True
    assert "hosting.behind_cdn" in codes(result)


def test_hosting_flags_crowded_ip(ctx_factory):
    resolver = FakeResolver({
        ("4.3.2.1.origin.asn.cymru.com", "TXT"): ['"64500 | 1.2.3.0/24 | NL | ripe | 2015-01-01"'],
        ("AS64500.asn.cymru.com", "TXT"): ['"64500 | NL | ripe | 2015-01-01 | SOME-HOST, NL"'],
    })
    neighbours = "\n".join(f"site{i}.com" for i in range(300))
    session = FakeSession({"hackertarget": FakeResponse(text=neighbours)})
    result = check_hosting(
        ctx_factory(resolver=resolver, session=session, shared={"ips": ["1.2.3.4"]})
    )
    assert "hosting.crowded_ip" in codes(result)
    assert result.data["neighbour_count"] == 300


def test_hosting_skips_without_ips(ctx_factory):
    result = check_hosting(ctx_factory(shared={"ips": []}))
    assert result.status == "skipped"


# -------------------------------------------------------------------------- http


GOOD_PAGE = """
<html><head><title>Northwind Coffee</title></head><body>
<h1>Fresh roasted coffee delivered</h1>
<p>%s</p>
<a href="/privacy-policy">Privacy Policy</a>
<a href="/terms">Terms of Service</a>
<a href="/contact">Contact us</a>
<script src="https://www.googletagmanager.com/gtag/js?id=AW-123456789"></script>
</body></html>
""" % ("We roast in small batches every morning. " * 40)


def test_find_policy_pages():
    found = find_policy_pages(GOOD_PAGE, "https://example.com/")
    assert set(found) >= {"privacy", "terms", "contact"}
    assert found["privacy"] == "https://example.com/privacy-policy"


def test_find_policy_pages_russian():
    html = '<a href="/pol">Политика конфиденциальности</a><a href="/c">Контакты</a>'
    found = find_policy_pages(html, "https://example.com/")
    assert "privacy" in found and "contact" in found


def test_detect_trackers():
    trackers = detect_trackers(GOOD_PAGE)
    assert "google_ads" in trackers
    assert "AW-123456789" in trackers["google_ads"]


def test_content_fingerprint_ignores_digits():
    a = content_fingerprint("<p>order 12345</p>")
    b = content_fingerprint("<p>order 98765</p>")
    assert a == b


def test_http_healthy_page(ctx_factory):
    session = FakeSession({
        "https://example.com": FakeResponse(text=GOOD_PAGE, url="https://example.com/"),
    })
    ctx = ctx_factory(session=session)
    result = check_http(ctx)
    assert result.status == "ok"
    assert result.risk_points == 0
    assert result.data["title"] == "Northwind Coffee"
    assert set(result.data["policy_pages"]) >= {"privacy", "terms", "contact"}


def test_http_missing_trust_pages(ctx_factory):
    page = "<html><head><title>LP</title></head><body>%s</body></html>" % ("buy now " * 200)
    session = FakeSession({"https://example.com": FakeResponse(text=page,
                                                               url="https://example.com/")})
    result = check_http(ctx_factory(session=session))
    assert "http.no_trust_pages" in codes(result)


def test_http_offsite_redirect(ctx_factory):
    session = FakeSession({
        "https://example.com": redirect_to("https://other-place.net/offer"),
        "https://other-place.net": FakeResponse(text=GOOD_PAGE),
    })
    result = check_http(ctx_factory(session=session))
    assert "http.offsite_redirect" in codes(result)
    assert result.data["final_domain"] == "other-place.net"
    assert result.data["redirect_chain"] == [
        "https://example.com/", "https://other-place.net/offer",
    ]


def test_http_follows_relative_redirect(ctx_factory):
    calls = {"n": 0}

    def route(url, **kwargs):
        calls["n"] += 1
        if url.endswith("/lp/"):
            return FakeResponse(text=GOOD_PAGE)
        return redirect_to("/lp/")

    session = FakeSession({"https://example.com": route})
    result = check_http(ctx_factory(session=session))
    assert result.data["final_url"] == "https://example.com/lp/"
    assert result.risk_points == 0


def test_http_stops_on_redirect_loop(ctx_factory, config):
    config.max_redirects = 3
    session = FakeSession({"https://example.com": redirect_to("https://example.com/x"),
                           "http://example.com": redirect_to("http://example.com/x")})
    result = check_http(ctx_factory(session=session, cfg=config))
    assert "http.unreachable" in codes(result)


def test_http_refuses_private_targets(ctx_factory, config):
    """A domain resolving to a private address must never be fetched."""
    config.block_private_targets = True
    session = FakeSession({"https://localhost": FakeResponse(text=GOOD_PAGE)})
    ctx = ctx_factory("localhost.localdomain", session=session, cfg=config)
    ctx.domain = "localhost"
    result = check_http(ctx)
    assert "http.unreachable" in codes(result)
    assert session.calls == []  # never left the process


def test_http_404_is_critical(ctx_factory):
    session = FakeSession({
        "https://example.com": FakeResponse(status_code=404, text="not found",
                                            url="https://example.com/"),
    })
    result = check_http(ctx_factory(session=session))
    assert "http.client_error" in codes(result)
    assert any(f.severity == "critical" for f in result.findings)


def test_http_unreachable(ctx_factory):
    result = check_http(ctx_factory(session=FakeSession({})))
    assert "http.unreachable" in codes(result)


def test_http_thin_content(ctx_factory):
    session = FakeSession({
        "https://example.com": FakeResponse(text="<html><title>x</title><body></body></html>",
                                            url="https://example.com/"),
    })
    result = check_http(ctx_factory(session=session))
    assert "http.thin_content" in codes(result)


def test_http_js_offsite_redirect(ctx_factory):
    page = "<html><title>t</title><body><script>window.location='https://elsewhere.io/go'" \
           "</script>%s</body></html>" % ("text " * 300)
    session = FakeSession({"https://example.com": FakeResponse(text=page,
                                                               url="https://example.com/")})
    result = check_http(ctx_factory(session=session))
    assert "http.js_offsite_redirect" in codes(result)


# ---------------------------------------------------------------------- cloaking


def test_cloaking_detects_different_content(ctx_factory):
    crawler_page = "<html><title>Nothing here</title><body>hello</body></html>"

    def route(url, **kwargs):
        ua = kwargs.get("headers", {}).get("User-Agent", "")
        if "Googlebot" in ua or "AdsBot" in ua:
            return FakeResponse(text=crawler_page, url="https://example.com/")
        return FakeResponse(text=GOOD_PAGE, url="https://example.com/")

    session = FakeSession({"https://example.com": route})
    ctx = ctx_factory(session=session)
    check_http(ctx)
    result = check_cloaking(ctx)
    assert "cloaking.content_differs" in codes(result)


def test_cloaking_consistent(ctx_factory):
    session = FakeSession({
        "https://example.com": FakeResponse(text=GOOD_PAGE, url="https://example.com/"),
    })
    ctx = ctx_factory(session=session)
    check_http(ctx)
    result = check_cloaking(ctx)
    assert "cloaking.consistent" in codes(result)
    assert result.risk_points == 0


def test_cloaking_skipped_without_baseline(ctx_factory):
    result = check_cloaking(ctx_factory())
    assert result.status == "skipped"


# -------------------------------------------------------------------- reputation


def test_safe_browsing_flagged(ctx_factory, config):
    config.safe_browsing_key = "test-key"
    session = FakeSession({
        "safebrowsing": FakeResponse(json_data={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}),
    })
    result = check_safe_browsing(ctx_factory(session=session, cfg=config))
    assert "safebrowsing.flagged" in codes(result)
    assert any(f.severity == "critical" for f in result.findings)


def test_safe_browsing_clean(ctx_factory, config):
    config.safe_browsing_key = "test-key"
    session = FakeSession({"safebrowsing": FakeResponse(json_data={})})
    result = check_safe_browsing(ctx_factory(session=session, cfg=config))
    assert result.risk_points == 0


def test_virustotal_malicious(ctx_factory, config):
    config.virustotal_key = "test-key"
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60},
        "reputation": -25,
        "categories": {"Forcepoint": "phishing and other frauds"},
    }}}
    session = FakeSession({"virustotal": FakeResponse(json_data=payload)})
    result = check_virustotal(ctx_factory(session=session, cfg=config))
    assert "virustotal.malicious" in codes(result)
    assert "virustotal.bad_reputation" in codes(result)


def test_virustotal_unknown_domain(ctx_factory, config):
    config.virustotal_key = "test-key"
    session = FakeSession({"virustotal": FakeResponse(status_code=404)})
    result = check_virustotal(ctx_factory(session=session, cfg=config))
    assert "virustotal.unknown" in codes(result)
    assert result.risk_points == 0


def test_naming_does_not_flag_official_brand_domain(ctx_factory):
    result = check_naming(ctx_factory("google.com"))
    assert "naming.brand_lookalike" not in codes(result)
    assert "naming.official_brand" in codes(result)
    assert result.risk_points == 0


def test_naming_flags_brand_on_wrong_tld(ctx_factory):
    result = check_naming(ctx_factory("google.top"))
    assert "naming.brand_lookalike" in codes(result)


def test_blocklist_error_codes_match_exactly_not_by_prefix(ctx_factory):
    """127.0.0.14 is a valid URIBL answer, not an error.

    Matching error codes by prefix would treat every 127.0.0.1x reply as a
    rejected query and silently drop real listings.
    """
    resolver = FakeResolver({
        ("test.uribl.com.multi.uribl.com", "A"): ["127.0.0.14"],
        ("example.com.multi.uribl.com", "A"): ["127.0.0.14"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "URIBL" in result.data["zones_verified"]
    assert "URIBL" not in result.data["unavailable_zones"]
    assert "blocklist.listed" in codes(result)


def test_blocklist_real_error_code_is_still_rejected(ctx_factory):
    resolver = FakeResolver({
        ("test.uribl.com.multi.uribl.com", "A"): ["127.0.0.1"],
    })
    result = check_blocklists(ctx_factory(resolver=resolver))
    assert "URIBL" in result.data["unavailable_zones"]


# ------------------------------------------------ дефолтные NS и ротация IP


def test_dns_flags_default_hosting_nameservers(ctx_factory):
    """Домен на стоковых NS хостинга — его никто не настраивал."""
    resolver = FakeResolver({
        ("example.com", "NS"): ["ns1.dns-parking.com.", "ns2.dns-parking.com."],
        ("example.com", "A"): ["1.2.3.4"],
    })
    result = check_dns(ctx_factory(resolver=resolver))
    assert "dns.default_hosting_ns" in codes(result)
    # Это не то же самое, что «домен продаётся».
    assert "dns.parked" not in codes(result)


def test_dns_parking_wins_over_default_ns(ctx_factory):
    resolver = FakeResolver({
        ("example.com", "NS"): ["ns1.sedoparking.com."],
        ("example.com", "A"): ["1.2.3.4"],
    })
    result = check_dns(ctx_factory(resolver=resolver))
    assert "dns.parked" in codes(result)
    assert "dns.default_hosting_ns" not in codes(result)


class RotatingResolver(FakeResolver):
    """Отдаёт разные A-записи на каждый запрос, как дешёвый хостинг."""

    def __init__(self, pools):
        super().__init__({})
        self.pools = list(pools)
        self.calls = 0

    def resolve(self, name, rdtype, tcp=False):
        self.queries.append((name, rdtype))
        if rdtype.upper() == "A" and name.lower().rstrip(".") == "example.com":
            pool = self.pools[min(self.calls, len(self.pools) - 1)]
            self.calls += 1
            return [FakeRdata(v) for v in pool]
        if rdtype.upper() == "NS":
            return [FakeRdata("ns1.example-dns.com.")]
        import dns.resolver
        raise dns.resolver.NXDOMAIN()


def test_dns_detects_rotating_addresses(ctx_factory):
    """Два запроса подряд дают разные адреса — сравнивать по IP нельзя."""
    resolver = RotatingResolver([["1.1.1.1", "2.2.2.2"], ["3.3.3.3", "4.4.4.4"]])
    result = check_dns(ctx_factory(resolver=resolver))
    assert result.data["rotating_ips"] is True
    assert "dns.rotating_ips" in codes(result)
    # Собраны адреса из обоих ответов, а не только из первого.
    assert set(result.data["a"]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}


def test_dns_stable_addresses_are_not_flagged(ctx_factory):
    resolver = RotatingResolver([["1.1.1.1"], ["1.1.1.1"]])
    result = check_dns(ctx_factory(resolver=resolver))
    assert result.data["rotating_ips"] is False
    assert "dns.rotating_ips" not in codes(result)


# ------------------------------------------------------- хостинг: без мнений


def test_hosting_states_the_network_without_judging_it(ctx_factory):
    """Кто хостит — факт с нулевым весом, а не обвинение."""
    resolver = FakeResolver({
        ("4.3.2.1.origin.asn.cymru.com", "TXT"): ['"47583 | 1.2.3.0/24 | CY | ripe | 2015-01-01"'],
        ("AS47583.asn.cymru.com", "TXT"):
            ['"47583 | CY | ripe | 2008-01-01 | AS-HOSTINGER - Hostinger International Limited, CY"'],
    })
    result = check_hosting(ctx_factory(resolver=resolver, shared={"ips": ["1.2.3.4"]}))
    assert "hosting.network" in codes(result)
    assert result.risk_points == 0, "хостинг сам по себе не должен двигать оценку"


def test_hosting_reports_truncated_neighbour_count_honestly(ctx_factory):
    """Ровно 500 от бесплатного API — это обрезка, а не количество."""
    resolver = FakeResolver({
        ("4.3.2.1.origin.asn.cymru.com", "TXT"): ['"64500 | 1.2.3.0/24 | NL | ripe | 2015-01-01"'],
        ("AS64500.asn.cymru.com", "TXT"): ['"64500 | NL | ripe | 2015-01-01 | SOME-HOST, NL"'],
    })
    session = FakeSession({"hackertarget": FakeResponse(
        text="\n".join(f"site{i}.com" for i in range(500)))})
    result = check_hosting(
        ctx_factory(resolver=resolver, session=session, shared={"ips": ["1.2.3.4"]})
    )
    assert result.data["neighbour_count_truncated"] is True
    msg = next(f.message for f in result.findings if f.code == "hosting.crowded_ip")
    assert "500+" in msg and "лимит API" in msg


def test_hosting_exact_count_is_not_marked_truncated(ctx_factory):
    resolver = FakeResolver({
        ("4.3.2.1.origin.asn.cymru.com", "TXT"): ['"64500 | 1.2.3.0/24 | NL | ripe | 2015-01-01"'],
        ("AS64500.asn.cymru.com", "TXT"): ['"64500 | NL | ripe | 2015-01-01 | SOME-HOST, NL"'],
    })
    session = FakeSession({"hackertarget": FakeResponse(
        text="\n".join(f"site{i}.com" for i in range(347)))})
    result = check_hosting(
        ctx_factory(resolver=resolver, session=session, shared={"ips": ["1.2.3.4"]})
    )
    assert result.data["neighbour_count_truncated"] is False
    msg = next(f.message for f in result.findings if f.code == "hosting.crowded_ip")
    assert "347" in msg and "+" not in msg


# ------------------------------------------------- бюджет времени на домен


def test_scan_domain_skips_checks_once_the_budget_is_spent(monkeypatch, config):
    """Checks run one after another, so one stalled endpoint eats the domain.

    When the budget is gone the rest are skipped and reported as skipped, so a
    slow domain comes back with partial results instead of holding the scan.
    """
    import domain_scanner.scanner as scanner
    from domain_scanner.checks.base import Check
    from domain_scanner.models import CheckResult

    clock = {"now": 0.0}
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock["now"])

    def quick(_ctx):
        return CheckResult(name="quick")

    def slow(_ctx):
        clock["now"] += 500.0  # burns the whole budget
        return CheckResult(name="slow")

    monkeypatch.setattr(scanner, "all_checks", lambda: [
        Check("slow", slow, 1, "", transport="none"),
        Check("quick", quick, 2, "", transport="none"),
    ])
    monkeypatch.setattr(scanner, "make_resolver", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "make_session", lambda *a, **k: type(
        "S", (), {"close": lambda self: None})())

    config.domain_budget = 120.0
    report = scanner.scan_domain("example.com", config)

    ran, skipped = report.check("slow"), report.check("quick")
    assert ran.status == "ok"
    assert skipped.status == "skipped"
    assert skipped.skip_kind == "timeout"
    # And the gap is visible in the report rather than passed off as coverage.
    assert report.unavailable_checks == ["quick"]


def test_scan_domain_runs_everything_when_there_is_time(monkeypatch, config):
    import domain_scanner.scanner as scanner
    from domain_scanner.checks.base import Check
    from domain_scanner.models import CheckResult

    monkeypatch.setattr(scanner, "all_checks", lambda: [
        Check(name, lambda _c, n=name: CheckResult(name=n), i, "", transport="none")
        for i, name in enumerate(("a", "b", "c"))
    ])
    monkeypatch.setattr(scanner, "make_resolver", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "make_session", lambda *a, **k: type(
        "S", (), {"close": lambda self: None})())

    report = scanner.scan_domain("example.com", config)
    assert [c.status for c in report.checks] == ["ok", "ok", "ok"]
    assert report.unavailable_checks == []


def test_http_and_hosting_run_before_the_slow_archive_lookups():
    """Ordering is what makes the budget safe to hit.

    If archive.org and crt.sh went first, a domain that ran long would lose the
    page fetch — the check that carries most of the verdict.
    """
    from domain_scanner.checks import all_checks

    order = [c.name for c in all_checks()]
    for slow in ("wayback", "crtsh"):
        assert order.index("http") < order.index(slow)
        assert order.index("hosting") < order.index(slow)
    assert order.index("http") < order.index("cloaking")
