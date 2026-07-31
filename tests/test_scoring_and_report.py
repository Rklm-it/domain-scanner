import json

from domain_scanner.footprint import analyze
from domain_scanner.models import CheckResult, DomainReport
from domain_scanner.report import Painter, render_report, render_summary, to_csv, to_json
from domain_scanner.scoring import confidence, score_report


def report_with(domain="example.com", findings=(), data=None, statuses=None):
    report = DomainReport(domain=domain, raw_input=domain)
    grouped: dict[str, CheckResult] = {}
    for check_name, code, severity, message in findings:
        check = grouped.setdefault(check_name, CheckResult(name=check_name))
        check.add(code, severity, message)
    for check_name, payload in (data or {}).items():
        check = grouped.setdefault(check_name, CheckResult(name=check_name))
        check.data.update(payload)
    for check_name, status in (statuses or {}).items():
        check = grouped.setdefault(check_name, CheckResult(name=check_name))
        check.status = status
        if status == "error":
            check.error = "boom"
    report.checks = list(grouped.values())
    return score_report(report)


def test_score_clean_domain():
    r = report_with(findings=[("dns", "dns.ok", "info", "fine")])
    assert r.score == 0
    assert r.verdict == "CLEAN"


def test_single_critical_finding_forces_avoid():
    r = report_with(findings=[("blocklists", "blocklist.listed", "critical", "listed")])
    assert r.score >= 75
    assert r.verdict == "AVOID"


def test_single_high_finding_reaches_risky():
    r = report_with(findings=[("wayback", "wayback.recycled", "high", "recycled")])
    assert r.score >= 45
    assert r.verdict == "RISKY"


def test_medium_findings_accumulate():
    r = report_with(findings=[
        ("tld", "tld.high_abuse", "medium", "bad tld"),
        ("naming", "naming.many_hyphens", "medium", "hyphens"),
        ("dns", "dns.no_mx", "low", "no mx"),
    ])
    assert r.verdict in ("WATCH", "RISKY")
    assert 22 <= r.score <= 60


def test_score_is_capped_at_100():
    findings = [("x", f"code{i}", "critical", "m") for i in range(10)]
    assert report_with(findings=findings).score == 100


def test_confidence_reflects_failed_checks():
    r = report_with(
        findings=[("dns", "dns.ok", "info", "fine")],
        statuses={"rdap": "error", "crtsh": "error", "wayback": "ok"},
    )
    assert confidence(r) < 1.0
    assert set(r.failed_checks) == {"rdap", "crtsh"}


def test_top_findings_excludes_info():
    r = report_with(findings=[
        ("dns", "dns.ok", "info", "fine"),
        ("tld", "tld.high_abuse", "medium", "bad tld"),
    ])
    top = r.top_findings()
    assert len(top) == 1
    assert top[0].code == "tld.high_abuse"


# ---------------------------------------------------------------------- footprint


def batch():
    a = report_with("a-lander.com", data={
        "dns": {"a": ["5.5.5.5"], "ns_provider": ["cheapdns.com"]},
        "rdap": {"created": 1717200000, "registrar": "Cheap Registrar"},
        "http": {"fingerprint": "aaaa1111", "title": "Get Yours Now",
                 "trackers": {"google_analytics": ["G-ABCD1234"]}},
        "hosting": {"networks": [{"asn": "64500"}]},
    })
    b = report_with("b-lander.com", data={
        "dns": {"a": ["5.5.5.5"], "ns_provider": ["cheapdns.com"]},
        "rdap": {"created": 1717200000, "registrar": "Cheap Registrar"},
        "http": {"fingerprint": "aaaa1111", "title": "Get Yours Now",
                 "trackers": {"google_analytics": ["G-ABCD1234"]}},
        "hosting": {"networks": [{"asn": "64500"}]},
    })
    c = report_with("c-lander.com", data={
        "dns": {"a": ["9.9.9.9"], "ns_provider": ["cloudflare.com"]},
        "rdap": {"created": 1600000000, "registrar": "Other Registrar"},
        "http": {"fingerprint": "cccc3333", "title": "Something Else", "trackers": {}},
        "hosting": {"networks": [{"asn": "13335"}]},
    })
    return [a, b, c]


def test_footprint_finds_shared_ip_and_content():
    links = analyze(batch())
    kinds = {l.kind for l in links}
    assert "ip" in kinds
    assert "content" in kinds
    assert "tracker" in kinds
    ip_link = next(l for l in links if l.kind == "ip")
    assert ip_link.domains == ["a-lander.com", "b-lander.com"]


def test_footprint_flags_same_registration_day():
    links = analyze(batch())
    day = next((l for l in links if l.kind == "registration_date"), None)
    assert day is not None
    assert len(day.domains) == 2


def test_footprint_escalates_when_whole_batch_matches():
    reports = batch()[:2]  # both identical
    links = analyze(reports)
    content = next(l for l in links if l.kind == "content")
    # Two of two is not "the whole batch" for escalation purposes (needs > 2).
    assert content.severity == "high"


def test_footprint_ignores_single_domain():
    assert analyze(batch()[:1]) == []


def test_footprint_does_not_flag_cloudflare_ns():
    reports = [
        report_with(f"d{i}.com", data={"dns": {"ns_provider": ["cloudflare.com"]}})
        for i in range(3)
    ]
    assert [l for l in analyze(reports) if l.kind == "ns"] == []


# ------------------------------------------------------------------------ report


def test_json_output_roundtrips():
    payload = json.loads(to_json(batch(), analyze(batch())))
    assert len(payload["domains"]) == 3
    assert payload["footprint"]
    assert payload["domains"][0]["domain"] == "a-lander.com"


def test_csv_has_one_row_per_domain():
    lines = [l for l in to_csv(batch()).splitlines() if l.strip()]
    assert len(lines) == 4  # header + 3
    assert lines[0].startswith("domain,score,verdict")


def test_render_report_is_plain_without_color():
    r = report_with(findings=[("tld", "tld.high_abuse", "medium", "bad tld")])
    text = render_report(r, Painter(False))
    assert "\033[" not in text
    assert "bad tld" in text


def test_render_summary_sorts_worst_first():
    reports = [
        report_with("clean.com", findings=[("dns", "dns.ok", "info", "ok")]),
        report_with("bad.com", findings=[("bl", "blocklist.listed", "critical", "listed")]),
    ]
    text = render_summary(reports, Painter(False))
    lines = text.splitlines()
    assert "bad.com" in lines[1]
    assert "clean.com" in lines[2]


def test_unregistered_domain_gets_its_own_verdict():
    r = report_with(findings=[
        ("rdap", "rdap.not_registered", "info", "no RDAP record"),
        ("dns", "dns.no_ns", "high", "no nameservers"),
    ])
    assert r.verdict == "UNREGISTERED"
    assert r.score == 0


def test_registered_domain_without_ns_is_still_scored():
    r = report_with(findings=[("dns", "dns.no_ns", "high", "no nameservers")])
    assert r.verdict == "RISKY"


def test_confidence_ignores_unconfigured_api_checks():
    r = DomainReport(domain="x.com", raw_input="x.com")
    ok = CheckResult(name="dns")
    ok.add("dns.ok", "info", "fine")
    no_key = CheckResult(name="virustotal")
    no_key.skip("missing config: virustotal_key", kind="config")
    r.checks = [ok, no_key]
    score_report(r)
    assert confidence(r) == 1.0
    assert r.unavailable_checks == []


def test_confidence_counts_transport_skips_as_missing_data():
    r = DomainReport(domain="x.com", raw_input="x.com")
    ok = CheckResult(name="dns")
    ok.add("dns.ok", "info", "fine")
    offline = CheckResult(name="http")
    offline.skip("no outbound HTTP from this machine", kind="transport")
    r.checks = [ok, offline]
    score_report(r)
    assert confidence(r) == 0.5
    assert r.unavailable_checks == ["http"]


def test_render_report_marks_low_confidence_as_provisional():
    r = DomainReport(domain="x.com", raw_input="x.com")
    ok = CheckResult(name="dns")
    ok.add("dns.ok", "info", "fine")
    r.checks = [ok] + [
        CheckResult(name=n).skip("offline", kind="transport")
        for n in ("http", "rdap", "wayback")
    ]
    score_report(r)
    text = render_report(r, Painter(False))
    assert "provisional" in text
    assert "http, rdap, wayback" in text


def test_csv_deduplicates_asns():
    r = report_with("x.com", data={"hosting": {"networks": [
        {"asn": "15169"}, {"asn": "15169"}, {"asn": "13335"},
    ]}})
    row = to_csv([r]).splitlines()[1]
    assert "13335; 15169" in row
