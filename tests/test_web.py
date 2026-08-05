import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from domain_scanner.config import Config
from domain_scanner.models import CheckResult, DomainReport
from domain_scanner.scoring import score_report
from domain_scanner.web import app as web_app
from domain_scanner.web.app import create_app
from domain_scanner.web.db import Database

TOKEN = "test-token-123"


@pytest.fixture(autouse=True)
def no_preflight(monkeypatch):
    """Tests use fake scanners, so probing real connectivity is noise."""
    monkeypatch.setenv("SCANNER_PREFLIGHT", "0")


def fake_report(domain, severity="info", code="dns.ok", message="fine"):
    report = DomainReport(domain=domain, raw_input=domain)
    check = CheckResult(name="dns")
    check.add(code, severity, message)
    check.data["a"] = ["5.5.5.5"]
    report.checks.append(check)
    return score_report(report)


@pytest.fixture
def scan_stub(monkeypatch):
    """Replace the real scanner so the API tests never touch the network."""
    calls = []

    def _scan(raw, config):
        calls.append(raw)
        severity = "critical" if raw.startswith("bad") else "info"
        return fake_report(raw, severity=severity, code="blocklist.listed",
                           message=f"synthetic {raw}")

    monkeypatch.setattr("domain_scanner.web.jobs.scan_domain", _scan)
    return calls


@pytest.fixture
def client(tmp_path, scan_stub):
    app = create_app(db_path=str(tmp_path / "t.db"), config=Config.from_env(), token=TOKEN)
    with TestClient(app) as c:
        c.headers.update({"X-Auth-Token": TOKEN})
        yield c


@pytest.fixture
def open_client(tmp_path, scan_stub):
    app = create_app(db_path=str(tmp_path / "o.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        yield c


def wait_for(client, scan_id, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/scans/{scan_id}").json()
        if body["scan"]["status"] in ("done", "failed"):
            return body
        time.sleep(0.05)
    raise AssertionError("scan did not finish in time")


# ------------------------------------------------------------------------ auth


def test_health_is_public(client):
    bare = TestClient(client.app)
    body = bare.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["auth_required"] is True
    assert body["connectivity"]["http"] is True


def test_health_reports_degraded_connectivity(tmp_path, scan_stub, monkeypatch):
    """A host that cannot reach the internet must say so, not scan blindly."""
    monkeypatch.setenv("SCANNER_PREFLIGHT", "1")
    monkeypatch.setattr(
        "domain_scanner.preflight.probe_http", lambda *a, **k: (False, "no route")
    )
    monkeypatch.setattr("domain_scanner.preflight.probe_dns", lambda *a, **k: (True, "ok"))
    app = create_app(db_path=str(tmp_path / "d.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        # The probe runs on a background thread so the socket binds immediately;
        # wait for it to land before asserting on what it found.
        assert app.state.monitor.wait_ready(5), "probe never completed"
        body = c.get("/api/health").json()
        assert body["status"] == "degraded"
        assert body["connectivity"]["http"] is False
        assert body["connectivity"]["http_detail"] == "no route"
        # And the scan config reflects it, so HTTP checks are skipped not failed.
        assert app.state.config.http_available is False


def test_api_rejects_missing_token(client):
    bare = TestClient(client.app)
    assert bare.get("/api/scans").status_code == 401


def test_api_rejects_wrong_token(client):
    bare = TestClient(client.app)
    assert bare.get("/api/scans", headers={"X-Auth-Token": "nope"}).status_code == 401


def test_bearer_token_accepted(client):
    bare = TestClient(client.app)
    resp = bare.get("/api/scans", headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200


def test_session_sets_cookie_then_authorises(client):
    bare = TestClient(client.app)
    assert bare.post("/api/session", headers={"X-Auth-Token": TOKEN}).status_code == 200
    assert bare.get("/api/scans").status_code == 200  # cookie carried by the client


def test_open_instance_needs_no_token(open_client):
    assert open_client.get("/api/scans").status_code == 200


# ----------------------------------------------------------------------- scans


def test_submit_and_complete_scan(client):
    resp = client.post("/api/scans", json={"domains": ["good.com", "bad.com"]})
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    body = wait_for(client, scan_id)
    assert body["scan"]["status"] == "done"
    assert body["scan"]["done_count"] == 2
    domains = {r["domain"] for r in body["results"]}
    assert domains == {"good.com", "bad.com"}
    # Worst first.
    assert body["results"][0]["domain"] == "bad.com"


def test_submit_normalises_and_deduplicates(client):
    resp = client.post("/api/scans", json={
        "domains": ["https://www.a.com/lp?x=1", "A.COM", "b.com, c.com"],
    })
    assert resp.json()["domains"] == ["a.com", "b.com", "c.com"]


def test_submit_reports_rejected_input(client):
    """One unusable line, one rejection -- not one per word on that line."""
    resp = client.post("/api/scans", json={"domains": ["good.com", "not a domain!!", "8.8.8.8"]})
    body = resp.json()
    assert body["domains"] == ["good.com"]
    assert {r["input"] for r in body["rejected"]} == {"not a domain!!", "8.8.8.8"}
    reason = next(r["reason"] for r in body["rejected"] if r["input"] == "8.8.8.8")
    assert reason == "это IP-адрес, а не домен"


def test_submit_strips_notes_and_whitespace_around_domains(client):
    """The paste that used to produce a screenful of bogus rejections."""
    resp = client.post("/api/scans", json={"domains": [
        "   spaced-out.com   ",
        "annotated.com  — акк 3, лил в июне, живой",
        "https://with-path.com/lp?utm=x   (клоака под DE)",
        "a.com, b.com;  c.com",
    ]})
    body = resp.json()
    assert body["domains"] == [
        "spaced-out.com", "annotated.com", "with-path.com", "a.com", "b.com", "c.com",
    ]
    assert body["rejected"] == []


def test_submit_all_invalid_is_400(client):
    assert client.post("/api/scans", json={"domains": ["!!!"]}).status_code == 400


def test_submit_enforces_domain_cap(client, monkeypatch):
    monkeypatch.setattr(web_app, "MAX_DOMAINS_PER_SCAN", 3)
    resp = client.post("/api/scans", json={"domains": [f"d{i}.com" for i in range(10)]})
    assert resp.status_code == 400
    assert "too many domains" in resp.json()["detail"]


def test_scan_records_footprint(client):
    resp = client.post("/api/scans", json={"domains": ["a.com", "b.com", "c.com"]})
    body = wait_for(client, resp.json()["scan_id"])
    # All three stubs share the 5.5.5.5 address.
    kinds = {link["kind"] for link in body["scan"]["footprint"]}
    assert "ip" in kinds


def test_single_domain_scan_has_no_footprint(client):
    resp = client.post("/api/scans", json={"domains": ["solo.com"]})
    body = wait_for(client, resp.json()["scan_id"])
    assert body["scan"]["footprint"] == []


def test_unknown_scan_is_404(client):
    assert client.get("/api/scans/deadbeef").status_code == 404


def test_delete_scan(client):
    scan_id = client.post("/api/scans", json={"domains": ["x.com"]}).json()["scan_id"]
    wait_for(client, scan_id)
    assert client.delete(f"/api/scans/{scan_id}").status_code == 200
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_scan_list_includes_worst_score(client):
    scan_id = client.post("/api/scans", json={"domains": ["bad.com"]}).json()["scan_id"]
    wait_for(client, scan_id)
    scans = client.get("/api/scans").json()["scans"]
    assert scans[0]["id"] == scan_id
    assert scans[0]["worst_score"] >= 75


# --------------------------------------------------------------------- export


@pytest.mark.parametrize("fmt,marker", [
    ("json", '"domains"'),
    ("csv", "домен,счёт,вердикт"),
    ("md", "# Скан доменов"),
])
def test_export_formats(client, fmt, marker):
    scan_id = client.post("/api/scans", json={"domains": ["a.com", "b.com"]}).json()["scan_id"]
    wait_for(client, scan_id)
    resp = client.get(f"/api/scans/{scan_id}/export", params={"format": fmt})
    assert resp.status_code == 200
    assert marker in resp.text
    assert "attachment" in resp.headers["content-disposition"]


def test_export_rejects_unknown_format(client):
    scan_id = client.post("/api/scans", json={"domains": ["a.com"]}).json()["scan_id"]
    wait_for(client, scan_id)
    assert client.get(f"/api/scans/{scan_id}/export?format=pdf").status_code == 400


def test_exported_json_roundtrips(client):
    scan_id = client.post("/api/scans", json={"domains": ["a.com"]}).json()["scan_id"]
    wait_for(client, scan_id)
    payload = json.loads(client.get(f"/api/scans/{scan_id}/export?format=json").text)
    assert payload["domains"][0]["domain"] == "a.com"
    assert payload["domains"][0]["checks"][0]["findings"]


# ------------------------------------------------------------------- outcomes


def test_set_and_read_outcome(client):
    scan_id = client.post("/api/scans", json={"domains": ["tracked.com"]}).json()["scan_id"]
    wait_for(client, scan_id)

    resp = client.put("/api/domains/tracked.com/outcome",
                      json={"outcome": "verification", "note": "died day 2"})
    assert resp.status_code == 200

    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["results"][0]["outcome"] == "verification"
    assert body["results"][0]["outcome_note"] == "died day 2"


@pytest.mark.parametrize("supplied", ["WWW.Upper.COM", "www.upper.com", "Upper.com"])
def test_outcome_normalises_domain(client, supplied):
    resp = client.put(f"/api/domains/{supplied}/outcome", json={"outcome": "alive"})
    assert resp.status_code == 200
    assert resp.json()["domain"] == "upper.com"
    assert client.app.state.db.get_outcomes(["upper.com"])["upper.com"]["outcome"] == "alive"


def test_invalid_outcome_is_400(client):
    assert client.put("/api/domains/x.com/outcome",
                      json={"outcome": "exploded"}).status_code == 400


def test_domain_history_lists_latest_scores(client):
    scan_id = client.post("/api/scans", json={"domains": ["hist.com"]}).json()["scan_id"]
    wait_for(client, scan_id)
    client.put("/api/domains/hist.com/outcome", json={"outcome": "alive"})
    body = client.get("/api/domains").json()
    entry = next(d for d in body["domains"] if d["domain"] == "hist.com")
    assert entry["outcome"] == "alive"
    assert body["totals"]["alive"] == 1


# ---------------------------------------------------------------- calibration


def test_calibration_separates_alive_from_flagged(client):
    scan_id = client.post("/api/scans", json={
        "domains": ["bad1.com", "bad2.com", "good1.com", "good2.com"],
    }).json()["scan_id"]
    wait_for(client, scan_id)

    # "bad*" stubs carry a critical blocklist.listed finding; "good*" do not.
    for domain in ("bad1.com", "bad2.com"):
        client.put(f"/api/domains/{domain}/outcome", json={"outcome": "verification"})
    for domain in ("good1.com", "good2.com"):
        client.put(f"/api/domains/{domain}/outcome", json={"outcome": "alive"})

    body = client.get("/api/calibration").json()
    listed = next(c for c in body["codes"] if c["code"] == "blocklist.listed")
    assert listed["flagged_rate"] == 1.0
    assert listed["alive_rate"] == 0.0
    assert listed["lift"] == 1.0
    assert body["totals"]["verification"] == 2


def test_calibration_empty_without_outcomes(client):
    assert client.get("/api/calibration").json()["codes"] == []


# ------------------------------------------------------------------ hardening


def test_rate_limit_blocks_excess_scans(tmp_path, monkeypatch, scan_stub):
    monkeypatch.setenv("SCANNER_RATE_LIMIT", "2")
    app = create_app(db_path=str(tmp_path / "r.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        assert c.post("/api/scans", json={"domains": ["a.com"]}).status_code == 202
        assert c.post("/api/scans", json={"domains": ["b.com"]}).status_code == 202
        assert c.post("/api/scans", json={"domains": ["c.com"]}).status_code == 429


def test_web_config_blocks_private_targets(client):
    assert client.app.state.config.block_private_targets is True


def test_robots_disallows_everything(client):
    assert "Disallow: /" in TestClient(client.app).get("/robots.txt").text


def test_ui_is_served(client):
    resp = TestClient(client.app).get("/")
    assert resp.status_code == 200
    assert "Domain Scanner" in resp.text


# --------------------------------------------------------------------- store


def test_database_survives_reopen(tmp_path):
    path = tmp_path / "persist.db"
    db = Database(path)
    scan_id = db.create_scan(["a.com"], "label")
    db.add_result(scan_id, fake_report("a.com").to_dict())
    db.set_scan_status(scan_id, "done")

    reopened = Database(path)
    assert reopened.get_scan(scan_id)["label"] == "label"
    assert reopened.get_results(scan_id)[0]["domain"] == "a.com"


def test_database_rejects_unknown_outcome(tmp_path):
    db = Database(tmp_path / "x.db")
    with pytest.raises(ValueError):
        db.set_outcome("a.com", "banana")


def test_outcome_upsert_replaces_previous(tmp_path):
    db = Database(tmp_path / "y.db")
    db.set_outcome("a.com", "alive")
    db.set_outcome("a.com", "banned", "caught")
    outcomes = db.get_outcomes(["a.com"])
    assert outcomes["a.com"]["outcome"] == "banned"
    assert outcomes["a.com"]["note"] == "caught"


# ------------------------------------------------------------- proxy awareness


def test_client_key_ignores_forwarded_header_by_default():
    from domain_scanner.web.app import client_key

    class Req:
        headers = {"X-Forwarded-For": "1.2.3.4"}
        client = type("C", (), {"host": "127.0.0.1"})()

    assert client_key(Req(), trust_proxy=False) == "127.0.0.1"


def test_client_key_uses_forwarded_header_when_trusted():
    from domain_scanner.web.app import client_key

    class Req:
        headers = {"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}
        client = type("C", (), {"host": "127.0.0.1"})()

    assert client_key(Req(), trust_proxy=True) == "1.2.3.4"


def test_rate_limit_is_per_client_behind_proxy(tmp_path, monkeypatch, scan_stub):
    """Two users behind the same proxy must not share one bucket."""
    monkeypatch.setenv("SCANNER_RATE_LIMIT", "1")
    monkeypatch.setenv("SCANNER_TRUST_PROXY", "1")
    app = create_app(db_path=str(tmp_path / "p.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        a = {"X-Forwarded-For": "1.1.1.1"}
        b = {"X-Forwarded-For": "2.2.2.2"}
        assert c.post("/api/scans", json={"domains": ["a.com"]}, headers=a).status_code == 202
        assert c.post("/api/scans", json={"domains": ["b.com"]}, headers=b).status_code == 202
        assert c.post("/api/scans", json={"domains": ["c.com"]}, headers=a).status_code == 429


# ------------------------------------------------------- startup must not block


def test_server_binds_before_connectivity_probe_finishes(tmp_path, scan_stub, monkeypatch):
    """A slow probe must not delay the socket.

    uvicorn runs lifespan startup before it binds, so anything blocking there
    means nothing is listening -- including /api/health, the endpoint used to
    decide whether the service came up.
    """
    monkeypatch.setenv("SCANNER_PREFLIGHT", "1")
    probe_started = threading.Event()
    release = threading.Event()

    def slow_probe(*_a, **_k):
        probe_started.set()
        release.wait(10)
        return True, "eventually"

    monkeypatch.setattr("domain_scanner.preflight.probe_http", slow_probe)
    monkeypatch.setattr("domain_scanner.preflight.probe_dns", lambda *a, **k: (True, "ok"))

    app = create_app(db_path=str(tmp_path / "s.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        assert probe_started.wait(5), "probe never started"
        # The probe is still in flight; the API must answer anyway.
        started = time.monotonic()
        body = c.get("/api/health")
        assert body.status_code == 200
        assert time.monotonic() - started < 2.0
        # Honest about not knowing yet, rather than reporting a premature "ok".
        assert body.json()["status"] == "checking"
        assert body.json()["connectivity"]["probed"] is False
        release.set()


def test_scan_waits_for_first_connectivity_probe(tmp_path, scan_stub, monkeypatch):
    """Scanning does wait, so a dead uplink is not blamed on the domains."""
    monkeypatch.setenv("SCANNER_PREFLIGHT", "1")
    release = threading.Event()

    def slow_probe(*_a, **_k):
        release.wait(10)
        return False, "no egress"

    monkeypatch.setattr("domain_scanner.preflight.probe_http", slow_probe)
    monkeypatch.setattr("domain_scanner.preflight.probe_dns", lambda *a, **k: (True, "ok"))

    app = create_app(db_path=str(tmp_path / "w.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        scan_id = c.post("/api/scans", json={"domains": ["a.com"]}).json()["scan_id"]
        time.sleep(0.4)
        # Still queued: the runner is waiting on the probe, not scanning blind.
        assert c.get(f"/api/scans/{scan_id}").json()["scan"]["status"] == "queued"
        release.set()
        body = wait_for(c, scan_id)
        assert body["scan"]["status"] == "done"
        assert app.state.config.http_available is False


def test_monitor_start_returns_immediately():
    from domain_scanner.config import Config as C
    from domain_scanner.preflight import ConnectivityMonitor

    cfg = C.from_env()
    monitor = ConnectivityMonitor(cfg, interval=3600, enabled=False)
    started = time.monotonic()
    monitor.start()
    assert time.monotonic() - started < 0.5
    assert monitor.wait_ready(1) is True
    monitor.stop()


# --------------------------------------------------------------- data directory


def test_database_reports_unwritable_directory_clearly(tmp_path, monkeypatch):
    """sqlite says "unable to open database file"; that is not a usable hint.

    The real-world cause is a bind-mounted host directory owned by root while
    the container runs unprivileged, and the message should say so.
    """
    target = tmp_path / "locked"
    target.mkdir()
    monkeypatch.setattr("domain_scanner.web.db.os.access", lambda *a, **k: False)
    with pytest.raises(RuntimeError) as excinfo:
        Database(target / "scanner.db")
    message = str(excinfo.value)
    assert "not writable" in message
    assert "named volume" in message


def test_database_creates_missing_directory(tmp_path):
    db = Database(tmp_path / "nested" / "deeper" / "scanner.db")
    scan_id = db.create_scan(["a.com"])
    assert db.get_scan(scan_id) is not None


# ------------------------------------------------------- a scan has to end
#
# The failure these cover is not "a scan is slow". It is that a scan which
# never returns holds one of a handful of runner slots, so every scan
# submitted afterwards sits in the queue and the whole tool looks hung.


@pytest.fixture
def controlled_scan(monkeypatch):
    """A scanner stub whose per-domain duration the test decides.

    Domains named ``slow-<n>`` take n seconds; ``wedged`` blocks until the
    fixture is torn down, standing in for an endpoint that never answers.
    """
    release = threading.Event()
    started: dict[str, float] = {}

    def _scan(raw, config, deadline=None):
        started[raw] = time.monotonic()
        if raw.startswith("wedged"):
            release.wait(30)
        elif raw.startswith("slow-"):
            time.sleep(float(raw.split("-")[1].split(".")[0]) / 10)
        return fake_report(raw)

    monkeypatch.setattr("domain_scanner.web.jobs.scan_domain", _scan)
    yield started
    # Let any abandoned worker thread exit, or the interpreter waits for it.
    release.set()


def impatient_app(tmp_path, name, domain_timeout=1.0, scan_timeout=5.0):
    cfg = Config.from_env(
        domain_timeout=domain_timeout, scan_timeout=scan_timeout, workers=8
    )
    return create_app(db_path=str(tmp_path / name), config=cfg, token="")


def test_progress_counts_completed_domains_not_a_prefix(tmp_path, controlled_scan):
    """done_count must mean "finished", not "finished, in submission order".

    Waiting on futures in the order they were submitted pins the counter to the
    first domain: five domains can be done and the bar still reads 0/6, which
    is exactly what a hang looks like from the browser.
    """
    # Generous timeouts: this test is about what the counter says while a
    # domain is still in flight, so nothing may cut that domain short.
    app = impatient_app(tmp_path, "prog.db", domain_timeout=20.0, scan_timeout=20.0)
    with TestClient(app) as c:
        # The blocked one is submitted first, so submission order and
        # completion order disagree.
        domains = ["wedged.com"] + [f"fast{i}.com" for i in range(5)]
        scan_id = c.post("/api/scans", json={"domains": domains}).json()["scan_id"]

        deadline = time.time() + 4
        seen = 0
        while time.time() < deadline and seen < 5:
            scan = c.get(f"/api/scans/{scan_id}").json()["scan"]
            seen = max(seen, scan["done_count"])
            time.sleep(0.05)

        assert seen == 5, (
            f"counter read {seen}/6 while five domains had finished and only "
            "the blocked one was left"
        )
        # And it is still running -- the five did not land because the scan
        # gave up, they landed as they completed.
        assert c.get(f"/api/scans/{scan_id}").json()["scan"]["status"] == "running"


def test_unresponsive_domain_does_not_hold_the_scan(tmp_path, controlled_scan):
    app = impatient_app(tmp_path, "wedge.db")
    with TestClient(app) as c:
        scan_id = c.post(
            "/api/scans", json={"domains": ["wedged.com", "ok.com"]}
        ).json()["scan_id"]
        body = wait_for(c, scan_id, timeout=10)

        assert body["scan"]["status"] == "done"
        # Both domains accounted for: the bar reaches the end either way.
        assert body["scan"]["done_count"] == 2
        wedged = next(r for r in body["results"] if r["domain"] == "wedged.com")
        assert wedged["verdict"] == "ERROR"
        assert "не уложился" in wedged["checks"][0]["error"]


def test_a_wedged_scan_does_not_block_the_next_one(tmp_path, controlled_scan, monkeypatch):
    """The reported symptom: one bad batch and everything after it hangs."""
    monkeypatch.setenv("SCANNER_MAX_CONCURRENT_SCANS", "1")
    app = impatient_app(tmp_path, "queue.db")
    with TestClient(app) as c:
        first = c.post("/api/scans", json={"domains": ["wedged.com"]}).json()["scan_id"]
        second = c.post("/api/scans", json={"domains": ["ok.com"]}).json()["scan_id"]

        body = wait_for(c, second, timeout=10)
        assert body["scan"]["status"] == "done"
        assert body["results"][0]["domain"] == "ok.com"
        assert wait_for(c, first, timeout=10)["scan"]["status"] == "done"


def test_queued_scan_reports_its_position(tmp_path, controlled_scan, monkeypatch):
    monkeypatch.setenv("SCANNER_MAX_CONCURRENT_SCANS", "1")
    app = impatient_app(tmp_path, "pos.db")
    with TestClient(app) as c:
        c.post("/api/scans", json={"domains": ["wedged.com"]})
        waiting = c.post("/api/scans", json={"domains": ["later.com"]}).json()["scan_id"]
        scan = c.get(f"/api/scans/{waiting}").json()["scan"]
        assert scan["status"] == "queued"
        assert scan["queue_position"] == 1
        assert scan["queue_capacity"] == 1


def test_cancel_stops_a_running_scan(tmp_path, controlled_scan):
    app = impatient_app(tmp_path, "cancel.db")
    with TestClient(app) as c:
        scan_id = c.post("/api/scans", json={"domains": ["wedged.com"]}).json()["scan_id"]
        # Wait until it is actually running, then pull the plug.
        deadline = time.time() + 3
        while time.time() < deadline:
            if c.get(f"/api/scans/{scan_id}").json()["scan"]["status"] == "running":
                break
            time.sleep(0.02)
        c.post(f"/api/scans/{scan_id}/cancel")

        body = wait_for(c, scan_id, timeout=5)
        assert body["scan"]["status"] == "failed"
        assert body["scan"]["error"] == "отменено"


def test_a_domain_that_raises_is_still_reported(tmp_path, monkeypatch):
    """A crashed domain used to vanish: N submitted, N-1 results, no reason given."""
    def _scan(raw, config, deadline=None):
        if raw == "boom.com":
            raise RuntimeError("check exploded")
        return fake_report(raw)

    monkeypatch.setattr("domain_scanner.web.jobs.scan_domain", _scan)
    app = create_app(db_path=str(tmp_path / "boom.db"), config=Config.from_env(), token="")
    with TestClient(app) as c:
        scan_id = c.post(
            "/api/scans", json={"domains": ["boom.com", "fine.com"]}
        ).json()["scan_id"]
        body = wait_for(c, scan_id)
        assert body["scan"]["done_count"] == 2
        boom = next(r for r in body["results"] if r["domain"] == "boom.com")
        assert boom["verdict"] == "ERROR"
        assert "check exploded" in boom["checks"][0]["error"]
