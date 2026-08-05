import json

import pytest

from domain_scanner import cli
from domain_scanner.models import CheckResult, DomainReport
from domain_scanner.scoring import score_report


def fake_scan(score_by_domain):
    def _scan(raws, config, on_done=None):
        reports = []
        for raw in raws:
            report = DomainReport(domain=raw, raw_input=raw)
            check = CheckResult(name="tld")
            severity = "critical" if score_by_domain.get(raw, 0) >= 70 else "info"
            check.add("tld.test", severity, f"synthetic finding for {raw}")
            report.checks.append(check)
            reports.append(score_report(report))
        return reports

    return _scan


@pytest.fixture
def patched(monkeypatch):
    monkeypatch.setattr(cli, "scan_domains", fake_scan({"bad.com": 90}))
    return monkeypatch


def test_read_domains_from_args():
    args = cli.build_parser().parse_args(["a.com", "b.com"])
    assert cli.read_domains(args) == (["a.com", "b.com"], [])


def test_read_domains_splits_commas_and_drops_comments(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("a.com, b.com\n# comment\nc.com  # trailing\n\n")
    args = cli.build_parser().parse_args(["-f", str(f)])
    assert cli.read_domains(args) == (["a.com", "b.com", "c.com"], [])


def test_read_domains_deduplicates(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("a.com\nA.COM\nb.com\n")
    args = cli.build_parser().parse_args(["-f", str(f)])
    assert cli.read_domains(args) == (["a.com", "b.com"], [])


def test_read_domains_strips_notes_after_the_domain(tmp_path):
    """A real list is a domain plus whatever the buyer wrote next to it."""
    f = tmp_path / "d.txt"
    f.write_text(
        "   a-lander.com   \n"
        "b.com  — акк 3, улетел на верифу 12.06\n"
        "https://c.com/lp?utm=x   (клоака под DE)\n"
    )
    args = cli.build_parser().parse_args(["-f", str(f)])
    domains, unusable = cli.read_domains(args)
    assert domains == ["a-lander.com", "b.com", "c.com"]
    assert unusable == []


def test_read_domains_reports_a_line_it_could_not_use(tmp_path):
    """A typo'd domain must be named, not silently dropped from the batch."""
    f = tmp_path / "d.txt"
    f.write_text("good.com\nbroken,com\n")
    args = cli.build_parser().parse_args(["-f", str(f)])
    domains, unusable = cli.read_domains(args)
    assert domains == ["good.com"]
    assert unusable == [("broken,com", "нет точки — на домен не похоже")]


def test_list_checks_exits_clean(capsys):
    assert cli.main(["--list-checks"]) == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "wayback" in out and "cloaking" in out


def test_unknown_check_is_rejected():
    with pytest.raises(SystemExit):
        cli.main(["example.com", "--only", "nope"])


def test_exit_code_clean(patched, capsys):
    assert cli.main(["good.com", "--no-color"]) == cli.EXIT_CLEAN


def test_exit_code_risky(patched, capsys):
    assert cli.main(["bad.com", "--no-color"]) == cli.EXIT_RISKY


def test_fail_over_threshold_is_configurable(patched, capsys):
    assert cli.main(["bad.com", "--no-color", "--fail-over", "101"]) == cli.EXIT_CLEAN


def test_json_output_written(patched, tmp_path, capsys):
    out = tmp_path / "r.json"
    cli.main(["good.com", "bad.com", "--json", str(out), "--no-color"])
    payload = json.loads(out.read_text())
    assert {d["domain"] for d in payload["domains"]} == {"good.com", "bad.com"}


def test_csv_output_written(patched, tmp_path):
    out = tmp_path / "r.csv"
    cli.main(["good.com", "--csv", str(out), "--no-color"])
    assert out.read_text().startswith("домен,счёт,вердикт")


def test_markdown_output_written(patched, tmp_path):
    out = tmp_path / "r.md"
    cli.main(["good.com", "bad.com", "--markdown", str(out), "--footprint", "--no-color"])
    text = out.read_text()
    assert "# Скан доменов" in text
    assert "bad.com" in text


def test_no_domains_errors():
    with pytest.raises(SystemExit):
        cli.main(["--no-color", "-f", "/nonexistent-file-xyz"])
