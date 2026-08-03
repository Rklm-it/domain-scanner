"""Turn findings into a single risk score and a verdict."""

from __future__ import annotations

from .models import DomainReport

# score >= threshold -> verdict
VERDICTS: list[tuple[int, str, str]] = [
    (70, "AVOID", "Не лить на этот домен."),
    (40, "RISKY", "Можно, но сначала почини перечисленное ниже."),
    (20, "WATCH", "Ничего дисквалифицирующего, но и не идеально."),
    (0, "CLEAN", "Значимых красных флагов не нашлось."),
]

# A single severe finding should not be diluted by a pile of clean checks.
SEVERITY_FLOOR = {"critical": 75, "high": 45, "medium": 22}


def score_report(report: DomainReport) -> DomainReport:
    findings = report.findings
    codes = {f.code for f in findings}

    # An available domain is not "risky" — it just has nothing to assess yet.
    if "rdap.not_registered" in codes and "dns.no_ns" in codes:
        report.score = 0
        report.verdict = "UNREGISTERED"
        return report

    raw = sum(f.weight or 0 for f in findings)
    score = min(100, raw)

    for severity, floor in SEVERITY_FLOOR.items():
        if any(f.severity == severity for f in findings):
            score = max(score, floor)
            break

    report.score = int(score)
    for threshold, verdict, _blurb in VERDICTS:
        if report.score >= threshold:
            report.verdict = verdict
            break
    return report


EXTRA_BLURBS = {
    "UNREGISTERED": "Домен не зарегистрирован — оценивать пока нечего.",
    "INVALID": "Не распознано как домен.",
    "ERROR": "Сам скан завершился ошибкой.",
}


def verdict_blurb(verdict: str) -> str:
    for _threshold, name, blurb in VERDICTS:
        if name == verdict:
            return blurb
    return EXTRA_BLURBS.get(verdict, "")


def confidence(report: DomainReport) -> float:
    """Share of applicable checks that actually produced data (0.0-1.0).

    Checks skipped because an optional API key is missing do not count against
    the score -- the user opted out. Checks that failed, or that could not run
    because this machine has no route to them, do.
    """
    applicable = [
        c for c in report.checks
        if not (c.status == "skipped" and c.skip_kind == "config")
    ]
    if not applicable:
        return 0.0
    ok = [c for c in applicable if c.status == "ok"]
    return round(len(ok) / len(applicable), 2)
