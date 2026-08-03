"""Output renderers: console, JSON, CSV, Markdown."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

from .footprint import Link
from .models import DomainReport
from .scoring import confidence, verdict_blurb

VERDICT_COLORS = {
    "CLEAN": "\033[92m",
    "WATCH": "\033[93m",
    "RISKY": "\033[33m",
    "AVOID": "\033[91m",
    "UNREGISTERED": "\033[96m",
    "INVALID": "\033[90m",
    "ERROR": "\033[90m",
}
SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
SEVERITY_MARK = {
    "critical": "XX",
    "high": " X",
    "medium": " !",
    "low": " ~",
    "info": " .",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def use_color(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        if not self.enabled or not code:
            return text
        return f"{code}{text}{RESET}"

    def verdict(self, verdict: str) -> str:
        return self(verdict, VERDICT_COLORS.get(verdict, ""))

    def severity(self, severity: str, text: str) -> str:
        return self(text, SEVERITY_COLORS.get(severity, ""))

    def bold(self, text: str) -> str:
        return self(text, BOLD)


def score_bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "#" * filled + "." * (width - filled)


def render_summary(reports: list[DomainReport], paint: Painter) -> str:
    """One line per domain, worst first."""
    rows = sorted(reports, key=lambda r: -r.score)
    name_width = max([len(r.domain) for r in rows] + [10])
    verdict_width = max([len(r.verdict) for r in rows] + [7])
    out = [paint.bold(f"{'ДОМЕН'.ljust(name_width)}  СЧЁТ  "
                      f"{'ВЕРДИКТ'.ljust(verdict_width)}  ГЛАВНАЯ ПРОБЛЕМА")]
    for r in rows:
        top = r.top_findings(1)
        issue = top[0].message if top else "-"
        if len(issue) > 62:
            issue = issue[:59] + "..."
        out.append(
            f"{r.domain.ljust(name_width)}  "
            f"{str(r.score).rjust(5)}  "
            f"{paint.verdict(r.verdict.ljust(verdict_width))}  {issue}"
        )
    return "\n".join(out)


def render_report(report: DomainReport, paint: Painter, verbose: bool = False) -> str:
    lines: list[str] = []
    header = f"{report.domain}  —  {report.score}/100  {report.verdict}"
    lines.append(paint.bold(header))
    lines.append(f"  [{score_bar(report.score)}]  {verdict_blurb(report.verdict)}")

    conf = confidence(report)
    if conf < 1.0:
        missing = ", ".join(report.unavailable_checks) or "none"
        note = "" if conf >= 0.75 else "  <- вердикт предварительный"
        lines.append(f"  покрытие {int(conf * 100)}% "
                     f"(нет данных от: {missing}){note}")

    shown = [f for f in report.findings if (f.weight or 0) > 0 or verbose]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    shown.sort(key=lambda f: (order.get(f.severity, 9), f.code))
    if not shown:
        lines.append("  находок нет")
    for f in shown:
        mark = SEVERITY_MARK.get(f.severity, " ?")
        lines.append(f"  {paint.severity(f.severity, mark)} {f.message}")
        if verbose and f.detail:
            detail = json.dumps(f.detail, ensure_ascii=False, default=str)
            lines.append(f"       {detail[:300]}")

    if verbose:
        lines.append("  " + paint.bold("статус проверок:"))
        for c in report.checks:
            status = c.status if c.status == "ok" else f"{c.status} ({c.error})"
            lines.append(f"    {c.name:<14} {status}  {c.duration_ms}ms")
    return "\n".join(lines)


def render_footprint(links: list[Link], paint: Painter) -> str:
    if not links:
        return paint.bold("Общий след") + "\n  не найден — домены выглядят независимыми"
    lines = [paint.bold("Общий след по пачке")]
    for link in links:
        mark = SEVERITY_MARK.get(link.severity, " ?")
        lines.append(f"  {paint.severity(link.severity, mark)} {link.message}")
        lines.append(f"       {', '.join(link.domains)}")
    return "\n".join(lines)


def to_json(reports: list[DomainReport], links: list[Link] | None = None) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains": [r.to_dict() for r in reports],
        "footprint": [l.to_dict() for l in (links or [])],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


CSV_COLUMNS = [
    "домен", "счёт", "вердикт", "покрытие", "возраст_дней", "регистратор", "тир_зоны",
    "перерегистрирован", "в_блоклистах", "safe_browsing", "vt_вредоносных", "http_код",
    "конечный_домен", "страницы_доверия", "ip", "asn", "главные_проблемы",
]


def to_csv(reports: list[DomainReport]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in sorted(reports, key=lambda x: -x.score):
        networks = r.data("hosting", "networks") or []
        blocklist_hits = r.data("blocklists", "listings") or {}
        writer.writerow({
            "домен": r.domain,
            "счёт": r.score,
            "вердикт": r.verdict,
            "покрытие": confidence(r),
            "возраст_дней": r.data("rdap", "age_days", ""),
            "регистратор": r.data("rdap", "registrar", ""),
            "тир_зоны": r.data("tld", "tier", ""),
            "перерегистрирован": r.data("wayback", "recycled", ""),
            "в_блоклистах": "; ".join(blocklist_hits) if blocklist_hits else "",
            "safe_browsing": "; ".join(r.data("safebrowsing", "threat_types") or []),
            "vt_вредоносных": r.data("virustotal", "malicious", ""),
            "http_код": r.data("http", "status", ""),
            "конечный_домен": r.data("http", "final_domain", ""),
            "страницы_доверия": "; ".join((r.data("http", "policy_pages") or {}).keys()),
            "ip": "; ".join(r.data("dns", "a") or []),
            "asn": "; ".join(sorted({str(n["asn"]) for n in networks if n.get("asn")})),
            "главные_проблемы": " | ".join(f.message for f in r.top_findings(3)),
        })
    return buf.getvalue()


def to_markdown(reports: list[DomainReport], links: list[Link] | None = None) -> str:
    rows = sorted(reports, key=lambda r: -r.score)
    out = ["# Скан доменов", "",
           f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}, "
           f"доменов: {len(rows)}_", "",
           "| Домен | Счёт | Вердикт | Главная проблема |",
           "| --- | ---: | --- | --- |"]
    for r in rows:
        top = r.top_findings(1)
        out.append(f"| `{r.domain}` | {r.score} | **{r.verdict}** | "
                   f"{top[0].message if top else '—'} |")
    out.append("")
    for r in rows:
        out.append(f"## {r.domain} — {r.score}/100 {r.verdict}")
        findings = [f for f in r.findings if (f.weight or 0) > 0]
        if not findings:
            out.append("Находок нет.")
        for f in sorted(findings, key=lambda f: -(f.weight or 0)):
            out.append(f"- **{f.severity}** · `{f.code}` — {f.message}")
        out.append("")
    if links:
        out.append("## Общий след")
        for link in links:
            out.append(f"- **{link.severity}** — {link.message}  \n  "
                       f"`{', '.join(link.domains)}`")
        out.append("")
    return "\n".join(out)
