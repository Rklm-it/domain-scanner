"""Scan orchestration: run every enabled check against every domain."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

from .checks import ScanContext, all_checks, run_check
from .config import Config
from .models import CheckResult, DomainReport
from .scoring import score_report
from .utils import DomainParseError, make_resolver, make_session, parse_domain


def scan_domain(raw: str, config: Config, deadline: float | None = None) -> DomainReport:
    """Run the full check suite against one domain.

    ``deadline`` is a ``time.monotonic()`` value past which no further check is
    started; it defaults to ``config.domain_budget`` seconds from now. Checks
    are ordered cheapest- and most-decisive-first, so what gets dropped when a
    domain runs long is the supporting detail, never the verdict.
    """
    started = time.monotonic()
    if deadline is None:
        deadline = started + config.domain_budget if config.domain_budget > 0 else None
    try:
        domain, sld, suffix = parse_domain(raw)
    except DomainParseError as exc:
        report = DomainReport(domain=raw.strip(), raw_input=raw)
        bad = CheckResult(name="input")
        bad.fail(str(exc))
        bad.add("input.invalid", "info", str(exc))
        report.checks.append(bad)
        report.verdict = "INVALID"
        return report

    report = DomainReport(domain=domain, raw_input=raw)
    ctx = ScanContext(
        domain=domain,
        sld=sld,
        suffix=suffix,
        config=config,
        resolver=make_resolver(config.dns_timeout, config.nameservers),
        session=make_session(config.proxy),
    )
    try:
        for check in all_checks():
            if not config.is_enabled(check.name):
                continue
            if deadline is not None and time.monotonic() >= deadline:
                out_of_time = CheckResult(name=check.name)
                out_of_time.skip(
                    f"домен исчерпал отведённые ему {config.domain_budget:.0f} с "
                    "— проверка не запускалась",
                    kind="timeout",
                )
                report.checks.append(out_of_time)
                continue
            report.checks.append(run_check(check, ctx))
    finally:
        ctx.session.close()

    report.duration_ms = int((time.monotonic() - started) * 1000)
    return score_report(report)


def scan_domains(
    raws: Iterable[str],
    config: Config,
    on_done: Callable[[DomainReport], None] | None = None,
) -> list[DomainReport]:
    """Scan many domains concurrently, preserving input order in the result."""
    items = [r for r in (s.strip() for s in raws) if r and not r.startswith("#")]
    if not items:
        return []

    reports: dict[int, DomainReport] = {}
    workers = max(1, min(config.workers, len(items)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_domain, raw, config): i for i, raw in enumerate(items)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                report = future.result()
            except Exception as exc:  # noqa: BLE001 - never lose the whole batch
                report = DomainReport(domain=items[index], raw_input=items[index])
                failed = CheckResult(name="scan")
                failed.fail(f"{type(exc).__name__}: {exc}")
                report.checks.append(failed)
                report.verdict = "ERROR"
            reports[index] = report
            if on_done:
                on_done(report)
    return [reports[i] for i in sorted(reports)]
