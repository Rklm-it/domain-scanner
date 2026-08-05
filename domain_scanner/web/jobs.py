"""Background scan runner.

Scans take tens of seconds per domain, far too long for a request/response
cycle, so the API queues them and the UI polls. An in-process thread pool is
the right size for this: single VPS, one operator, no extra broker to run.

Everything here is built around one rule: a scan must end. A scan that never
finishes does not just lose its own results -- it holds a slot in a pool only a
few scans wide, so every scan submitted afterwards sits in the queue behind it
and the operator sees the whole tool hang.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait

from ..config import Config
from ..footprint import analyze
from ..models import CheckResult, DomainReport
from ..scanner import scan_domain
from ..scoring import score_report
from .db import Database

log = logging.getLogger("domain_scanner.jobs")

# How often the runner comes up for air while waiting on domains: how quickly
# a cancel takes effect, and how fresh the progress counter is.
TICK = 1.0


class ScanRunner:
    """Runs queued scans, one worker per scan, N domains in parallel inside it."""

    def __init__(self, db: Database, config: Config, max_concurrent_scans: int = 4,
                 monitor=None) -> None:
        self.db = db
        self.config = config
        # Optional ConnectivityMonitor. Scans wait for its first probe so a
        # host that cannot reach the internet is not mistaken for a batch of
        # broken domains.
        self.monitor = monitor
        self.capacity = max(1, max_concurrent_scans)
        self._pool = ThreadPoolExecutor(
            max_workers=self.capacity, thread_name_prefix="scan"
        )
        self._cancelled: set[str] = set()
        self._lock = threading.Lock()

    def submit(self, scan_id: str, domains: list[str]) -> None:
        self._pool.submit(self._run, scan_id, domains)

    def cancel(self, scan_id: str) -> None:
        with self._lock:
            self._cancelled.add(scan_id)

    def is_cancelled(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._cancelled

    def shutdown(self, wait: bool = False) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=True)

    # ------------------------------------------------------------------ budget

    def _budget(self, count: int, workers: int) -> float:
        """Seconds this batch is allowed to take, end to end.

        Domains run ``workers`` at a time, so a batch is that many waves deep;
        each wave gets one domain timeout. The absolute cap keeps a 50-domain
        batch from turning into an open-ended job.
        """
        waves = math.ceil(count / max(1, workers))
        return min(self.config.domain_timeout * waves, self.config.scan_timeout)

    # --------------------------------------------------------------------- run

    def _run(self, scan_id: str, domains: list[str]) -> None:
        if self.monitor is not None:
            self.monitor.wait_ready(timeout=45.0)
        self.db.set_scan_status(scan_id, "running")
        reports: list[DomainReport] = []
        try:
            workers = max(1, min(self.config.workers, len(domains)))
            deadline = time.monotonic() + self._budget(len(domains), workers)
            # Not a context manager: exiting one joins every worker thread, so
            # a scan that gave up on a stuck domain would go right back to
            # waiting for it. Abandoned threads unwind on their own once their
            # socket timeouts expire.
            pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="domain")
            futures: dict[Future, str] = {
                pool.submit(scan_domain, d, self.config): d for d in domains
            }
            pending = set(futures)
            cancelled = False

            def harvest(done: set[Future]) -> None:
                for future in done:
                    domain = futures[future]
                    try:
                        report = future.result()
                    except Exception as exc:  # noqa: BLE001 - one bad domain must not kill the scan
                        log.exception("scan failed for %s", domain)
                        report = _failed_report(
                            domain, f"проверка упала: {type(exc).__name__}: {exc}"
                        )
                    reports.append(report)
                    self.db.add_result(scan_id, report.to_dict())

            while pending:
                if self.is_cancelled(scan_id):
                    cancelled = True
                    break
                if time.monotonic() >= deadline:
                    break
                # Wake up regularly rather than blocking on the whole set, so
                # results land in the database as they arrive and cancelling
                # takes effect within a tick.
                done, pending = wait(pending, timeout=TICK, return_when=FIRST_COMPLETED)
                harvest(done)

            # A domain that finished in the gap between the last poll and the
            # deadline has a real result; do not throw it away and call it a
            # timeout.
            if pending and not cancelled:
                done, pending = wait(pending, timeout=0)
                harvest(done)

            # Anything still running has outlived its budget. Record it as a
            # result rather than dropping it: the progress bar has to reach the
            # end, and "this domain timed out" is information the operator
            # needs, not something to hide.
            timed_out = sorted(futures[f] for f in pending) if not cancelled else []
            for domain in timed_out:
                report = _failed_report(
                    domain,
                    f"домен не уложился в {self.config.domain_timeout:.0f} с и был "
                    "снят — обычно это неотвечающий сайт или бесконечная цепочка "
                    "редиректов",
                )
                reports.append(report)
                self.db.add_result(scan_id, report.to_dict())
            if timed_out:
                log.warning("scan %s abandoned %d domain(s) on timeout: %s",
                            scan_id, len(timed_out), ", ".join(timed_out))

            pool.shutdown(wait=False, cancel_futures=True)

            if cancelled:
                self.db.set_scan_status(scan_id, "failed", "отменено")
                with self._lock:
                    self._cancelled.discard(scan_id)
                return

            if len(reports) > 1:
                self.db.set_footprint(scan_id, [l.to_dict() for l in analyze(reports)])
            self.db.set_scan_status(scan_id, "done")
        except Exception as exc:  # noqa: BLE001
            log.exception("scan %s failed", scan_id)
            self.db.set_scan_status(scan_id, "failed", f"{type(exc).__name__}: {exc}")


def _failed_report(domain: str, reason: str) -> DomainReport:
    """A placeholder result so a domain that blew up still shows up."""
    report = DomainReport(domain=domain, raw_input=domain)
    failed = CheckResult(name="scan")
    failed.fail(reason)
    report.checks.append(failed)
    score_report(report)
    report.verdict = "ERROR"
    return report
