"""Background scan runner.

Scans take tens of seconds per domain, far too long for a request/response
cycle, so the API queues them and the UI polls. An in-process thread pool is
the right size for this: single VPS, one operator, no extra broker to run.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from ..config import Config
from ..footprint import analyze
from ..models import DomainReport
from ..scanner import scan_domain
from .db import Database

log = logging.getLogger("domain_scanner.jobs")


class ScanRunner:
    """Runs queued scans, one worker per scan, N domains in parallel inside it."""

    def __init__(self, db: Database, config: Config, max_concurrent_scans: int = 2) -> None:
        self.db = db
        self.config = config
        self._pool = ThreadPoolExecutor(
            max_workers=max_concurrent_scans, thread_name_prefix="scan"
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

    def _run(self, scan_id: str, domains: list[str]) -> None:
        self.db.set_scan_status(scan_id, "running")
        reports: list[DomainReport] = []
        try:
            workers = max(1, min(self.config.workers, len(domains)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(scan_domain, d, self.config): d for d in domains}
                for future in futures:
                    if self.is_cancelled(scan_id):
                        future.cancel()
                for future, domain in futures.items():
                    if self.is_cancelled(scan_id):
                        break
                    try:
                        report = future.result()
                    except Exception:  # noqa: BLE001 - one bad domain must not kill the scan
                        log.exception("scan failed for %s", domain)
                        continue
                    reports.append(report)
                    self.db.add_result(scan_id, report.to_dict())

            if self.is_cancelled(scan_id):
                self.db.set_scan_status(scan_id, "failed", "cancelled")
                with self._lock:
                    self._cancelled.discard(scan_id)
                return

            if len(reports) > 1:
                self.db.set_footprint(scan_id, [l.to_dict() for l in analyze(reports)])
            self.db.set_scan_status(scan_id, "done")
        except Exception as exc:  # noqa: BLE001
            log.exception("scan %s failed", scan_id)
            self.db.set_scan_status(scan_id, "failed", f"{type(exc).__name__}: {exc}")
