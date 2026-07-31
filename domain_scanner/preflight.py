"""Connectivity self-test, shared by the CLI and the web app.

Without this a broken proxy, a dead uplink or blocked egress makes every domain
look like it has an unreachable landing page. The scanner must know the
difference between "the domain is broken" and "I cannot see anything".
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .config import Config
from .utils import make_resolver, make_session, probe_dns, probe_http

log = logging.getLogger("domain_scanner.preflight")


@dataclass
class Connectivity:
    http_ok: bool
    dns_ok: bool
    http_detail: str = ""
    dns_detail: str = ""
    checked_at: float = 0.0

    @property
    def degraded(self) -> bool:
        return not (self.http_ok and self.dns_ok)


def run_preflight(config: Config, apply: bool = True) -> Connectivity:
    """Probe outbound HTTP and DNS, optionally writing the result into config."""
    session = make_session(config.proxy)
    try:
        http_ok, http_detail = probe_http(session, min(10.0, config.http_timeout))
    finally:
        session.close()
    dns_ok, dns_detail = probe_dns(
        make_resolver(config.dns_timeout, config.nameservers), config.dns_timeout
    )
    result = Connectivity(http_ok, dns_ok, http_detail, dns_detail, time.time())
    if apply:
        config.http_available = http_ok
        config.dns_available = dns_ok
    return result


class ConnectivityMonitor:
    """Keeps a long-running process's view of its own connectivity fresh.

    A server started while the uplink was down must recover on its own once the
    uplink returns, rather than skipping HTTP checks until someone restarts it.
    """

    def __init__(self, config: Config, interval: float = 300.0,
                 enabled: bool = True) -> None:
        self.config = config
        self.interval = interval
        # Turning this off assumes full connectivity. Useful when egress blocks
        # the control hosts but real scanning works, and in tests.
        self.enabled = enabled
        self.state = Connectivity(True, True)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def check_now(self) -> Connectivity:
        self.state = run_preflight(self.config)
        if self.state.degraded:
            log.warning(
                "connectivity degraded: http=%s (%s) dns=%s (%s)",
                self.state.http_ok, self.state.http_detail,
                self.state.dns_ok, self.state.dns_detail,
            )
        return self.state

    def start(self) -> None:
        if not self.enabled:
            self.config.http_available = True
            self.config.dns_available = True
            return
        self.check_now()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="connectivity")
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.check_now()
            except Exception:  # noqa: BLE001 - monitoring must never crash the app
                log.exception("connectivity probe failed")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
