"""SQLite persistence for scans, results and outcome tracking.

Plain sqlite3 on purpose: one file to back up, no migration tooling, no ORM.
Scan history is not a nice-to-have here -- recording which domains later got
flagged is the only way to calibrate the scoring against real outcomes.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    finished_at  REAL,
    status       TEXT NOT NULL,           -- queued | running | done | failed
    label        TEXT,
    domain_count INTEGER NOT NULL DEFAULT 0,
    done_count   INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    footprint    TEXT                     -- JSON array of links
);

CREATE TABLE IF NOT EXISTS results (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    domain    TEXT NOT NULL,
    score     INTEGER NOT NULL,
    verdict   TEXT NOT NULL,
    report    TEXT NOT NULL,              -- full JSON report
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE INDEX IF NOT EXISTS idx_results_domain ON results(domain);

-- What actually happened to the domain once it carried traffic. This is the
-- ground truth the scoring can be calibrated against.
CREATE TABLE IF NOT EXISTS outcomes (
    domain     TEXT PRIMARY KEY,
    outcome    TEXT NOT NULL,             -- unknown | alive | verification | banned
    note       TEXT,
    updated_at REAL NOT NULL
);
"""

VALID_OUTCOMES = {"unknown", "alive", "verification", "banned"}


class Database:
    """Thread-safe SQLite wrapper.

    Every worker thread gets its own connection; SQLite handles cross-connection
    locking, and WAL keeps readers from blocking the writer.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._local = threading.local()
        if self.path != ":memory:":
            self._ensure_writable(Path(self.path))
        else:
            # An in-memory database must share one connection or it vanishes.
            self._shared = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared.row_factory = sqlite3.Row
            self._lock = threading.Lock()
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @staticmethod
    def _ensure_writable(db_path: Path) -> None:
        """Fail with an actionable message instead of sqlite's opaque one.

        sqlite reports "unable to open database file" for a directory it cannot
        write to, which sends people looking for a corrupt database. The usual
        cause in Docker is a bind-mounted host directory owned by root while
        the container runs unprivileged.
        """
        parent = db_path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(
                f"cannot create the database directory {parent}: {exc.strerror}"
            ) from exc
        if not os.access(parent, os.W_OK | os.X_OK):
            uid = os.getuid() if hasattr(os, "getuid") else "?"
            raise RuntimeError(
                f"the database directory {parent} is not writable by uid {uid}. "
                "In Docker this usually means a bind-mounted host directory owned "
                "by root while the container runs unprivileged -- either chown it "
                "to the container's uid, or use a named volume."
            )
        if db_path.exists() and not os.access(db_path, os.W_OK):
            raise RuntimeError(f"the database file {db_path} is not writable")

    def connect(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            return self._shared
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self.connect()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.connect().execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.connect().execute(sql, params).fetchone()

    # ------------------------------------------------------------------ scans

    def create_scan(self, domains: list[str], label: str | None = None) -> str:
        scan_id = uuid.uuid4().hex[:16]
        self.execute(
            "INSERT INTO scans (id, created_at, status, label, domain_count) "
            "VALUES (?, ?, 'queued', ?, ?)",
            (scan_id, time.time(), label, len(domains)),
        )
        return scan_id

    def set_scan_status(self, scan_id: str, status: str, error: str | None = None) -> None:
        finished = time.time() if status in ("done", "failed") else None
        self.execute(
            "UPDATE scans SET status = ?, error = ?, "
            "finished_at = COALESCE(?, finished_at) WHERE id = ?",
            (status, error, finished, scan_id),
        )

    def set_footprint(self, scan_id: str, links: list[dict]) -> None:
        self.execute("UPDATE scans SET footprint = ? WHERE id = ?",
                     (json.dumps(links, ensure_ascii=False, default=str), scan_id))

    def add_result(self, scan_id: str, report: dict) -> None:
        conn = self.connect()
        conn.execute(
            "INSERT INTO results (scan_id, domain, score, verdict, report, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, report["domain"], report["score"], report["verdict"],
             json.dumps(report, ensure_ascii=False, default=str), time.time()),
        )
        conn.execute("UPDATE scans SET done_count = done_count + 1 WHERE id = ?", (scan_id,))
        conn.commit()

    def queue_position(self, scan_id: str) -> int:
        """How many scans are waiting ahead of this one, plus itself.

        A queued scan otherwise looks identical to a hung one from the UI, and
        the difference matters: one needs patience, the other needs a look at
        the logs.
        """
        row = self.query_one(
            "SELECT COUNT(*) AS n FROM scans WHERE status = 'queued' AND created_at < "
            "(SELECT created_at FROM scans WHERE id = ?)",
            (scan_id,),
        )
        return (row["n"] if row else 0) + 1

    def running_count(self) -> int:
        row = self.query_one("SELECT COUNT(*) AS n FROM scans WHERE status = 'running'")
        return row["n"] if row else 0

    def get_scan(self, scan_id: str) -> dict | None:
        row = self.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        if row is None:
            return None
        scan = dict(row)
        scan["footprint"] = json.loads(scan["footprint"]) if scan["footprint"] else []
        return scan

    def get_results(self, scan_id: str) -> list[dict]:
        rows = self.query(
            "SELECT report FROM results WHERE scan_id = ? ORDER BY score DESC, domain",
            (scan_id,),
        )
        return [json.loads(r["report"]) for r in rows]

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict]:
        rows = self.query(
            "SELECT s.*, "
            "  (SELECT MAX(score) FROM results WHERE scan_id = s.id) AS worst_score "
            "FROM scans s ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        out = []
        for row in rows:
            scan = dict(row)
            scan.pop("footprint", None)
            out.append(scan)
        return out

    def delete_scan(self, scan_id: str) -> bool:
        cur = self.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.execute("DELETE FROM results WHERE scan_id = ?", (scan_id,))
        return cur.rowcount > 0

    # --------------------------------------------------------------- outcomes

    def set_outcome(self, domain: str, outcome: str, note: str | None = None) -> None:
        if outcome not in VALID_OUTCOMES:
            raise ValueError(f"unknown outcome: {outcome}")
        self.execute(
            "INSERT INTO outcomes (domain, outcome, note, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET outcome = excluded.outcome, "
            "note = excluded.note, updated_at = excluded.updated_at",
            (domain, outcome, note, time.time()),
        )

    def get_outcomes(self, domains: list[str] | None = None) -> dict[str, dict]:
        if domains:
            marks = ",".join("?" * len(domains))
            rows = self.query(
                f"SELECT * FROM outcomes WHERE domain IN ({marks})", tuple(domains)
            )
        else:
            rows = self.query("SELECT * FROM outcomes")
        return {r["domain"]: dict(r) for r in rows}

    def domain_history(self, limit: int = 200) -> list[dict]:
        """Latest score per domain, joined with its recorded outcome."""
        rows = self.query(
            "SELECT r.domain, r.score, r.verdict, r.created_at, "
            "       o.outcome, o.note "
            "FROM results r "
            "JOIN (SELECT domain, MAX(created_at) AS latest FROM results GROUP BY domain) m "
            "  ON r.domain = m.domain AND r.created_at = m.latest "
            "LEFT JOIN outcomes o ON o.domain = r.domain "
            "ORDER BY r.created_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def calibration(self) -> list[dict]:
        """How often each finding code appears, split by recorded outcome.

        This is the payoff of outcome tracking: if a code shows up in domains
        that got flagged far more than in domains that survived, its weight is
        earning its keep -- and if it does not, it is noise.
        """
        rows = self.query(
            "SELECT r.report, o.outcome FROM results r "
            "JOIN outcomes o ON o.domain = r.domain "
            "WHERE o.outcome IN ('alive', 'verification', 'banned')"
        )
        stats: dict[str, dict[str, Any]] = {}
        totals = {"alive": 0, "flagged": 0}
        for row in rows:
            report = json.loads(row["report"])
            bucket = "alive" if row["outcome"] == "alive" else "flagged"
            totals[bucket] += 1
            seen: set[str] = set()
            for check in report.get("checks", []):
                for finding in check.get("findings", []):
                    if (finding.get("weight") or 0) <= 0:
                        continue
                    code = finding["code"]
                    if code in seen:
                        continue
                    seen.add(code)
                    entry = stats.setdefault(
                        code, {"code": code, "alive": 0, "flagged": 0,
                               "severity": finding.get("severity")}
                    )
                    entry[bucket] += 1

        out = []
        for entry in stats.values():
            alive_rate = entry["alive"] / totals["alive"] if totals["alive"] else 0.0
            flagged_rate = entry["flagged"] / totals["flagged"] if totals["flagged"] else 0.0
            entry["alive_rate"] = round(alive_rate, 3)
            entry["flagged_rate"] = round(flagged_rate, 3)
            entry["lift"] = round(flagged_rate - alive_rate, 3)
            out.append(entry)
        out.sort(key=lambda e: -e["lift"])
        return out

    def outcome_totals(self) -> dict[str, int]:
        rows = self.query("SELECT outcome, COUNT(*) AS n FROM outcomes GROUP BY outcome")
        return {r["outcome"]: r["n"] for r in rows}
