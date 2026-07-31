"""FastAPI application: REST API plus the single-page UI."""

from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..config import Config, load_dotenv
from ..models import DomainReport
from ..preflight import ConnectivityMonitor
from ..report import to_csv, to_json, to_markdown
from ..utils import DomainParseError, parse_domain
from .db import VALID_OUTCOMES, Database
from .jobs import ScanRunner

log = logging.getLogger("domain_scanner.web")

STATIC_DIR = Path(__file__).parent / "static"
MAX_DOMAINS_PER_SCAN = int(os.getenv("MAX_DOMAINS_PER_SCAN", "50"))


# --------------------------------------------------------------------- schemas


class ScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1)
    label: str | None = Field(None, max_length=120)


class OutcomeRequest(BaseModel):
    outcome: str
    note: str | None = Field(None, max_length=500)


# ------------------------------------------------------------------------ auth


class Auth:
    """Shared-token auth.

    Deliberately simple: this is a single-operator tool, and the thing that
    matters is that a public URL is not an open scanning proxy for anyone who
    finds it.
    """

    def __init__(self, token: str | None) -> None:
        self.token = token

    @property
    def enabled(self) -> bool:
        return bool(self.token)

    def check(self, request: Request) -> None:
        if not self.enabled:
            return
        supplied = (
            request.headers.get("X-Auth-Token")
            or request.cookies.get("scanner_token")
            or ""
        )
        header = request.headers.get("Authorization", "")
        if not supplied and header.lower().startswith("bearer "):
            supplied = header[7:]
        if not secrets.compare_digest(supplied, self.token or ""):
            raise HTTPException(status_code=401, detail="invalid or missing token")


def client_key(request: Request, trust_proxy: bool) -> str:
    """Identify the caller for rate limiting.

    Behind a reverse proxy every request appears to come from 127.0.0.1, which
    would turn a per-client limit into one global bucket. Only trust
    X-Forwarded-For when explicitly told to -- otherwise anyone could spoof it.
    """
    if trust_proxy:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Per-client cap on scan submissions."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> None:
        now = time.monotonic()
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        if len(hits) >= self.limit:
            raise HTTPException(
                status_code=429,
                detail=f"rate limit: {self.limit} scans per {int(self.window)}s",
            )
        hits.append(now)
        self._hits[key] = hits


# ------------------------------------------------------------------------- app


def create_app(
    db_path: str | None = None,
    config: Config | None = None,
    token: str | None = None,
) -> FastAPI:
    load_dotenv(os.getenv("ENV_FILE", ".env"))

    db = Database(db_path or os.getenv("SCANNER_DB", "data/scanner.db"))
    cfg = config or Config.from_env(
        workers=int(os.getenv("SCANNER_WORKERS", "8")),
        http_timeout=float(os.getenv("SCANNER_HTTP_TIMEOUT", "12")),
    )
    # Anything network-facing must refuse internal targets.
    cfg.block_private_targets = True
    if os.getenv("SCANNER_NAMESERVER"):
        cfg.nameservers = [
            ns.strip() for ns in os.environ["SCANNER_NAMESERVER"].split(",") if ns.strip()
        ]

    auth = Auth(token if token is not None else os.getenv("SCANNER_TOKEN") or None)
    limiter = RateLimiter(
        limit=int(os.getenv("SCANNER_RATE_LIMIT", "20")),
        window=float(os.getenv("SCANNER_RATE_WINDOW", "3600")),
    )
    trust_proxy = os.getenv("SCANNER_TRUST_PROXY", "0") == "1"
    runner = ScanRunner(db, cfg, int(os.getenv("SCANNER_MAX_CONCURRENT_SCANS", "2")))
    monitor = ConnectivityMonitor(
        cfg,
        interval=float(os.getenv("SCANNER_PREFLIGHT_INTERVAL", "300")),
        enabled=os.getenv("SCANNER_PREFLIGHT", "1") != "0",
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Establish what this host can actually reach before scanning anything,
        # and keep re-checking so a recovered uplink is picked up on its own.
        monitor.start()
        yield
        monitor.stop()
        runner.shutdown()

    app = FastAPI(title="domain-scanner", version=__version__, docs_url="/api/docs",
                  openapi_url="/api/openapi.json", lifespan=lifespan)
    app.state.db = db
    app.state.config = cfg
    app.state.auth = auth
    app.state.runner = runner
    app.state.monitor = monitor

    if not auth.enabled:
        log.warning(
            "SCANNER_TOKEN is not set - the API is unauthenticated. Set it before "
            "exposing this to the internet."
        )

    def require_auth(request: Request) -> None:
        auth.check(request)

    # Everything on this router is behind the token. Health and session sit on
    # the app itself: one must answer before login, the other performs it.
    api = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

    # ---------------------------------------------------------------- health

    @app.get("/api/health")
    def health() -> dict:
        state = monitor.state
        return {
            "status": "degraded" if state.degraded else "ok",
            "version": __version__,
            "auth_required": auth.enabled,
            "connectivity": {
                "http": state.http_ok,
                "dns": state.dns_ok,
                "http_detail": "" if state.http_ok else state.http_detail,
                "dns_detail": "" if state.dns_ok else state.dns_detail,
                "checked_at": state.checked_at,
            },
            "checks_configured": {
                "safe_browsing": bool(cfg.safe_browsing_key),
                "virustotal": bool(cfg.virustotal_key),
            },
        }

    @app.post("/api/session")
    def login(request: Request, response: Response) -> dict:
        """Exchange a token for a cookie so the UI does not hold it in JS."""
        auth.check(request)
        if auth.enabled:
            token_value = (
                request.headers.get("X-Auth-Token")
                or request.headers.get("Authorization", "")[7:]
            )
            response.set_cookie(
                "scanner_token", token_value, httponly=True, samesite="strict",
                secure=request.url.scheme == "https", max_age=30 * 86400,
            )
        return {"ok": True}

    # ----------------------------------------------------------------- scans

    @api.post("/scans", status_code=202)
    def create_scan(payload: ScanRequest, request: Request) -> dict:
        limiter.check(client_key(request, trust_proxy))

        cleaned: list[str] = []
        rejected: list[dict] = []
        seen: set[str] = set()
        for raw in payload.domains:
            for part in raw.replace(",", " ").split():
                part = part.split("#", 1)[0].strip()
                if not part:
                    continue
                try:
                    domain = parse_domain(part)[0]
                except DomainParseError as exc:
                    rejected.append({"input": part, "reason": str(exc)})
                    continue
                if domain not in seen:
                    seen.add(domain)
                    cleaned.append(domain)

        if not cleaned:
            raise HTTPException(400, detail={"error": "no valid domains", "rejected": rejected})
        if len(cleaned) > MAX_DOMAINS_PER_SCAN:
            raise HTTPException(
                400, detail=f"too many domains ({len(cleaned)}); "
                            f"limit is {MAX_DOMAINS_PER_SCAN} per scan",
            )

        scan_id = db.create_scan(cleaned, payload.label)
        runner.submit(scan_id, cleaned)
        return {"scan_id": scan_id, "domains": cleaned, "rejected": rejected}

    @api.get("/scans")
    def list_scans(limit: int = Query(50, le=200), offset: int = 0) -> dict:
        return {"scans": db.list_scans(limit, offset)}

    @api.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, detail="no such scan")
        results = db.get_results(scan_id)
        outcomes = db.get_outcomes([r["domain"] for r in results])
        for result in results:
            entry = outcomes.get(result["domain"])
            result["outcome"] = entry["outcome"] if entry else None
            result["outcome_note"] = entry["note"] if entry else None
        return {"scan": scan, "results": results}

    @api.delete("/scans/{scan_id}")
    def delete_scan(scan_id: str) -> dict:
        if not db.delete_scan(scan_id):
            raise HTTPException(404, detail="no such scan")
        return {"deleted": scan_id}

    @api.post("/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str) -> dict:
        if db.get_scan(scan_id) is None:
            raise HTTPException(404, detail="no such scan")
        runner.cancel(scan_id)
        return {"cancelling": scan_id}

    @api.get("/scans/{scan_id}/export")
    def export_scan(scan_id: str, format: str = Query("json")) -> Response:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, detail="no such scan")
        reports = [_rehydrate(r) for r in db.get_results(scan_id)]
        links = [_Link(l) for l in scan["footprint"]]
        stamp = time.strftime("%Y%m%d-%H%M", time.localtime(scan["created_at"]))

        if format == "csv":
            body, media, ext = to_csv(reports), "text/csv", "csv"
        elif format in ("md", "markdown"):
            body, media, ext = to_markdown(reports, links), "text/markdown", "md"
        elif format == "json":
            body, media, ext = to_json(reports, links), "application/json", "json"
        else:
            raise HTTPException(400, detail="format must be json, csv or md")
        return Response(
            content=body,
            media_type=media,
            headers={
                "Content-Disposition":
                    f'attachment; filename="scan-{stamp}-{scan_id[:8]}.{ext}"'
            },
        )

    # -------------------------------------------------------------- outcomes

    @api.get("/domains")
    def domain_history(limit: int = Query(200, le=1000)) -> dict:
        return {"domains": db.domain_history(limit), "totals": db.outcome_totals()}

    @api.put("/domains/{domain}/outcome")
    def set_outcome(domain: str, payload: OutcomeRequest) -> dict:
        if payload.outcome not in VALID_OUTCOMES:
            raise HTTPException(
                400, detail=f"outcome must be one of {sorted(VALID_OUTCOMES)}"
            )
        try:
            normalized = parse_domain(domain)[0]
        except DomainParseError as exc:
            raise HTTPException(400, detail=str(exc)) from exc
        db.set_outcome(normalized, payload.outcome, payload.note)
        return {"domain": normalized, "outcome": payload.outcome}

    @api.get("/calibration")
    def calibration() -> dict:
        """Which findings actually predicted trouble, per recorded outcomes."""
        return {"codes": db.calibration(), "totals": db.outcome_totals()}

    app.include_router(api)

    # -------------------------------------------------------------------- UI

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    @app.get("/robots.txt", include_in_schema=False)
    def robots() -> PlainTextResponse:
        return PlainTextResponse("User-agent: *\nDisallow: /\n")

    @app.exception_handler(DomainParseError)
    def _bad_domain(_request: Request, exc: DomainParseError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app


class _Link:
    """Adapts a stored footprint dict back to what the renderers expect."""

    def __init__(self, data: dict) -> None:
        self.kind = data.get("kind", "")
        self.value = data.get("value", "")
        self.domains = data.get("domains", [])
        self.severity = data.get("severity", "low")
        self.message = data.get("message", "")
        self.detail = data.get("detail", {})

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "value": self.value, "domains": self.domains,
            "severity": self.severity, "message": self.message, "detail": self.detail,
        }


def _rehydrate(payload: dict) -> DomainReport:
    """Rebuild a DomainReport from stored JSON so the CLI renderers can be reused."""
    from ..models import CheckResult, Finding

    report = DomainReport(
        domain=payload["domain"],
        raw_input=payload.get("input", payload["domain"]),
        score=payload.get("score", 0),
        verdict=payload.get("verdict", "UNKNOWN"),
        scanned_at=payload.get("scanned_at", 0.0),
        duration_ms=payload.get("duration_ms", 0),
    )
    for check in payload.get("checks", []):
        result = CheckResult(
            name=check["name"],
            status=check.get("status", "ok"),
            data=check.get("data", {}),
            error=check.get("error"),
            duration_ms=check.get("duration_ms", 0),
            skip_kind=check.get("skip_kind"),
        )
        for finding in check.get("findings", []):
            result.findings.append(Finding(
                code=finding["code"],
                severity=finding["severity"],
                message=finding["message"],
                detail=finding.get("detail", {}),
                weight=finding.get("weight"),
            ))
        report.checks.append(result)
    return report
