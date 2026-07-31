"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import all_checks
from .config import Config, load_dotenv
from .footprint import analyze
from .report import (
    Painter,
    render_footprint,
    render_report,
    render_summary,
    to_csv,
    to_json,
    to_markdown,
    use_color,
)
from .preflight import run_preflight
from .scanner import scan_domains

EXIT_CLEAN = 0
EXIT_RISKY = 1
EXIT_ERROR = 2


class InputError(Exception):
    """A problem with the domains the user supplied."""


def read_domains(args: argparse.Namespace) -> list[str]:
    domains: list[str] = list(args.domains or [])
    if args.file:
        for path in args.file:
            if path == "-":
                domains.extend(sys.stdin.read().splitlines())
                continue
            try:
                text = Path(path).read_text(encoding="utf-8")
            except OSError as exc:
                raise InputError(f"cannot read {path}: {exc.strerror}") from exc
            domains.extend(text.splitlines())
    if not domains and not sys.stdin.isatty():
        domains.extend(sys.stdin.read().splitlines())
    # Split comma-separated pastes and drop comments/blanks.
    expanded: list[str] = []
    for item in domains:
        item = item.split("#", 1)[0]
        expanded.extend(part.strip() for part in item.replace(",", " ").split())
    seen: set[str] = set()
    unique: list[str] = []
    for d in expanded:
        key = d.lower()
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def preflight(config: Config, stream, paint: Painter) -> None:
    """Check this machine's own connectivity before blaming any domain."""
    state = run_preflight(config)
    if not state.http_ok:
        print(paint("warning: no outbound HTTPS from this machine "
                    f"({state.http_detail}). Checks that need it will be skipped, not "
                    "counted against the domains.", "\033[93m"), file=stream)
    if not state.dns_ok:
        print(paint("warning: DNS resolution is not working "
                    f"({state.dns_detail}). DNS-based checks will be skipped.", "\033[93m"),
              file=stream)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-scanner",
        description="Check domains for the history and setup problems that get ad "
                    "accounts pushed into verification.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  domain-scanner example.com\n"
            "  domain-scanner -f domains.txt --csv out.csv\n"
            "  domain-scanner -f domains.txt --footprint -v\n"
            "  domain-scanner example.com --only rdap,wayback,crtsh\n"
        ),
    )
    parser.add_argument("domains", nargs="*", help="domains or URLs to scan")
    parser.add_argument("-f", "--file", action="append",
                        help="file with one domain per line ('-' for stdin)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show info-level findings, raw detail and per-check timings")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="print only the summary table")

    out = parser.add_argument_group("output")
    out.add_argument("--json", metavar="PATH", help="write full JSON results ('-' for stdout)")
    out.add_argument("--csv", metavar="PATH", help="write a CSV summary ('-' for stdout)")
    out.add_argument("--markdown", metavar="PATH", help="write a Markdown report ('-' for stdout)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    sel = parser.add_argument_group("checks")
    sel.add_argument("--only", metavar="LIST", help="comma-separated checks to run")
    sel.add_argument("--skip", metavar="LIST", help="comma-separated checks to skip")
    sel.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    sel.add_argument("--footprint", action="store_true",
                     help="also report attributes shared across the scanned batch")

    net = parser.add_argument_group("network")
    net.add_argument("-w", "--workers", type=int, default=8,
                     help="domains scanned in parallel (default: 8)")
    net.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout in seconds")
    net.add_argument("--dns-timeout", type=float, default=6.0, help="DNS timeout in seconds")
    net.add_argument("--nameserver", action="append", metavar="IP",
                     help="resolver to use for DNS and blocklist queries (repeatable). "
                          "Blocklists refuse queries from public resolvers, so point this "
                          "at your ISP or a local resolver.")
    net.add_argument("--proxy", metavar="URL", help="HTTP(S) proxy for outbound requests")
    net.add_argument("--env-file", default=".env", help="path to a .env file (default: .env)")
    net.add_argument("--no-preflight", action="store_true",
                     help="skip the connectivity self-test")

    parser.add_argument("--fail-over", type=int, metavar="SCORE", default=40,
                        help="exit with status 1 if any domain scores at or above this "
                             "(default: 40)")
    parser.add_argument("--version", action="version", version=f"domain-scanner {__version__}")
    return parser


def write_output(path: str, content: str, label: str) -> None:
    if path == "-":
        sys.stdout.write(content if content.endswith("\n") else content + "\n")
    else:
        Path(path).write_text(content, encoding="utf-8")
        print(f"{label} written to {path}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        for check in all_checks():
            needs = f"  (needs {', '.join(check.requires)})" if check.requires else ""
            print(f"  {check.name:<14} {check.description}{needs}")
        return EXIT_CLEAN

    load_dotenv(args.env_file)
    config = Config.from_env(
        http_timeout=args.timeout,
        dns_timeout=args.dns_timeout,
        nameservers=args.nameserver,
        proxy=args.proxy,
        workers=args.workers,
    )
    known = {c.name for c in all_checks()}
    if args.only:
        requested = {s.strip() for s in args.only.split(",") if s.strip()}
        unknown = requested - known
        if unknown:
            parser.error(f"unknown check(s): {', '.join(sorted(unknown))}")
        config.enabled_checks = requested
    if args.skip:
        requested = {s.strip() for s in args.skip.split(",") if s.strip()}
        unknown = requested - known
        if unknown:
            parser.error(f"unknown check(s): {', '.join(sorted(unknown))}")
        config.disabled_checks = requested

    try:
        domains = read_domains(args)
    except InputError as exc:
        parser.error(str(exc))
    if not domains:
        parser.error("no domains given (pass them as arguments, with -f, or on stdin)")

    to_stdout = {args.json, args.csv, args.markdown} & {"-"}
    stream = sys.stderr if to_stdout else sys.stdout
    paint = Painter(use_color(stream) and not args.no_color)

    if not args.no_preflight:
        preflight(config, stream, paint)

    if len(domains) > 1 and not to_stdout:
        print(f"scanning {len(domains)} domains with {config.workers} workers...",
              file=stream)

    reports = scan_domains(domains, config)
    links = analyze(reports) if args.footprint else []

    if not to_stdout:
        if not args.quiet:
            for report in sorted(reports, key=lambda r: -r.score):
                print(render_report(report, paint, args.verbose), file=stream)
                print(file=stream)
        if len(reports) > 1:
            print(render_summary(reports, paint), file=stream)
            print(file=stream)
        if args.footprint:
            print(render_footprint(links, paint), file=stream)
            print(file=stream)

    if args.json:
        write_output(args.json, to_json(reports, links), "JSON")
    if args.csv:
        write_output(args.csv, to_csv(reports), "CSV")
    if args.markdown:
        write_output(args.markdown, to_markdown(reports, links), "Markdown")

    if any(r.verdict in ("INVALID", "ERROR") for r in reports):
        return EXIT_ERROR
    if any(r.score >= args.fail_over for r in reports):
        return EXIT_RISKY
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
