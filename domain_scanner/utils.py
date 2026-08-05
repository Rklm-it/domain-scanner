"""Small helpers: domain normalisation, DNS resolver, HTTP session."""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from urllib.parse import urlparse

import dns.resolver
import requests
from requests.adapters import HTTPAdapter

# Multi-label public suffixes we care about. The full Public Suffix List is
# overkill here -- affiliate/media-buying traffic is overwhelmingly gTLD plus a
# handful of well-known second-level ccTLD suffixes.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy", "com.py",
    "co.za", "org.za", "net.za", "web.za",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.tw", "com.hk", "com.sg", "com.my", "com.ph", "com.vn", "com.tr", "com.pk",
    "co.il", "org.il", "net.il", "ac.il",
    "com.ua", "net.ua", "org.ua", "in.ua", "kiev.ua",
    "com.pl", "net.pl", "org.pl", "com.ro", "com.hr", "com.gr", "com.cy", "com.mt",
    "co.id", "or.id", "web.id", "ac.id",
    "com.eg", "com.sa", "com.ng", "com.gh", "co.ke", "co.tz", "co.ug",
    "com.pt", "com.es", "com.de", "com.se", "com.ru", "net.ru", "org.ru",
    "co.th", "in.th", "ac.th", "go.th",
}

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?$", re.IGNORECASE)


class DomainParseError(ValueError):
    pass


def normalize_input(value: str) -> str:
    """Turn anything a buyer might paste into a bare hostname.

    Accepts full URLs, ``www.`` prefixes, trailing dots, IDN, surrounding
    whitespace/quotes and inline commas.
    """
    raw = (value or "").strip().strip("\"'").strip()
    if not raw:
        raise DomainParseError("empty value")
    if "://" not in raw and not raw.startswith("//"):
        raw = "//" + raw
    parsed = urlparse(raw)
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise DomainParseError(f"cannot parse a hostname out of {value!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Leave already-punycode or otherwise odd hosts as-is.
        pass
    if host.startswith("www."):
        host = host[4:]
    return host


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_domain(value: str) -> tuple[str, str, str]:
    """Return ``(registrable_domain, sld, public_suffix)``."""
    host = normalize_input(value)
    if is_ip(host):
        raise DomainParseError(f"{value!r} is an IP address, not a domain")
    labels = host.split(".")
    if len(labels) < 2:
        raise DomainParseError(f"{value!r} has no TLD")
    for label in labels:
        if not _HOST_RE.match(label):
            raise DomainParseError(f"{value!r} contains an invalid label: {label!r}")
    last_two = ".".join(labels[-2:])
    if len(labels) >= 3 and last_two in MULTI_LABEL_SUFFIXES:
        suffix = last_two
        sld = labels[-3]
        registrable = ".".join(labels[-3:])
    else:
        suffix = labels[-1]
        sld = labels[-2]
        registrable = last_two
    return registrable, sld, suffix


# One domain, pulled out of whatever it was pasted next to.
#
# The strictness lives in the last label: letters only, at least two of them.
# That is what keeps ordinary prose out -- "конверт 3.5%", "и т.д.", a version
# number -- while still allowing IDN zones like .рф, since the character
# classes are Unicode-aware. A URL's path is swallowed whole so that
# "site.com/a/index.html" yields one domain rather than two.
_DOMAIN_TOKEN_RE = re.compile(
    r"""
    (?<![\w@.\-])                          # not mid-word, and not an email address
    (?:[a-z][a-z0-9+.\-]*://)?             # scheme, when this is a URL
    (?:[^\W_](?:[\w\-]{0,61}[^\W_])?\.)+   # one or more labels
    [^\W\d_]{2,24}                         # the suffix: letters, never digits
    (?![\w\-])                             # and the name ends here
    (?:[:/?\#]\S*)?                        # port, path, query -- consumed, not parsed
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Suffixes that match the pattern above but are file extensions, not zones.
# Only entries IANA has never delegated belong here: .zip, .mov, .sh, .js,
# .md, .py, .pl and .dev are all real TLDs and must keep working as domains.
NON_TLD_SUFFIXES = {
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "svg",
    "pdf", "txt", "rtf", "docx", "xlsx", "pptx", "odt", "csv", "tsv",
    "html", "htm", "xhtml", "css", "php", "aspx", "jsp",
    "json", "xml", "yaml", "yml", "toml", "ini", "conf", "cfg",
    "exe", "dll", "rar", "tar", "gz", "iso", "bin",
    "mp3", "mp4", "avi", "mkv", "wav", "flac", "webm",
    "log", "bak", "sql", "env",
}


def extract_domains(text: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Pull registrable domains out of arbitrary pasted text.

    Real lists are never clean. A domain arrives with a note after it, as a URL
    with a path and query, wrapped in quotes or brackets, behind stray tabs, or
    followed by a comment. Splitting on whitespace and calling every resulting
    word a candidate turns one annotated domain into a screenful of rejections,
    which is worse than useless -- it buries the line that genuinely was a typo.

    So: text around a domain is dropped silently, and a line that yields no
    domain at all is returned separately, whole, with a reason. That way the
    caller can name the one line it could not use.

    Returns ``(domains, unusable)``; domains are normalised, de-duplicated and
    in the order they appeared.
    """
    domains: list[str] = []
    unusable: list[tuple[str, str]] = []
    seen: set[str] = set()

    for line in text.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        found = False
        for match in _DOMAIN_TOKEN_RE.finditer(body):
            try:
                registrable, _sld, suffix = parse_domain(match.group(0))
            except DomainParseError:
                continue
            if suffix.rsplit(".", 1)[-1] in NON_TLD_SUFFIXES:
                continue  # a filename that happens to be shaped like a domain
            found = True
            if registrable not in seen:
                seen.add(registrable)
                domains.append(registrable)
        if not found:
            unusable.append((body[:120], _why_no_domain(body)))
    return domains, unusable


def _why_no_domain(line: str) -> str:
    """Say something more useful than "invalid" when a line yields nothing."""
    stripped = line.strip().strip("\"'<>()[]")
    if is_ip(stripped):
        return "это IP-адрес, а не домен"
    if "@" in stripped:
        return "это почта — нужен домен без имени ящика"
    if "." not in stripped:
        return "нет точки — на домен не похоже"
    return "не нашёл здесь домена"


def make_resolver(timeout: float = 6.0, nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def dns_query(
    resolver: dns.resolver.Resolver,
    name: str,
    rdtype: str,
) -> list[str]:
    """Resolve and return string answers. Empty list on NXDOMAIN/NoAnswer.

    Retries over TCP when the UDP answer is truncated or times out, which is
    common for large TXT record sets.
    """
    try:
        answers = resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        try:
            answers = resolver.resolve(name, rdtype, tcp=True)
        except Exception:
            raise
    return [r.to_text() for r in answers]


def dns_query_quiet(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    """Like :func:`dns_query` but swallows every error into an empty list."""
    try:
        return dns_query(resolver, name, rdtype)
    except Exception:
        return []


def unquote_txt(value: str) -> str:
    """dnspython renders TXT records with quotes and splits long strings."""
    parts = re.findall(r'"([^"]*)"', value)
    if parts:
        return "".join(parts)
    return value.strip('"')


USER_AGENTS = {
    "browser": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "googlebot": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    "adsbot": (
        "AdsBot-Google (+http://www.google.com/adsbot.html)"
    ),
    "mobile": (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
    ),
}


def make_session(proxy: str | None = None, retries: int = 1) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retries, pool_connections=32, pool_maxsize=32)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"Accept-Language": "en-US,en;q=0.9"})
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


class RateLimiter:
    """Simple thread-safe "N calls per period" gate for keyed APIs."""

    def __init__(self, calls: int, period: float) -> None:
        self.calls = max(1, calls)
        self.period = period
        self._lock = threading.Lock()
        self._hits: list[float] = []

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._hits = [t for t in self._hits if now - t < self.period]
                if len(self._hits) < self.calls:
                    self._hits.append(now)
                    return
                sleep_for = self.period - (now - self._hits[0]) + 0.05
            time.sleep(max(0.05, sleep_for))


# Stable endpoints used only to tell "the domain is broken" apart from
# "this machine cannot reach the internet".
CONTROL_URLS = (
    "https://www.google.com/generate_204",
    "https://one.one.one.one/",
)
CONTROL_DNS_NAMES = ("google.com", "cloudflare.com")


def probe_http(session, timeout: float = 8.0) -> tuple[bool, str]:
    """Can this machine make outbound HTTPS requests at all?"""
    last = "no attempt"
    for url in CONTROL_URLS:
        try:
            resp = session.get(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
            continue
        if resp.status_code < 400:
            return True, url
        last = f"{url} -> HTTP {resp.status_code}"
    return False, last


def probe_dns(resolver, timeout: float = 5.0) -> tuple[bool, str]:
    """Can this machine resolve public names at all?"""
    last = "no attempt"
    for name in CONTROL_DNS_NAMES:
        try:
            if dns_query(resolver, name, "A"):
                return True, name
            last = f"{name} resolved to nothing"
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
    return False, last


def reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


# Ranges Python's ipaddress does not classify as private but which are still
# never a legitimate scan target.
EXTRA_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in (
        "100.64.0.0/10",     # RFC 6598 carrier-grade NAT
        "192.0.0.0/24",      # IETF protocol assignments
        "198.18.0.0/15",     # benchmarking
        "64:ff9b::/96",      # NAT64
    )
)


class BlockedTargetError(Exception):
    """A request was aimed at an address the scanner must not touch."""


def is_public_ip(value: str) -> bool:
    """False for loopback, RFC1918, link-local, CGNAT and other reserved space.

    169.254.169.254 (cloud instance metadata) falls under link-local, which is
    the address that matters most when this runs on a VPS.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return not any(ip in net for net in EXTRA_BLOCKED_NETWORKS if ip.version == net.version)


def assert_public_host(host: str) -> list[str]:
    """Resolve ``host`` and refuse it unless every address is public.

    Raises :class:`BlockedTargetError` for internal targets. Resolution failure
    is not an error here -- the caller's own request will surface that.
    """
    if is_ip(host):
        if not is_public_ip(host):
            raise BlockedTargetError(f"{host} is not a public address")
        return [host]
    ips = resolve_host(host)
    private = [ip for ip in ips if not is_public_ip(ip)]
    if private:
        raise BlockedTargetError(
            f"{host} resolves to non-public address(es): {', '.join(private)}"
        )
    return ips


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


def days_between(later: float, earlier: float) -> int:
    return int((later - earlier) // 86400)


def human_days(days: int | None) -> str:
    if days is None:
        return "?"
    if days < 60:
        return f"{days}d"
    if days < 730:
        return f"{days // 30}mo"
    return f"{days / 365.25:.1f}y"
