import json

import pytest

from domain_scanner.checks.base import ScanContext
from domain_scanner.config import Config
from domain_scanner.utils import parse_domain


class FakeResolver:
    """Stands in for dns.resolver.Resolver; answers come from a dict."""

    def __init__(self, answers: dict[tuple[str, str], list[str]] | None = None):
        self.answers = answers or {}
        self.queries: list[tuple[str, str]] = []

    def resolve(self, name, rdtype, tcp=False):
        self.queries.append((name, rdtype))
        key = (name.lower().rstrip("."), rdtype.upper())
        if key not in self.answers:
            import dns.resolver

            raise dns.resolver.NXDOMAIN()
        return [FakeRdata(v) for v in self.answers[key]]


class FakeRdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


def redirect_to(location: str, status: int = 302):
    """A response that sends the client somewhere else."""
    return FakeResponse(status_code=status, text="",
                        headers={"Content-Type": "text/html", "Location": location})


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text="", headers=None, url="",
                 history=None):
        self.status_code = status_code
        self._json = json_data
        if not text and json_data is not None:
            text = json.dumps(json_data)
        self.text = text
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.url = url
        self.history = history or []

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Routes requests to handlers keyed by a substring of the URL."""

    def __init__(self, routes: dict[str, object] | None = None):
        self.routes = routes or {}
        self.calls: list[tuple[str, str, dict]] = []
        self.headers: dict[str, str] = {}
        self.proxies: dict[str, str] = {}

    def _dispatch(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for fragment, response in self.routes.items():
            if fragment in url:
                if callable(response):
                    return response(url, **kwargs)
                return response
        raise ConnectionError(f"no route for {url}")

    def get(self, url, **kwargs):
        return self._dispatch("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._dispatch("POST", url, **kwargs)

    def close(self):
        pass


@pytest.fixture
def config():
    cfg = Config.from_env()
    # Unit tests use fake sessions, so there is no real host to validate.
    cfg.block_private_targets = False
    return cfg


def make_ctx(domain: str, config: Config, resolver=None, session=None, shared=None):
    registrable, sld, suffix = parse_domain(domain)
    return ScanContext(
        domain=registrable,
        sld=sld,
        suffix=suffix,
        config=config,
        resolver=resolver or FakeResolver(),
        session=session or FakeSession(),
        shared=shared or {},
    )


@pytest.fixture
def ctx_factory(config):
    def factory(domain="example.com", resolver=None, session=None, shared=None, cfg=None):
        return make_ctx(domain, cfg or config, resolver, session, shared)

    return factory
