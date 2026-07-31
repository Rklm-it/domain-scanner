import pytest

from domain_scanner.utils import (
    DomainParseError,
    RateLimiter,
    is_ip,
    normalize_input,
    parse_domain,
    reverse_ip,
    unquote_txt,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("  example.com  ", "example.com"),
        ("https://example.com/path?a=1", "example.com"),
        ("http://www.example.com", "example.com"),
        ("WWW.Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("//example.com", "example.com"),
        ("'example.com'", "example.com"),
        ("https://sub.example.com:8443/x", "sub.example.com"),
    ],
)
def test_normalize_input(raw, expected):
    assert normalize_input(raw) == expected


def test_normalize_input_idn():
    assert normalize_input("пример.рф").startswith("xn--")


def test_normalize_input_rejects_empty():
    with pytest.raises(DomainParseError):
        normalize_input("   ")


@pytest.mark.parametrize(
    "raw,registrable,sld,suffix",
    [
        ("example.com", "example.com", "example", "com"),
        ("www.example.co.uk", "example.co.uk", "example", "co.uk"),
        ("a.b.example.co.uk", "example.co.uk", "example", "co.uk"),
        ("shop.example.com.br", "example.com.br", "example", "com.br"),
        ("deep.sub.example.io", "example.io", "example", "io"),
        ("https://my-lander.top/lp1", "my-lander.top", "my-lander", "top"),
    ],
)
def test_parse_domain(raw, registrable, sld, suffix):
    assert parse_domain(raw) == (registrable, sld, suffix)


def test_parse_domain_rejects_ip():
    with pytest.raises(DomainParseError):
        parse_domain("8.8.8.8")


def test_parse_domain_rejects_bare_label():
    with pytest.raises(DomainParseError):
        parse_domain("localhost")


def test_is_ip():
    assert is_ip("1.2.3.4")
    assert is_ip("::1")
    assert not is_ip("example.com")


def test_reverse_ip():
    assert reverse_ip("1.2.3.4") == "4.3.2.1"


def test_unquote_txt_joins_split_strings():
    assert unquote_txt('"v=spf1 " "include:_spf.example.com ~all"') == (
        "v=spf1 include:_spf.example.com ~all"
    )
    assert unquote_txt("plain") == "plain"


def test_rate_limiter_allows_burst_up_to_limit():
    limiter = RateLimiter(calls=3, period=60.0)
    for _ in range(3):
        limiter.acquire()
    assert len(limiter._hits) == 3


@pytest.mark.parametrize(
    "ip,public",
    [
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("169.254.169.254", False),   # cloud instance metadata
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("172.16.5.5", False),
        ("192.168.0.1", False),
        ("100.64.0.1", False),        # CGNAT
        ("198.18.0.1", False),        # benchmarking
        ("0.0.0.0", False),
        ("::1", False),
        ("2606:4700:4700::1111", True),
        ("not-an-ip", False),
    ],
)
def test_is_public_ip(ip, public):
    from domain_scanner.utils import is_public_ip

    assert is_public_ip(ip) is public


def test_assert_public_host_rejects_literal_private_ip():
    from domain_scanner.utils import BlockedTargetError, assert_public_host

    with pytest.raises(BlockedTargetError):
        assert_public_host("169.254.169.254")


def test_assert_public_host_allows_public_literal():
    from domain_scanner.utils import assert_public_host

    assert assert_public_host("8.8.8.8") == ["8.8.8.8"]


# ------------------------------------------------------- environment parsing


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("20", "20"),
        ("20   # scans per client", "20"),          # docker-compose env_file
        ("20\t# tab-separated comment", "20"),
        ("value#nospace", "value#nospace"),         # '#' inside a value survives
        ('"quoted # hash"', "quoted # hash"),
        ("'single quoted'", "single quoted"),
        ("  padded  ", "padded"),
        ("# whole line", ""),
        ("", ""),
    ],
)
def test_strip_inline_comment(raw, expected):
    from domain_scanner.config import strip_inline_comment

    assert strip_inline_comment(raw) == expected


def test_env_int_survives_inline_comment(monkeypatch):
    """A stray comment must not put the service into a restart loop."""
    from domain_scanner.config import env_int

    monkeypatch.setenv("X_NUM", "8   # workers")
    assert env_int("X_NUM", 99) == 8


def test_env_int_falls_back_on_garbage(monkeypatch, caplog):
    from domain_scanner.config import env_int

    monkeypatch.setenv("X_NUM", "not-a-number")
    assert env_int("X_NUM", 42) == 42


def test_env_int_uses_default_when_unset(monkeypatch):
    from domain_scanner.config import env_int

    monkeypatch.delenv("X_NUM", raising=False)
    assert env_int("X_NUM", 7) == 7


def test_env_bool_variants(monkeypatch):
    from domain_scanner.config import env_bool

    for value, expected in [("1", True), ("true", True), ("YES", True), ("on", True),
                            ("0", False), ("false", False), ("nonsense", False)]:
        monkeypatch.setenv("X_FLAG", value)
        assert env_bool("X_FLAG", False) is expected
    monkeypatch.setenv("X_FLAG", "1   # enabled")
    assert env_bool("X_FLAG", False) is True


def test_load_dotenv_handles_comments_and_export(tmp_path, monkeypatch):
    from domain_scanner.config import load_dotenv

    env = tmp_path / ".env"
    env.write_text(
        "# a comment line\n"
        "SCANNER_TOKEN=abc123\n"
        "SCANNER_WORKERS=8   # how many at once\n"
        "export SCANNER_DB=/data/x.db\n"
        'QUOTED="has # hash"\n'
        "\n"
    )
    for key in ("SCANNER_TOKEN", "SCANNER_WORKERS", "SCANNER_DB", "QUOTED"):
        monkeypatch.delenv(key, raising=False)
    load_dotenv(env)
    import os

    assert os.environ["SCANNER_TOKEN"] == "abc123"
    assert os.environ["SCANNER_WORKERS"] == "8"
    assert os.environ["SCANNER_DB"] == "/data/x.db"
    assert os.environ["QUOTED"] == "has # hash"
