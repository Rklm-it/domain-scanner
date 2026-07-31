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
