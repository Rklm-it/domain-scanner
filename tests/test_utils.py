import pytest

from domain_scanner.utils import (
    DomainParseError,
    RateLimiter,
    extract_domains,
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


# ------------------------------------------- вытаскивание домена из текста
#
# Списки доменов приходят из таблиц и чатов: с отступами, с пометками справа,
# URL-ами целиком. Раньше строка резалась по пробелам и каждое слово пометки
# объявлялось «отклонённым доменом» — экран мусора, в котором терялась
# единственная строка с настоящей опечаткой.


def only(text):
    domains, unusable = extract_domains(text)
    assert unusable == [], unusable
    return domains


@pytest.mark.parametrize("line,expected", [
    ("   padded.com   ", "padded.com"),
    ("\t\ttabbed.com\t", "tabbed.com"),
    ("noted.com  — акк 3, улетел на верифу", "noted.com"),
    ("noted.com - account 3, dead", "noted.com"),
    ("shop.com: наш основной ленд", "shop.com"),
    ("https://url.com/lp/index.html?utm=x&a=1", "url.com"),
    ("http://www.WWWish.com/", "wwwish.com"),
    ("«quoted.com»", "quoted.com"),
    ("[bracketed.com]", "bracketed.com"),
    ("(parens.com)", "parens.com"),
    ("port.com:8080/lp", "port.com"),
    ("trailing-dot.com.", "trailing-dot.com"),
    ("multi.level.co.uk  проверить", "level.co.uk"),
])
def test_extract_pulls_one_domain_out_of_a_messy_line(line, expected):
    assert only(line) == [expected]


def test_extract_keeps_several_domains_on_one_line():
    assert only("a.com, b.com;  c.com   d.com") == ["a.com", "b.com", "c.com", "d.com"]


def test_extract_deduplicates_across_lines():
    assert only("a.com\nA.COM\nhttps://www.a.com/lp\nb.com") == ["a.com", "b.com"]


def test_extract_preserves_input_order():
    assert only("z.com\nm.com\na.com") == ["z.com", "m.com", "a.com"]


def test_extract_drops_comments():
    assert only("a.com # старый\n# целиком коммент\nb.com") == ["a.com", "b.com"]


@pytest.mark.parametrize("prose", [
    "конверт 3.5% и т.д.",
    "смотри в доке, стр. 12",
    "Ленды на июль:",
    "проверить всё это завтра",
])
def test_extract_finds_nothing_in_prose(prose):
    domains, unusable = extract_domains(prose)
    assert domains == []
    assert len(unusable) == 1


@pytest.mark.parametrize("name", [
    "report.pdf", "screenshot.png", "выгрузка.xlsx", "index.html", "config.json",
])
def test_extract_ignores_filenames_shaped_like_domains(name):
    """A file extension is not a zone -- .pdf and .png are not delegated."""
    assert extract_domains(f"приложил {name}")[0] == []


@pytest.mark.parametrize("real", ["archive.zip", "clip.mov", "script.sh", "app.py"])
def test_extract_keeps_names_whose_suffix_is_a_real_tld(real):
    """.zip, .mov, .sh and .py are actual TLDs; they must not be filtered out."""
    assert extract_domains(real)[0] == [real]


def test_extract_reports_the_whole_line_it_could_not_use():
    domains, unusable = extract_domains("good.com\nnot a domain!!\nalso-good.com")
    assert domains == ["good.com", "also-good.com"]
    assert [line for line, _ in unusable] == ["not a domain!!"]


@pytest.mark.parametrize("line,reason", [
    ("8.8.8.8", "это IP-адрес, а не домен"),
    ("user@mail.ru", "это почта — нужен домен без имени ящика"),
    ("broken,com", "нет точки — на домен не похоже"),
])
def test_extract_says_why_a_line_was_unusable(line, reason):
    assert extract_domains(line)[1] == [(line, reason)]


def test_extract_does_not_mistake_an_email_for_its_domain():
    """Guessing that a mailbox meant its domain is a guess; say so instead."""
    assert extract_domains("контакт: sales@example.com")[0] == []


def test_extract_handles_idn():
    assert only("пример.рф  — тестовый") == ["xn--e1afmkfd.xn--p1ai"]


def test_extract_ignores_blank_lines_silently():
    assert extract_domains("a.com\n\n   \n\nb.com") == (["a.com", "b.com"], [])


def test_extract_does_not_split_a_url_path_into_a_second_domain():
    """"site.com/a/index.html" is one domain, not "site.com" plus "index.html"."""
    assert only("https://site.com/a/index.html") == ["site.com"]


# ------------------------------- домен с пробелом внутри (артефакт вставки)
#
# Копирование URL из PDF, чата или отрендеренной страницы регулярно вставляет
# пробел после точки: "https://www.leoslo. com/фывфыв". Для человека это тот же
# домен, для парсера — мусор.


@pytest.mark.parametrize("line,expected", [
    ("https://www.leoslo. com/фывфыв", "leoslo.com"),
    ("https://pusteblume-auringen. de/", "pusteblume-auringen.de"),
    ("www.example. com", "example.com"),
    ("https://a. b. example. com/lp", "example.com"),          # сломана дважды
    ("https://spaced. de/  — акк 3, живой", "spaced.de"),      # ещё и с пометкой
    ("leoslo. com", "leoslo.com"),                             # без схемы вообще
    ("shop . example . co.uk", "example.co.uk"),               # пробелы с двух сторон
    ("пример. рф", "xn--e1afmkfd.xn--p1ai"),
])
def test_extract_repairs_a_space_inside_the_domain(line, expected):
    assert only(line) == [expected]


@pytest.mark.parametrize("prose", [
    "Ленды на июль. Проверить всё завтра",
    "Домен умер. Заменил на новый",
    "конверт 3.5%. Дальше посмотрим",
    "смотри в доке. Страница 12",
])
def test_repair_does_not_glue_a_full_stop_in_prose(prose):
    """"Ленды на июль. Проверить" must not become июль.Проверить."""
    assert extract_domains(prose)[0] == []


@pytest.mark.parametrize("prose", [
    "Проверить все.Завтра",
    "Всё ок.Работает",
    "Умер.Заменил",
])
def test_cyrillic_prose_without_a_space_is_not_a_domain(prose):
    """A missing space after a full stop is the one case the shape cannot rule
    out, so the Cyrillic zones are checked against the real, short list."""
    assert extract_domains(prose)[0] == []


@pytest.mark.parametrize("domain", ["пример.рф", "тест.москва", "сайт.онлайн"])
def test_real_cyrillic_zones_still_work(domain):
    assert extract_domains(domain)[0] == [normalize_input(domain)]


def test_a_dot_in_a_url_path_is_left_alone():
    """"foo.com/lp. Дальше" — the break is in the path, not the host."""
    assert only("https://foo.com/lp. Дальше текст") == ["foo.com"]


def test_the_screenshot_paste():
    """Exactly what the operator pasted; two of the four used to be dropped."""
    domains, unusable = extract_domains(
        "https://jaiser-blechbearbeitung.com/\n"
        "https://www.leoslo. com/фывфыв\n"
        "https://pusteblume-auringen. de/\n"
        "https://vegassigns.co.za/\n"
    )
    assert domains == [
        "jaiser-blechbearbeitung.com",
        "leoslo.com",
        "pusteblume-auringen.de",
        "vegassigns.co.za",
    ]
    assert unusable == []
