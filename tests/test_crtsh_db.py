import psycopg
import pytest

from collectors import crtsh_db

ROWS = [
    (1, "api.example.com"),
    (1, "*.example.com"),
    (2, "docs.example.com"),
    (2, "api.example.com"),
    (3, "evil.com"),
    (3, "\x1b[31mbad.example.com"),
]


def test_parse_keeps_only_clean_domain_names():
    assert crtsh_db.parse_subdomains(ROWS, "example.com") == [
        "api.example.com", "docs.example.com", "example.com"]
    assert crtsh_db.parse_wildcards(ROWS, "example.com") == ["*.example.com"]


def test_collect_counts_each_certificate_once(monkeypatch):
    monkeypatch.setattr(crtsh_db, "fetch_raw", lambda domain, budget: ROWS)
    r = crtsh_db.collect("example.com")
    assert r["source"] == "crt.sh database"
    assert r["certificates_seen"] == 3  # ids 1, 2, 3 - not 6 rows
    assert r["subdomain_count"] == 3


def test_fetch_raw_retries_once_then_gives_up(monkeypatch):
    tries = []

    def broken_connect(**kwargs):
        tries.append(kwargs)
        raise psycopg.OperationalError("server closed the connection unexpectedly\nmore detail")

    monkeypatch.setattr(crtsh_db.psycopg, "connect", broken_connect)
    with pytest.raises(RuntimeError, match="gave up after 2 tries.*server closed the connection unexpectedly$"):
        crtsh_db.fetch_raw("example.com", budget=60)
    assert len(tries) == 2
