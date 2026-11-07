import psycopg
import pytest
import socket
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

    monkeypatch.setattr(crtsh_db.socket, "gethostbyname", lambda host: "203.0.113.7")
    monkeypatch.setattr(crtsh_db.psycopg, "connect", broken_connect)
    with pytest.raises(RuntimeError, match="gave up after 2 tries.*server closed the connection unexpectedly$"):
        crtsh_db.fetch_raw("example.com", budget=60)
    assert len(tries) == 2

class FakeConnIPv4:
    def __init__(self):
        self.sql = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.sql.append(sql)
        return self

    def fetchall(self):
        return [(1, "a.example.com")]


def test_connects_to_crtsh_over_ipv4(monkeypatch):
    seen = {}
    conn = FakeConnIPv4()

    def fake_connect(**kwargs):
        seen.update(kwargs)
        return conn

    monkeypatch.setattr(crtsh_db.socket, "gethostbyname", lambda host: "203.0.113.7")
    monkeypatch.setattr(crtsh_db.psycopg, "connect", fake_connect)

    rows = crtsh_db.fetch_raw("example.com", budget=60)

    assert rows == [(1, "a.example.com")]
    assert seen["hostaddr"] == "203.0.113.7"  # the IPv4 address, so no IPv6 attempt
    assert seen["host"] == "crt.sh"
    assert "SET statement_timeout" in conn.sql[0]


def test_ipv4_lookup_failure_is_reported(monkeypatch):
    def no_dns(host):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(crtsh_db.socket, "gethostbyname", no_dns)
    monkeypatch.setattr(crtsh_db, "warn", lambda msg: None)

    try:
        crtsh_db.fetch_raw("example.com", budget=60)
    except RuntimeError as e:
        assert "IPv4 address" in str(e)
    else:
        raise AssertionError("expected RuntimeError")
