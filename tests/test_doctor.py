"""Tests for doctor.py: every check's ok / warn / fail, with nothing real
called (no real API, no real package list)."""

import sys

import anthropic
import pytest

import doctor
import monomi
from doctor import FAIL, OK, WARN

KEY = "sk-ant-api03-" + "x" * 90  # a made-up key, never a real one


def statuses(results):
    return [r["status"] for r in results]


# ---------- helpers ----------

def test_version_tuple():
    assert doctor.version_tuple("2.34.2") == (2, 34, 2)
    assert doctor.version_tuple("1.0rc1") == (1, 0)
    assert doctor.version_tuple("3.10") > doctor.version_tuple("3.9")
    assert doctor.version_tuple("dev") == ()


def test_read_requirements(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests>=2.34.2\n# a comment\n\n"
                 "psycopg[binary]>=3.2\nrich\n", encoding="utf-8")
    assert doctor.read_requirements(f) == [
        ("requests", "2.34.2"), ("psycopg", "3.2"), ("rich", None)]


def test_plural():
    assert doctor.plural(1, "warning") == "1 warning"
    assert doctor.plural(0, "problem") == "0 problems"


# ---------- Setup ----------

def test_python_ok():
    assert statuses(doctor.check_python()) == [OK]


def test_python_too_old(monkeypatch):
    monkeypatch.setattr(doctor, "MIN_PYTHON", (99, 0))
    [r] = doctor.check_python()
    assert r["status"] == FAIL and "99.0" in r["fix"]


def fake_packages(monkeypatch, installed):
    reqs = [("requests", "2.34.2"), ("anthropic", "0.40"), ("psycopg", "3.2")]
    monkeypatch.setattr(doctor, "read_requirements", lambda: reqs)
    monkeypatch.setattr(doctor, "installed_version", installed.get)


def test_packages_all_good(monkeypatch):
    fake_packages(monkeypatch, {"requests": "2.34.2", "anthropic": "0.45.1",
                                "psycopg": "3.2.10"})
    [r] = doctor.check_packages()
    assert r["status"] == OK
    assert r["detail"] == "packages: requests, anthropic, psycopg"


def test_missing_or_old_package_fails(monkeypatch):
    fake_packages(monkeypatch, {"requests": "2.31.0", "anthropic": "0.45.1"})
    [r] = doctor.check_packages()
    assert r["status"] == FAIL
    assert "missing: psycopg" in r["detail"]
    assert "too old: requests 2.31.0 (needs 2.34.2)" in r["detail"]
    assert r["fix"] == doctor.PIP_FIX


def test_missing_anthropic_is_only_a_warning(monkeypatch):
    fake_packages(monkeypatch, {"requests": "2.34.2", "psycopg": "3.2"})
    results = doctor.check_packages()
    assert statuses(results) == [OK, WARN]
    assert "--ai is off" in results[1]["detail"]


def test_no_requirements_file(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "REQUIREMENTS", str(tmp_path / "nope.txt"))
    assert statuses(doctor.check_packages()) == [WARN]


def test_folders_writable(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "folders", lambda: {
        "scans/": str(tmp_path / "scans"), "cache/": str(tmp_path / "cache")})
    [r] = doctor.check_folders()
    assert r["status"] == OK and (tmp_path / "scans").is_dir()


def test_folder_that_cant_be_made_fails(monkeypatch, tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a folder")
    monkeypatch.setattr(doctor, "folders", lambda: {
        "scans/": str(blocker / "scans")})  # a folder inside a file can't exist
    [r] = doctor.check_folders()
    assert r["status"] == FAIL and "scans/" in r["detail"]


# ---------- Claude API ----------

def test_no_key_is_a_warning(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    [r] = doctor.check_api_key()
    assert r["status"] == WARN and "--ai is off" in r["detail"]


@pytest.mark.parametrize("bad", [f'"{KEY}"', f"{KEY} ", f"'{KEY}'"])
def test_key_with_quotes_or_spaces_fails(monkeypatch, bad):
    monkeypatch.setenv("ANTHROPIC_API_KEY", bad)
    [r] = doctor.check_api_key()
    assert r["status"] == FAIL


def test_key_is_never_shown(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setattr(doctor, "check_api_access", lambda: [])
    [r] = doctor.check_api_key()
    assert r["status"] == OK
    assert KEY not in r["detail"] and KEY[8:] not in r["detail"]
    assert f"{len(KEY)} chars" in r["detail"]


def test_key_with_wrong_start_is_a_warning(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-proj-abc123")
    monkeypatch.setattr(doctor, "check_api_access", lambda: [])
    assert statuses(doctor.check_api_key()) == [WARN]


class Model:
    def __init__(self, id):
        self.id = id


def fake_client(monkeypatch, models=None, error=None):
    """Replace anthropic.Anthropic with a fake that lists `models` or raises `error`."""
    class Models:
        def list(self, limit):
            if error:
                raise error
            return [Model(m) for m in models]

    class Client:
        def __init__(self, **kwargs):
            self.models = Models()

    monkeypatch.setattr(anthropic, "Anthropic", Client)


class FakeResponse:
    """Just enough of an HTTP response for anthropic's error classes
    (so the tests don't depend on which HTTP library anthropic uses)."""
    def __init__(self, code):
        self.status_code, self.headers, self.request = code, {}, None


def http_error(cls, code):
    return cls("nope", response=FakeResponse(code), body=None)


def test_key_accepted_shows_the_model(monkeypatch):
    monkeypatch.delenv("CLAUDE_MODEL", raising=False)
    fake_client(monkeypatch, ["claude-opus-x", "claude-sonnet-x"])
    [r] = doctor.check_api_access()
    assert r["status"] == OK and "claude-sonnet-x" in r["detail"]


def test_claude_model_not_in_the_list(monkeypatch):
    monkeypatch.setenv("CLAUDE_MODEL", "claude-typo")
    fake_client(monkeypatch, ["claude-sonnet-x"])
    [r] = doctor.check_api_access()
    assert r["status"] == WARN and "claude-typo" in r["detail"]


def test_claude_model_in_the_list(monkeypatch):
    monkeypatch.setenv("CLAUDE_MODEL", "claude-opus-x")
    fake_client(monkeypatch, ["claude-opus-x", "claude-sonnet-x"])
    [r] = doctor.check_api_access()
    assert r["status"] == OK and "(from $CLAUDE_MODEL)" in r["detail"]


@pytest.mark.parametrize("error, status", [
    (http_error(anthropic.AuthenticationError, 401), FAIL),
    (http_error(anthropic.PermissionDeniedError, 403), FAIL),
    (http_error(anthropic.InternalServerError, 500), WARN),
    (anthropic.APIConnectionError(request=None), WARN),
])
def test_api_errors(monkeypatch, error, status):
    fake_client(monkeypatch, error=error)
    [r] = doctor.check_api_access()
    assert r["status"] == status and r["fix"]


# ---------- running and showing ----------

def test_a_crashing_check_becomes_a_fail_line():
    def check_boom():
        raise ValueError("oops")

    results = doctor.run_all([doctor.check_python, check_boom])
    assert statuses(results) == [OK, FAIL]
    assert "boom check crashed: ValueError: oops" in results[1]["detail"]


def test_show_counts(capsys):
    doctor.show([doctor.result("Setup", "a", OK, "fine"),
                 doctor.result("Setup", "b", WARN, "meh", "do this")])
    out = capsys.readouterr().out
    assert "fix: do this" in out
    assert "1 ok · 1 warning · 0 problems: ready to scan" in out


def test_exit_code_is_1_when_anything_fails(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_all",
                        lambda: [doctor.result("Setup", "a", FAIL, "broken")])
    assert doctor.main(["--no-color"]) == 1
    monkeypatch.setattr(doctor, "run_all",
                        lambda: [doctor.result("Setup", "a", WARN, "meh")])
    assert doctor.main(["--no-color"]) == 0


def test_monomi_doctor_runs_the_doctor(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["monomi.py", "doctor", "--no-color"])
    monkeypatch.setattr(doctor, "run_all", lambda: [])
    assert monomi.main() == 0
    assert "monomi doctor" in capsys.readouterr().out


# ---------- DNS (d2) ----------

class FakeResolver:
    """Answers, or raises `error`, like dns.resolver.Resolver.resolve."""
    def __init__(self, error=None):
        self.error = error

    def resolve(self, name, rtype, lifetime):
        if self.error:
            raise self.error


def fake_dns(monkeypatch, system=None, public=None, doh=None):
    """system/public: an error to raise, or None. doh: {server name: error or None}."""
    monkeypatch.setattr(doctor.dnscheck, "_resolvers",
                        lambda: (FakeResolver(system), FakeResolver(public)))
    doh = doh or {}
    urls = {url: doh.get(name) for name, url in doctor.dnscheck.DOH_SERVERS.items()}

    def ask(url, name, rtype):
        if urls[url]:
            raise doctor.dnscheck.DNSLookupError(urls[url])
        return "ok", ["an-ip"]

    monkeypatch.setattr(doctor.dnscheck, "_ask_doh", ask)
    monkeypatch.setattr(doctor, "in_wsl", lambda: False)


def test_dns_all_good(monkeypatch):
    fake_dns(monkeypatch)
    results = doctor.check_dns()
    assert statuses(results) == [OK, OK, OK]
    assert results[2]["detail"] == "DNS-over-HTTPS: Cloudflare, Google"


def test_port_53_blocked_is_a_warning_while_doh_works(monkeypatch):
    fake_dns(monkeypatch, system=TimeoutError("timed out"))
    results = doctor.check_dns()
    assert statuses(results) == [WARN, OK, OK]
    assert "fall back to DNS-over-HTTPS" in results[0]["detail"]
    assert "NordVPN" in results[0]["fix"]


def test_wsl_gets_the_flushdns_tip(monkeypatch):
    fake_dns(monkeypatch, system=TimeoutError("timed out"))
    monkeypatch.setattr(doctor, "in_wsl", lambda: True)
    assert "ipconfig /flushdns" in doctor.check_dns()[0]["fix"]


def test_one_doh_server_down(monkeypatch):
    fake_dns(monkeypatch, doh={"Google": "HTTP 503"})
    doh = doctor.check_dns()[2]
    assert doh["status"] == WARN
    assert "Google failed (HTTP 503)" in doh["detail"]
    assert "Cloudflare works" in doh["detail"]


def test_all_doh_down_but_port_53_works(monkeypatch):
    fake_dns(monkeypatch, doh={"Cloudflare": "x", "Google": "y"})
    assert statuses(doctor.check_dns()) == [OK, OK, WARN]


def test_no_dns_at_all_is_one_fail_line(monkeypatch):
    fake_dns(monkeypatch, system=TimeoutError("a"), public=TimeoutError("b"),
             doh={"Cloudflare": "x", "Google": "y"})
    [r] = doctor.check_dns()
    assert r["status"] == FAIL and "failed everywhere" in r["detail"]


# ---------- Sources (d2) ----------

class FakeHTTP:
    def __init__(self, code=200, headers=None):
        self.status_code, self.headers = code, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise doctor.requests.HTTPError(response=self)


def fake_get(monkeypatch, answer):
    """requests.get in doctor returns `answer` (a FakeHTTP) or raises it (an error).
    Returns the list of URLs asked, so tests can check nothing was sent."""
    asked = []

    def get(url, **kwargs):
        asked.append(url)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(doctor.requests, "get", get)
    return asked


def test_net_error_in_plain_words():
    requests = doctor.requests
    assert doctor.net_error(requests.ConnectionError("x")) == "couldn't connect"
    assert doctor.net_error(requests.Timeout()) == f"timed out after {doctor.TIMEOUT}s"
    err = doctor.requests.HTTPError(response=FakeHTTP(502))
    assert doctor.net_error(err) == "HTTP 502"


@pytest.mark.parametrize("answer, status, words", [
    (FakeHTTP(200), OK, "reachable"),
    (FakeHTTP(502), WARN, "HTTP 502"),
    (doctor.requests.ConnectionError("boom"), WARN, "couldn't connect"),
])
def test_crtsh_website(monkeypatch, answer, status, words):
    fake_get(monkeypatch, answer)
    r = doctor.check_crtsh_website()
    assert r["status"] == status and words in r["detail"]


def test_crtsh_website_respects_the_rate_limit(monkeypatch):
    for _ in range(doctor.pacing.CRTSH.limit):
        doctor.pacing.CRTSH.acquire(max_wait=0)  # use up this minute's requests
    asked = fake_get(monkeypatch, FakeHTTP(200))
    r = doctor.check_crtsh_website()
    assert r["status"] == WARN and "not checked" in r["detail"]
    assert asked == []  # no request sent


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query):
        assert query == "SELECT 1"


def fake_db(monkeypatch, lookup_error=None, connect_error=None):
    def lookup(host):
        if lookup_error:
            raise lookup_error
        return "an-ip"

    def connect(**kwargs):
        if connect_error:
            raise connect_error
        return FakeConnection()

    monkeypatch.setattr(doctor.socket, "gethostbyname", lookup)
    monkeypatch.setattr(doctor.crtsh_db.psycopg, "connect", connect)


def test_crtsh_database_ok(monkeypatch):
    fake_db(monkeypatch)
    assert doctor.check_crtsh_database()["status"] == OK


def test_crtsh_database_lookup_fails(monkeypatch):
    fake_db(monkeypatch, lookup_error=OSError("no name"))
    r = doctor.check_crtsh_database()
    assert r["status"] == WARN and "couldn't look up" in r["detail"]


def test_crtsh_database_down(monkeypatch):
    down = doctor.crtsh_db.psycopg.OperationalError("down")
    fake_db(monkeypatch, connect_error=down)
    r = doctor.check_crtsh_database()
    assert r["status"] == WARN and "down" in r["detail"]


def test_certspotter_ok_counts_the_query(monkeypatch):
    fake_get(monkeypatch, FakeHTTP(200))
    r = doctor.check_certspotter()
    assert r["status"] == OK and "1 of 90 free queries used" in r["detail"]


def test_certspotter_429_starts_a_cooldown(monkeypatch):
    fake_get(monkeypatch, FakeHTTP(429, {"Retry-After": "600"}))
    assert doctor.check_certspotter()["status"] == WARN
    assert doctor.pacing.CERTSPOTTER.status()["cooldown_until"]  # later scans skip it


def test_certspotter_cooling_down_sends_nothing(monkeypatch):
    doctor.pacing.CERTSPOTTER.cool_down(600)
    asked = fake_get(monkeypatch, FakeHTTP(200))
    r = doctor.check_certspotter()
    assert r["status"] == WARN and "cooling down until" in r["detail"]
    assert asked == []


def test_pacer_status_takes_no_slot():
    doctor.pacing.CERTSPOTTER.acquire(max_wait=0)
    first = doctor.pacing.CERTSPOTTER.status()
    assert first == doctor.pacing.CERTSPOTTER.status()
    assert first["used"] == 1 and first["cooldown_until"] is None


def test_no_certificate_source_is_a_fail(monkeypatch):
    down = lambda: doctor.result("Sources", "x", WARN, "down")
    for name in ("check_crtsh_website", "check_crtsh_database", "check_certspotter"):
        monkeypatch.setattr(doctor, name, down)
    assert statuses(doctor.check_ct_sources()) == [WARN, WARN, WARN, FAIL]


def test_one_certificate_source_is_enough(monkeypatch):
    monkeypatch.setattr(doctor, "check_crtsh_website",
                        lambda: doctor.result("Sources", "x", WARN, "down"))
    monkeypatch.setattr(doctor, "check_crtsh_database",
                        lambda: doctor.result("Sources", "x", WARN, "down"))
    monkeypatch.setattr(doctor, "check_certspotter",
                        lambda: doctor.result("Sources", "x", OK, "fine"))
    assert FAIL not in statuses(doctor.check_ct_sources())


@pytest.mark.parametrize("code, status", [(200, OK), (404, OK), (500, WARN)])
def test_shodan(monkeypatch, code, status):
    fake_get(monkeypatch, FakeHTTP(code))
    assert statuses(doctor.check_shodan()) == [status]


def test_aws_fresh_cache(monkeypatch, tmp_path):
    cache = tmp_path / "aws.json"
    cache.write_text("{}")
    monkeypatch.setattr(doctor.aws_ranges, "CACHE_FILE", str(cache))
    [r] = doctor.check_aws_ranges()
    assert r["status"] == OK and "cached 0h ago" in r["detail"]


def test_aws_no_cache_downloads(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor.aws_ranges, "CACHE_FILE", str(tmp_path / "none.json"))
    monkeypatch.setattr(doctor.aws_ranges, "_download", lambda: {})
    [r] = doctor.check_aws_ranges()
    assert r["status"] == OK and "just downloaded" in r["detail"]


def test_aws_download_fails_with_an_old_copy(monkeypatch, tmp_path):
    cache = tmp_path / "aws.json"
    cache.write_text("{}")
    three_days_ago = doctor.time.time() - 3 * 86400
    doctor.os.utime(cache, (three_days_ago, three_days_ago))
    monkeypatch.setattr(doctor.aws_ranges, "CACHE_FILE", str(cache))
    # no mock for _download: the real one runs and its request fails
    fake_get(monkeypatch, doctor.requests.ConnectionError("x"))
    [r] = doctor.check_aws_ranges()
    assert r["status"] == WARN
    assert "download failed (couldn't connect); using a 3-day-old copy" in r["detail"]


@pytest.mark.parametrize("answer, status", [
    (FakeHTTP(200), OK), (FakeHTTP(503), WARN),
    (doctor.requests.Timeout(), WARN)])
def test_tor_list(monkeypatch, answer, status):
    fake_get(monkeypatch, answer)
    assert statuses(doctor.check_tor_list()) == [status]


def test_crtsh_database_shows_the_reason_not_the_address(monkeypatch):
    message = ('connection failed: connection to server at "an-ip", port 5432 '
               'failed: sorry, too many clients already')
    error = doctor.crtsh_db.psycopg.OperationalError(message)
    fake_db(monkeypatch, connect_error=error)
    r = doctor.check_crtsh_database()
    assert r["detail"].endswith("database: sorry, too many clients already")
