"""Tests for doctor.py: every check's ok / warn / fail, with nothing real
called (no real API, no real package list)."""

import json
import sys

import anthropic
import pytest

from monomi import cli, doctor
from monomi.doctor import FAIL, OK, WARN

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
    assert cli.main() == 0
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
    def down():
        return doctor.result("Sources", "x", WARN, "down")

    for name in ("check_crtsh_website", "check_crtsh_database", "check_certspotter", "check_otx"):
        monkeypatch.setattr(doctor, name, down)
    assert statuses(doctor.check_ct_sources()) == [WARN, WARN, WARN, WARN, FAIL]


def test_one_certificate_source_is_enough(monkeypatch):
    monkeypatch.setattr(doctor, "check_crtsh_website",
                        lambda: doctor.result("Sources", "x", WARN, "down"))
    monkeypatch.setattr(doctor, "check_crtsh_database",
                        lambda: doctor.result("Sources", "x", WARN, "down"))
    monkeypatch.setattr(doctor, "check_certspotter",
                        lambda: doctor.result("Sources", "x", OK, "fine"))
    monkeypatch.setattr(doctor, "check_otx",
                        lambda: doctor.result("Sources", "x", WARN, "down"))
    assert FAIL not in statuses(doctor.check_ct_sources())


def test_otx_alone_is_enough(monkeypatch):
    """OTX finds hostnames too, so scans can still run when every CT log is down."""
    def down():
        return doctor.result("Sources", "x", WARN, "down")

    for name in ("check_crtsh_website", "check_crtsh_database", "check_certspotter"):
        monkeypatch.setattr(doctor, name, down)
    monkeypatch.setattr(doctor, "check_otx", lambda: doctor.result("Sources", "x", OK, "fine"))
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


# ---------- MCP (Claude app) ----------

ENTRY = {"command": "/monomi/venv/bin/python", "args": ["/monomi/mcp_server.py"]}


def fake_mcp(monkeypatch, tmp_path, files, error=None):
    """files: {file name: text} -> config files that 'exist' in tmp_path."""
    paths = []
    for name, text in files.items():
        f = tmp_path / name
        f.write_text(text, encoding="utf-8")
        paths.append(str(f))

    def config_paths():
        if error:
            raise error
        return paths, str(tmp_path / "standard.json")
    monkeypatch.setattr(doctor.mcp_setup, "config_paths", config_paths)
    monkeypatch.setattr(doctor.mcp_setup, "server_entry", lambda: dict(ENTRY))


def config_with(entry):
    servers = {"other": {"command": "x"}}
    if entry is not None:
        servers["monomi"] = entry
    return doctor.mcp_setup.json.dumps({"mcpServers": servers})


def test_mcp_points_at_this_monomi(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    [r] = doctor.check_mcp()
    assert r["status"] == OK
    assert r["detail"] == "Claude app config points at this Monomi"


def test_mcp_no_config_yet(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {})
    [r] = doctor.check_mcp()
    assert r["status"] == WARN
    assert r["fix"] == "python monomi.py mcp setup"


def test_mcp_no_monomi_entry(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(None)})
    [r] = doctor.check_mcp()
    assert (r["status"], r["detail"]) == (
        WARN, "Monomi isn't set up in the Claude app")


def test_mcp_points_at_a_different_monomi(monkeypatch, tmp_path):
    old = {"command": "/old/venv/bin/python", "args": ["/old/mcp_server.py"]}
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(old)})
    [r] = doctor.check_mcp()
    assert r["status"] == WARN
    assert "a different Monomi" in r["detail"]


def test_mcp_broken_json_is_a_warning_not_a_crash(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": "{not json"})
    [r] = doctor.check_mcp()
    assert r["status"] == WARN
    assert "isn't valid JSON" in r["detail"]
    assert "a.json" in r["detail"]


def test_mcp_config_not_found(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {},
             error=doctor.mcp_setup.SetupError("no %APPDATA%"))
    [r] = doctor.check_mcp()
    assert r["status"] == WARN
    assert "--print" in r["fix"]


def test_mcp_two_copies_shows_the_worst(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"standard.json": config_with(ENTRY),
                                     "msix.json": config_with(None)})
    [r] = doctor.check_mcp()
    assert r["status"] == WARN
    assert "isn't set up" in r["detail"] and "msix.json" in r["detail"]


def test_mcp_two_good_copies(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"standard.json": config_with(ENTRY),
                                     "msix.json": config_with(ENTRY)})
    [r] = doctor.check_mcp()
    assert r["status"] == OK
    assert r["detail"].endswith("(2 config files)")


def test_mcp_check_writes_nothing(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(None)})
    before = (tmp_path / "a.json").read_text(encoding="utf-8")
    doctor.check_mcp()
    assert (tmp_path / "a.json").read_text(encoding="utf-8") == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.json"]


# ---------- active checks (v1.20: a terminal approval for each) ----------

# A v1.19 entry with old flags, in the order v1.19 wrote them
ACTIVE = {**ENTRY, "args": ENTRY["args"] + ["--scope", "/lab/scope.txt", "--scope-sha256", "ab" * 32,
                                            "--allow-active"]}


def fake_log(monkeypatch, tmp_path, lines=None):
    """The active log, and an empty approvals folder, both in tmp_path."""
    log = tmp_path / "active.log"
    if lines is not None:
        log.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    monkeypatch.setattr(doctor.mcp_setup, "ACTIVE_LOG", str(log))
    monkeypatch.setattr(doctor.approvals, "approvals_dir", lambda: str(tmp_path / "approvals"))
    return tmp_path / "approvals"


def test_clean_config_says_active_checks_need_an_approval(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    fake_log(monkeypatch, tmp_path)
    [r] = doctor.check_active()
    assert r["status"] == OK and "only after you approve each one in a terminal" in r["detail"]


def test_old_flags_in_a_config_are_a_warning_naming_each_file(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"standard.json": config_with(ACTIVE),
                                     "data.json": config_with(ENTRY),
                                     "bad.json": "{not json"})
    fake_log(monkeypatch, tmp_path)
    [r] = doctor.check_active()
    first, *files = r["detail"].split("\n")
    assert r["status"] == WARN and "not used since v1.20" in first and "ignores them" in first
    assert len(files) == 1 and files[0].strip() == (
        f"--scope, --scope-sha256, --allow-active in {tmp_path / 'standard.json'}")
    assert r["fix"] == "python monomi.py mcp setup, to remove them"


def test_old_flags_still_point_at_this_monomi(monkeypatch, tmp_path):
    # They're reported by check_active, so check_mcp mustn't call the entry "different"
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ACTIVE)})
    [r] = doctor.check_mcp()
    assert (r["status"], r["detail"]) == (OK, "Claude app config points at this Monomi")


def test_waiting_approvals_are_counted_and_expired_ones_are_not(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    fake_log(monkeypatch, tmp_path)
    now = doctor.approvals._now()
    doctor.approvals.request("fingerprint_hosts", ["a.test"], now=now)
    doctor.approvals.request("fingerprint_hosts", ["b.test"], now=now)
    doctor.approvals.request("fingerprint_hosts", ["c.test"], now=now - doctor.approvals.REQUEST_TTL)
    _, r = doctor.check_active()
    assert r["name"] == "approvals" and r["detail"].startswith("2 approval requests waiting for your yes")


def test_active_log_shows_the_last_request(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    first = {"time": "2026-11-10T01:00:00+00:00", "tool": "fingerprint_hosts", "host": "app", "url": "x"}
    last = {**first, "time": "2026-11-10T02:00:00+00:00", "host": "dev"}
    fake_log(monkeypatch, tmp_path, [json.dumps(first), json.dumps(last)])
    _, r = doctor.check_active()
    assert r["detail"] == ("last active request 2026-11-10T02:00:00+00:00: fingerprint_hosts -> dev "
                           "(2 requests in scans/active.log)")


def test_active_log_says_the_rate_and_research_file_the_last_request_used(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    last = {"time": "t", "tool": "--fingerprint", "host": "dev", "url": "x",
            "rate": 1.0, "research_sha256": "abcdef123456789"}
    fake_log(monkeypatch, tmp_path, [json.dumps(last)])
    _, r = doctor.check_active()
    assert "dev, at 1/s, research header sha256 abcdef123456... (1 request" in r["detail"]


def test_active_log_with_a_broken_last_line_doesnt_crash(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    fake_log(monkeypatch, tmp_path, ['{"time": "t"}', "{half a li"])
    _, r = doctor.check_active()
    assert "unreadable" in r["detail"] and "2 requests" in r["detail"]


def test_active_check_with_no_config_found(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {}, error=doctor.mcp_setup.SetupError("no %APPDATA%"))
    fake_log(monkeypatch, tmp_path)
    [r] = doctor.check_active()
    assert r["status"] == OK


def test_active_log_counts_refusals_separately(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    req = {"time": "2026-11-12T01:00:00+00:00", "event": "request", "tool": "fingerprint_hosts",
           "host": "www", "url": "x"}
    ref = {"time": "2026-11-12T02:00:00+00:00", "event": "refused", "tool": "fingerprint_hosts",
           "host": "evil", "reason": "no rule matches"}
    fake_log(monkeypatch, tmp_path, [json.dumps(req), json.dumps(ref), json.dumps(ref)])
    _, r = doctor.check_active()
    # the last REQUEST is shown, not the later refusal
    assert r["detail"] == ("last active request 2026-11-12T01:00:00+00:00: fingerprint_hosts -> www "
                           "(1 request, 2 refusals in scans/active.log)")


def test_active_log_with_only_refusals(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(ENTRY)})
    ref = {"time": "t", "event": "refused", "tool": "fingerprint_hosts", "host": None, "reason": "off"}
    fake_log(monkeypatch, tmp_path, [json.dumps(ref)])
    _, r = doctor.check_active()
    assert r["detail"] == "no active requests sent yet (1 refusal in scans/active.log)"


# ---------- other MCP clients (v1.13): Codex, OpenCode, Hermes ----------

BASE = {"command": "py", "args": ["server"]}


def fake_clients(monkeypatch, tmp_path, codex=None, opencode=None, hermes=None):
    """Point every client at tmp_path; write the configs given as text."""
    monkeypatch.setattr(doctor.mcp_setup, "direct_entry", lambda: dict(BASE))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    for text, path in ((codex, tmp_path / "codex" / "config.toml"),
                       (opencode, tmp_path / ".config" / "opencode" / "opencode.json"),
                       (hermes, tmp_path / "hermes" / "config.yaml")):
        if text is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")


def by_name(results):
    return {r["name"]: r for r in results}


CODEX_OK = '[mcp_servers.monomi]\ncommand = "py"\nargs = ["server"]\n'


def test_clients_with_no_config_are_one_ok_line(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path)
    [r] = doctor.check_clients()
    assert r["status"] == OK and r["detail"] == "no config found for: Codex, OpenCode, Hermes"


def test_each_client_points_at_this_monomi(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path, codex=CODEX_OK,
                 opencode='{"mcp": {"monomi": {"type": "local", "command": ["py", "server"]}}}',
                 hermes="mcp_servers:\n  monomi:\n    command: py\n    args: [server]\n")
    results = by_name(doctor.check_clients())
    assert set(results) == {"codex", "opencode", "hermes"}  # no "not found" line
    for r in results.values():
        assert r["status"] == OK and "points at this Monomi, active checks need your approval" in r["detail"]


def test_client_with_old_flags_still_points_here_but_warns(monkeypatch, tmp_path):
    old = ('[mcp_servers.monomi]\ncommand = "py"\n'
           'args = ["server", "--scope", "s.txt", "--scope-sha256", "ab", "--allow-active"]\n')
    fake_clients(monkeypatch, tmp_path, codex=old)
    r = by_name(doctor.check_clients())["codex"]
    assert r["status"] == WARN and "points at this Monomi, still has flags not used since v1.20" in r["detail"]
    assert r["fix"] == "python monomi.py mcp setup --client codex, to remove them"


def test_client_without_monomi_says_how_to_add_it_without_warning(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path, codex='model = "x"\n')
    r = by_name(doctor.check_clients())["codex"]
    assert r["status"] == OK and "python monomi.py mcp setup --client codex" in r["detail"]


def test_client_pointing_elsewhere_is_a_warning(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path, hermes="mcp_servers:\n  monomi:\n    command: other\n")
    r = by_name(doctor.check_clients())["hermes"]
    assert r["status"] == WARN and r["fix"] == "python monomi.py mcp setup --client hermes"


def test_opencode_with_comments_is_not_called_broken(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path, opencode='{\n  // mine\n  "mcp": {}\n}\n')
    r = by_name(doctor.check_clients())["opencode"]
    assert r["status"] == OK and "has comments" in r["detail"]


def test_broken_client_config_is_a_warning_not_a_crash(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path, codex='model = "unclosed\n')
    r = by_name(doctor.check_clients())["codex"]
    assert r["status"] == WARN and "can't be read" in r["detail"]


def test_client_check_writes_nothing(monkeypatch, tmp_path):
    fake_clients(monkeypatch, tmp_path, codex='model = "x"\n', hermes="a: 1\n")
    before = sorted(p.name for p in tmp_path.rglob("*"))
    doctor.check_clients()
    assert sorted(p.name for p in tmp_path.rglob("*")) == before


def test_doctor_runs_the_clients_check():
    assert doctor.check_clients in doctor.CHECKS


# ---------- rate for MCP (v1.19) ----------

def test_rate_default_and_set(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(doctor.mcp_setup.build_entry(dict(ENTRY)))})
    [r] = doctor.check_settings()
    assert r["detail"] == "active requests: 1/s (the default), in total"
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(doctor.mcp_setup.build_entry(dict(ENTRY), "2"))})
    assert "2/s" in doctor.check_settings()[0]["detail"]


def test_a_bad_rate_warns_that_active_checks_refuse(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with({**ENTRY, "args": ENTRY["args"] + ["--rate", "fast"]})})
    [r] = doctor.check_settings()
    assert r["status"] == WARN and "active checks refuse" in r["detail"]


def test_copies_with_different_rates_disagree(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(doctor.mcp_setup.build_entry(dict(ENTRY), "2")),
                                     "b.json": config_with(dict(ENTRY))})
    [r] = doctor.check_settings()
    assert r["status"] == WARN and "disagree" in r["detail"]


def test_rate_doesnt_make_the_entry_different(monkeypatch, tmp_path):
    fake_mcp(monkeypatch, tmp_path, {"a.json": config_with(doctor.mcp_setup.build_entry(dict(ENTRY), "2"))})
    [r] = doctor.check_mcp()
    assert r["status"] == OK


def test_doctor_runs_the_settings_check():
    assert doctor.check_settings in doctor.CHECKS
