"""Content discovery (v1.26). The network is faked at requests.get only, so
the scope check, the host parsing and every guard run for real."""

import pytest
import requests

from monomi import content, research, scope

LAB = scope.from_bytes(b"*.example.test\n!dev.example.test\n")
HOST = "app.example.test"
TOKEN = "f00dfeedcafe1234"
HTML = {"Content-Type": "text/html; charset=utf-8"}


class Page:
    def __init__(self, status=200, headers=None, body=b""):
        self.status_code = status
        self.headers = headers if headers is not None else dict(HTML)
        self._body = body
        self.read_bytes = 0

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            self.read_bytes += len(self._body[i:i + size])
            yield self._body[i:i + size]

    def close(self):
        pass


NOT_FOUND = Page(404, body=b"<html>Not Found</html>")


@pytest.fixture(autouse=True)
def fixed_token(monkeypatch):
    monkeypatch.setattr(content, "TOKEN", lambda: TOKEN)


def fake_site(monkeypatch, pages=None, default=NOT_FOUND, hosts=(HOST,)):
    """pages: {path: Page or exception class}. Paths not listed get `default`
    (a Page, or a function of the path). Only the given hosts may be asked:
    a request anywhere else fails the test. Returns the sent (url, headers)."""
    pages = pages or {}
    sent = []

    def get(url, **kw):
        assert kw["allow_redirects"] is False and kw["stream"] is True
        sent.append((url, kw["headers"]))
        parsed = requests.utils.urlparse(url)
        assert parsed.hostname in hosts, f"request left the host: {url}"
        out = pages.get(parsed.path, default)
        if isinstance(out, type) and issubclass(out, Exception):
            raise out("fake")
        return out(parsed.path) if callable(out) and not isinstance(out, Page) else out
    monkeypatch.setattr(content.requests, "get", get)
    return sent


def run(host=HOST, **kw):
    kw.setdefault("scope", LAB)
    return content.check_host(host, **kw)


# --- finding real files ------------------------------------------------------

def test_an_exposed_git_folder_and_env_file_are_found(monkeypatch):
    fake_site(monkeypatch, {
        "/.git/HEAD": Page(body=b"ref: refs/heads/main\n", headers={"Content-Type": "text/plain"}),
        "/.env": Page(body=b"APP_NAME=shop\nDB_PASSWORD=hunter2-very-secret\nSTRIPE_SECRET_KEY=sk_live_abc\n"),
    })
    r = run()
    assert r["scheme"] == "https" and r["stopped"] is None
    found = {f["path"]: f for f in r["found"]}
    assert found["/.git/HEAD"]["what"] == "a Git HEAD file (branch main)"
    assert found["/.git/HEAD"]["severity"] == "source"
    assert found["/.env"]["severity"] == "secrets"
    assert "3 settings, 2 named like secrets" in found["/.env"]["what"]
    # what a file holds is never kept
    assert "hunter2" not in repr(r) and "sk_live" not in repr(r)
    assert [f["severity"] for f in r["found"]] == ["secrets", "source"]  # worst first


def test_every_request_is_a_get_on_the_one_host_and_the_whole_list_is_tried(monkeypatch):
    sent = fake_site(monkeypatch)
    r = run()
    paths = content.host_paths(HOST)
    assert r["tried"] == len(paths) and r["found"] == [] and r["leads"] == []
    assert r["requests"] == len(sent) == content.CALIBRATION + len(paths)
    assert len(sent) <= content.MAX_REQUESTS


def test_a_200_error_page_for_every_path_finds_nothing(monkeypatch):
    # the classic false positive: a site that answers 200 with its home page for any URL
    home = Page(body=b"<!doctype html><html><title>Shop</title>" + b"x" * 900 + b"</html>")
    fake_site(monkeypatch, default=home)
    r = run()
    assert r["found"] == [] and r["leads"] == []
    assert r["calibration"] == [200, 200, 200]


def test_a_site_that_serves_a_zip_for_every_url_is_not_trusted_for_zips(monkeypatch):
    fake_site(monkeypatch, default=Page(body=b"PK\x03\x04" + b"\x00" * 100,
                                        headers={"Content-Type": "application/zip"}))
    r = run()
    assert "zip" in r["untrusted"] and r["found"] == []


def test_untrusted_checks_are_not_even_requested(monkeypatch):
    sent = fake_site(monkeypatch, default=Page(body=b"PK\x03\x04" + b"\x00" * 100))
    run()
    assert not any(url.endswith(".zip") and TOKEN not in url for url, _ in sent)


def test_a_file_check_needs_status_200(monkeypatch):
    fake_site(monkeypatch, {"/.git/HEAD": Page(403, body=b"ref: refs/heads/main\n")})
    assert run()["found"] == []


def test_host_and_label_backup_names(monkeypatch):
    fake_site(monkeypatch, {"/app.zip": Page(body=b"PK\x03\x04rest"),
                            "/app.example.test.tar.gz": Page(body=b"\x1f\x8b\x08\x00rest")})
    found = {f["path"] for f in run()["found"]}
    assert found == {"/app.zip", "/app.example.test.tar.gz"}


# --- leads -------------------------------------------------------------------

def test_leads_are_paths_that_answer_unlike_a_made_up_one(monkeypatch):
    fake_site(monkeypatch, {
        "/admin": Page(401, {"WWW-Authenticate": 'Basic realm="x"'}, b"no"),
        "/login": Page(200, body=b"<html><form>login</form></html>"),
        "/console": Page(302, {"Location": "https://evil.test/steal"}),
    })
    leads = {lead["path"]: lead for lead in run()["leads"]}
    assert set(leads) == {"/admin", "/login", "/console"}
    assert leads["/admin"]["auth"] == "Basic"
    # where a redirect points is recorded, never followed (fake_site fails on evil.test)
    assert leads["/console"]["location"] == "https://evil.test/steal"


def test_a_redirect_for_every_path_makes_no_leads(monkeypatch):
    fake_site(monkeypatch, default=lambda path: Page(302, {"Location": f"/sign-in?next={path}"}))
    r = run()
    assert r["leads"] == [] and r["calibration"] == [302, 302, 302]


def test_a_403_for_everything_makes_no_leads(monkeypatch):
    fake_site(monkeypatch, default=Page(403, body=b"<html>Forbidden by WAF</html>"))
    assert run()["leads"] == []


def test_a_wordlist_path_is_a_lead_only(monkeypatch):
    fake_site(monkeypatch, {"/secret-panel": Page(200, body=b"panel")})
    r = run(extra=["/secret-panel"])
    assert [lead["path"] for lead in r["leads"]] == ["/secret-panel"] and r["found"] == []


# --- guards ------------------------------------------------------------------

def test_out_of_scope_sends_nothing(monkeypatch):
    sent = fake_site(monkeypatch, hosts=("dev.example.test",))
    r = run("dev.example.test")
    assert sent == [] and r["requests"] == 0 and "scope" in r["stopped"]


def test_a_host_that_hides_where_it_connects_sends_nothing(monkeypatch):
    # real requests parsing: this connects to evil.test, so it must never be asked
    sent = fake_site(monkeypatch, hosts=())
    r = run("evil.test\\@app.example.test")
    assert sent == [] and r["requests"] == 0


def test_the_request_cap_is_enforced(monkeypatch):
    sent = fake_site(monkeypatch)
    monkeypatch.setattr(content, "max_requests", lambda extra=0: 10)
    r = run()
    assert len(sent) == r["requests"] == 10 and "cap" in r["stopped"]


def test_the_time_limit_stops_sending(monkeypatch):
    sent = fake_site(monkeypatch)
    clock = iter(range(0, 10_000))
    monkeypatch.setattr(content, "CLOCK", lambda: next(clock))
    r = run(stop_at=30)
    assert r["stopped"] and "time limit" in r["stopped"]
    assert 0 < len(sent) < 20


def test_http_once_only_when_https_breaks_at_tls(monkeypatch):
    sent = fake_site(monkeypatch)

    real_get = content.requests.get

    def get(url, **kw):
        if url.startswith("https://"):
            raise requests.exceptions.SSLError("bad cert")
        return real_get(url, **kw)
    monkeypatch.setattr(content.requests, "get", get)
    r = run()
    assert r["scheme"] == "http" and r["https_error"] == "SSLError"
    assert all(url.startswith("http://") for url, _ in sent)
    assert r["requests"] == 1 + len(sent)


def test_a_timeout_gets_no_http_retry_and_nothing_more(monkeypatch):
    fake_site(monkeypatch, {f"/{TOKEN}": requests.Timeout})
    r = run()
    assert r["scheme"] is None and r["requests"] == 1 and r["tried"] == 0


def test_rate_log_and_research_header_cover_every_request(monkeypatch, tmp_path):
    sent = fake_site(monkeypatch)
    header_file = tmp_path / "research.txt"
    header_file.write_text("X-HackerOne-Researcher: tester\n")

    class Counting:
        slots = 0

        def wait(self):
            Counting.slots += 1
    logged = []
    r = run(limiter=Counting(), on_request=lambda h, url, rule: logged.append(url),
            research=research.load(str(header_file)))
    assert Counting.slots == len(logged) == len(sent) == r["requests"]
    assert all(h.get("X-HackerOne-Researcher") == "tester" for _, h in sent)


def test_only_the_start_of_a_big_file_is_read(monkeypatch):
    big = Page(body=b"PK\x03\x04" + b"\x00" * 5_000_000)
    fake_site(monkeypatch, {"/backup.zip": big})
    r = run()
    assert [f["path"] for f in r["found"]] == ["/backup.zip"]
    assert big.read_bytes <= content.MAX_BODY_BYTES + content.CHUNK


def test_check_all_skips_hosts_without_a_public_ip(monkeypatch):
    sent = fake_site(monkeypatch)
    enrichment = {"hosts": {HOST: {"ips": ["93.184.216.34"]},
                            "intra.example.test": {"ips": ["10.0.0.5"]}}}
    out = content.check_all(enrichment, scope=LAB)
    assert out["requested"] == [HOST] and out["requests"] == len(sent)
    assert not any("intra" in url for url, _ in sent)


# --- the checks themselves ---------------------------------------------------

SAMPLES = {
    "git_head": b"ref: refs/heads/main\n",
    "git_config": b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://u:p@git.test/x\n",
    "svn_entries": b"12\n\ndir\n1234\n",
    "sqlite": b"SQLite format 3\x00" + b"\x00" * 50,
    "hg_requires": b"dotencode\nfncache\nrevlogv1\nstore\n",
    "bzr": b"This is a Bazaar control directory.\n",
    "ds_store": b"\x00\x00\x00\x01Bud1" + b"\x00" * 50,
    "env": b"APP_ENV=prod\nAPI_KEY=abc\n",
    "htpasswd": b"admin:$apr1$abc$def\n",
    "npmrc": b"//registry.npmjs.org/:_authToken=npm_abc\n",
    "aws_credentials": b"[default]\naws_access_key_id = AKIA\naws_secret_access_key = x\n",
    "docker_auth": b'{"auths": {"registry.test": {"auth": "eA=="}}}',
    "git_credentials": b"https://user:token@github.test\n",
    "private_key": b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n",
    "php_config": b"<?php\ndefine('DB_PASSWORD', 'x');\n",
    "iis_config": b'<?xml version="1.0"?>\n<configuration><connectionStrings/></configuration>',
    "sftp_config": b'{"host": "ftp.test", "password": "x"}',
    "compose": b"version: '3'\nservices:\n  db:\n    image: postgres\n",
    "dockerfile": b"FROM python:3.14\nRUN pip install x\n",
    "phpinfo": b"<html><title>phpinfo()</title>PHP Version 8.3.0</html>",
    "apache_status": b"<html><h1>Apache Server Status for app.test</h1></html>",
    "apache_info": b"<html><h1>Apache Server Information</h1></html>",
    "nginx_status": b"Active connections: 2\nserver accepts handled requests\n 1 1 1\n",
    "spring_env": b'{"activeProfiles": [], "propertySources": []}',
    "hprof": b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 20,
    "elmah": b"<html><title>Error log for /LM/W3SVC</title>Error Log for x ELMAH</html>",
    "trace_axd": b"<html><h1>Application Trace</h1></html>",
    "web_xml": b'<?xml version="1.0"?>\n<web-app version="3.0"></web-app>',
    "pprof": b"<html>Types of profiles available:</html>",
    "expvar": b'{"cmdline": ["/app"], "memstats": {}}',
    "symfony_profiler": b"<html><title>Symfony Profiler</title></html>",
    "laravel_log": b"[2026-11-23 10:00:00] local.ERROR: boom\n",
    "php_error_log": b"[23-Nov-2026] PHP Fatal error: x in /var/www/a.php\n",
    "npm_debug": b"0 info it worked if it ends with ok\n1 verbose cli npm\n",
    "sql_dump": b"-- MySQL dump 10.13\nCREATE TABLE users (id int);\n",
    "zip": b"PK\x03\x04rest",
    "gzip": b"\x1f\x8b\x08\x00rest",
    "tar": b"\x00" * 257 + b"ustar\x00" + b"\x00" * 20,
    "es_indices": b"green open logs-2026 abc 1 1 100 0 1mb 1mb\nyellow open users xyz 1 1 5 0 1kb 1kb\n",
}


def test_every_check_has_a_sample():
    assert set(SAMPLES) == set(content.CHECKS)


@pytest.mark.parametrize("kind", sorted(SAMPLES))
def test_each_check_knows_its_file(kind):
    assert content.CHECKS[kind](SAMPLES[kind])


@pytest.mark.parametrize("kind", sorted(SAMPLES))
def test_no_check_passes_an_ordinary_error_page(kind):
    page = b"<!doctype html><html><head><title>404</title></head><body>Not found</body></html>"
    assert content.CHECKS[kind](page) is None


def test_evidence_never_holds_a_secret_value():
    for kind, sample in SAMPLES.items():
        what = content.CHECKS[kind](sample)
        for secret in ("hunter2", "npm_abc", "AKIA", "token@", "u:p@", "b3Blbg", "eA=="):
            assert secret not in what, (kind, what)


def test_a_script_with_a_few_assignments_is_not_an_env_file():
    js = b"function f() {\n  a = 1\n  b = 2\n  return a + b;\n}\nconsole.log(f());\nwindow.x();\n"
    assert content.CHECKS["env"](js) is None


def test_git_config_says_when_its_remote_has_a_login():
    assert "login" in content.CHECKS["git_config"](SAMPLES["git_config"])
    assert "login" not in content.CHECKS["git_config"](b"[core]\n\tbare = false\n")


def test_every_listed_kind_has_a_check_and_a_severity():
    for _, kind in content.PATHS:
        assert kind == content.LEAD or (kind in content.CHECKS and kind in content.SEVERITY)


def test_every_path_is_a_plain_path():
    for path, _ in content.host_paths(HOST):
        assert path.startswith("/") and not content.BAD_PATH_RE.search(path), path


# --- --wordlist --------------------------------------------------------------

def test_a_wordlist_loads_plain_paths(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("# comment\nadmin\n/backup/\n\nadmin\n")
    assert content.load_wordlist(str(f)) == ["/admin", "/backup/"]


@pytest.mark.parametrize("line", ["../etc/passwd", "a?b=1", "https://evil.test/", "a\\b",
                                  "%2e%2e/x", "a b", "x#y"])
def test_a_wordlist_refuses_anything_but_a_plain_path(tmp_path, line):
    f = tmp_path / "w.txt"
    f.write_text(f"ok\n{line}\n")
    with pytest.raises(content.WordlistError, match="plain path"):
        content.load_wordlist(str(f))


def test_a_huge_wordlist_is_refused(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("\n".join(f"p{i}" for i in range(content.MAX_WORDLIST + 1)))
    with pytest.raises(content.WordlistError, match="split"):
        content.load_wordlist(str(f))
