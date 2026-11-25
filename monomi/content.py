"""
Content discovery (v1.26): files and paths a site serves that it shouldn't,
or that are worth a closer look. Monomi's fourth opt-in ACTIVE check.

Only runs with --content (CLI) or discover_content (MCP, after a typed yes).
For each host it sends a fixed list of GET requests, one per path in PATHS
(about 150), plus CALIBRATION made-up paths first. It never POSTs, never
follows a redirect (where one points is recorded, never requested), never
leaves the host, and reads at most MAX_BODY_BYTES of any answer.

What makes it more than a status-code scanner is that each path knows what
the real thing looks like:

  * A FILE path (/.git/HEAD, /.env, /backup.zip...) counts as found only
    when its content passes that kind's check: /.git/HEAD must start with
    "ref: " or a commit hash, a .zip must start with the zip signature, and
    so on. A 200 error page is never a finding.
  * A LEAD path (/admin, /console, /actuator...) has no fixed content, so it
    is reported only when it answers differently from a path that can't
    exist: a lead to look at, never claimed as a flaw.

Calibration: before the list, CALIBRATION made-up paths (random letters) on
each host show what that host's "not found" looks like. A lead that answers
the same way is dropped, and if a made-up path passes a file check (a site
that serves a zip for every URL), that check isn't trusted on that host.

Secrets are never kept or returned. Evidence says what a file IS (".env with
12 settings, 3 named like secrets"), never what it holds: no values, no key
material, no code.

Honest limits: a small fixed list finds the common mistakes, not everything
(--wordlist adds your own paths, as leads only); a WAF that answers every
path with the same page hides leads (calibration drops them rather than
guess); and as with every active check, the DNS answer can change between
the lookup and the request (see probe.py).
"""

import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from monomi import rate as ratemod
from monomi.common import now_utc
from monomi.fingerprint import _retry_on_http
from monomi.research import request_headers
from monomi.scope import OutOfScope, check_url

MAX_HOSTS = 20            # hosts per CLI run (each takes ~150 requests)
MAX_BODY_BYTES = 16384    # bytes read per answer: every check needs only the start
CHUNK = 4096
CALIBRATION = 3           # made-up paths per host, before the list
MAX_WORDLIST = 5000       # paths a --wordlist file may add
LEADS_SHOWN = 15
CLOCK = time.monotonic


def TOKEN() -> str:  # noqa: N802 (a name tests replace, like CLOCK)
    """The random letters in this host's made-up paths."""
    return secrets.token_hex(8)


class RequestCapReached(requests.RequestException):
    """The host's request cap is used up: the rest of its list isn't sent."""


class TimeLimit(requests.Timeout):
    """The run's time limit passed: nothing more is sent."""


# --- What the real thing looks like ------------------------------------------
# Each check takes the first MAX_BODY_BYTES of the answer (bytes) and returns
# a short description of what was found, or None. Descriptions are built from
# the file's shape only, never from its values.

SECRET_NAME_RE = re.compile(r"KEY|SECRET|TOKEN|PASSW|PWD|CREDENTIAL|PRIVATE|AUTH", re.I)
ENV_LINE_RE = re.compile(rb"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=", re.M)
HEX40_RE = re.compile(rb"^[0-9a-f]{40}(?:[0-9a-f]{24})?\s*$")
BRANCH_RE = re.compile(rb"^ref: refs/heads/([A-Za-z0-9._/-]{1,60})\s*$")
URL_CREDS_RE = re.compile(rb"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.I)
PRIVATE_KEY_RE = re.compile(rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----")


HTML_STARTS = (b"<!doctype", b"<html", b"<head", b"<body", b"<script", b"<?xml-stylesheet", b"<!--",
               b"<meta", b"<div", b"<title", b"<link", b"<style", b"<p>", b"<pre", b"<h1", b"<center")


def _looks_like_html(body: bytes) -> bool:
    head = body[:512].removeprefix(b"\xef\xbb\xbf").lstrip().lower()   # a UTF-8 BOM first is common
    return head.startswith(HTML_STARTS) or b"<html" in body[:2048].lower()


def _git_head(body):
    m = BRANCH_RE.match(body)
    if m:
        return f"a Git HEAD file (branch {m.group(1).decode()})"
    if HEX40_RE.match(body):
        return "a Git HEAD file (a detached commit)"
    return None


def _git_config(body):
    if _looks_like_html(body) or b"[core]" not in body:
        return None
    creds = ", and a remote URL with a login in it" if URL_CREDS_RE.search(body) else ""
    return f"a Git config file{creds}"


def _svn_entries(body):
    lines = body.split(b"\n")
    # format 8-12: a version number line, then (after the name line) "dir" on its own line
    if len(lines) > 3 and lines[0].strip() in (b"8", b"9", b"10", b"11", b"12") and b"dir" in [
            ln.strip() for ln in lines[1:4]]:
        return "a Subversion entries file"
    return None


def _sqlite(body):
    return "an SQLite database" if body.startswith(b"SQLite format 3\x00") else None


HG_REQUIRES = {b"revlogv1", b"store", b"fncache", b"dotencode", b"generaldelta", b"sparserevlog",
               b"share-safe", b"persistent-nodemap", b"revlog-compression-zstd", b"treemanifest",
               b"exp-sparse", b"largefiles", b"lfs", b"shared", b"relshared"}


def _hg_requires(body):
    lines = [ln.strip() for ln in body.strip().split(b"\n") if ln.strip()]
    if lines and all(ln in HG_REQUIRES for ln in lines) and (b"revlogv1" in lines or b"store" in lines):
        return "a Mercurial requires file"
    return None


def _bzr(body):
    return "a Bazaar control folder" if b"This is a Bazaar control directory" in body[:200] else None


def _ds_store(body):
    return "a macOS .DS_Store file (lists the folder's files)" if body.startswith(b"\x00\x00\x00\x01Bud1") else None


def _env(body):
    if _looks_like_html(body) or body.lstrip().startswith((b"{", b"[", b"<")):
        return None
    names = [m.group(1).decode() for m in ENV_LINE_RE.finditer(body)]
    lines = [ln for ln in body.split(b"\n") if ln.strip() and not ln.lstrip().startswith(b"#")]
    # most lines must be settings: a script with a few "x = 1" lines is not an .env
    if len(names) < 2 or len(names) < 0.8 * len(lines):
        return None
    secretish = sum(1 for n in names if SECRET_NAME_RE.search(n))
    named = f", {secretish} named like secrets" if secretish else ""
    more = "+" if len(body) >= MAX_BODY_BYTES else ""
    return f"an environment file with {len(names)}{more} settings{named} (values not kept)"


def _htpasswd(body):
    lines = [ln for ln in body.strip().split(b"\n") if ln.strip()]
    # known hash formats only (old 13-character DES is left out: "error:AccessDenied" looks like one)
    hashed = re.compile(rb"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\$[156]\$|\{SHA\})")
    hits = sum(1 for ln in lines if hashed.match(ln.strip()))
    return f"an .htpasswd file with {hits} password hash(es) (not kept)" if hits and hits == len(lines) else None


def _npmrc(body):
    if re.search(rb"_auth(Token)?\s*=|_password\s*=", body):
        return "an .npmrc with a registry token (not kept)"
    return None


def _aws_credentials(body):
    if re.search(rb"aws_access_key_id\s*=", body, re.I) and b"[" in body:
        return "an AWS credentials file (keys not kept)"
    return None


def _docker_auth(body):
    if b'"auths"' in body or (b'"auth"' in body and b"{" in body[:5]):
        return "a Docker registry login file (not kept)"
    return None


def _git_credentials(body):
    return "a Git credentials file (not kept)" if URL_CREDS_RE.match(body.lstrip()) else None


def _private_key(body):
    m = PRIVATE_KEY_RE.search(body[:200])
    return f"a private key ({m.group(1).decode()}, not kept)" if m else None


def _php_config(body):
    if b"<?php" in body[:200] and re.search(rb"DB_PASSWORD|\$password|'password'|\"password\"|db_pass", body, re.I):
        return "PHP config source with database settings (values not kept)"
    return None


def _iis_config(body):
    if b"<configuration" in body[:500] and (b"connectionString" in body or b"<appSettings" in body):
        return "an IIS web.config with settings or connection strings (values not kept)"
    return None


def _sftp_config(body):
    if b'"host"' in body and re.search(rb'"(password|private_key|privateKeyPath|passphrase)"', body):
        return "an editor SFTP/deploy config with a login (not kept)"
    return None


def _compose(body):
    if not _looks_like_html(body) and re.search(rb"^services:\s*$", body, re.M) and (
            b"image:" in body or b"build:" in body):
        return "a docker-compose file"
    return None


DOCKER_STEP_RE = re.compile(rb"^(RUN|COPY|ADD|CMD|ENTRYPOINT|WORKDIR|ENV|EXPOSE|USER|ARG|LABEL|VOLUME)\s", re.M)


def _dockerfile(body):
    # FROM in capitals (a JS "from 'react'" isn't one) and at least one more instruction
    if not _looks_like_html(body) and re.search(rb"^FROM\s+\S", body, re.M) and DOCKER_STEP_RE.search(body):
        return "a Dockerfile"
    return None


def _phpinfo(body):
    return "a phpinfo() page (PHP's full configuration)" if b"phpinfo()" in body and b"PHP Version" in body else None


def _apache_status(body):
    return "Apache server-status (live requests and client IPs)" if b"Apache Server Status for" in body else None


def _apache_info(body):
    return "Apache server-info (the full server configuration)" if b"Apache Server Information" in body else None


def _nginx_status(body):
    return "nginx stub_status" if b"Active connections:" in body and b"server accepts handled requests" in body else None


def _spring_env(body):
    if body.lstrip().startswith(b"{") and (b'"propertySources"' in body or b'"activeProfiles"' in body):
        return "Spring Boot /env (the app's configuration; values not kept)"
    return None


def _hprof(body):
    return "a Java heap dump (the app's memory: may hold secrets and sessions)" if body.startswith(b"JAVA PROFILE 1.0") else None


def _elmah(body):
    return "an ELMAH error log" if b"Error Log for" in body and b"ELMAH" in body else None


def _trace_axd(body):
    return "ASP.NET trace.axd (recent requests)" if b"Application Trace" in body else None


def _web_xml(body):
    return "a Java WEB-INF/web.xml" if b"<web-app" in body else None


def _pprof(body):
    return "Go pprof (live profiles of the server)" if b"Types of profiles available" in body else None


def _expvar(body):
    return "Go expvar (/debug/vars: the command line and memory stats)" if (
        body.lstrip().startswith(b"{") and b'"cmdline"' in body and b'"memstats"' in body) else None


def _symfony_profiler(body):
    return "the Symfony profiler (recent requests, with their data)" if b"Symfony Profiler" in body else None


def _laravel_log(body):
    return "a Laravel log" if re.search(rb"^\[\d{4}-\d\d-\d\d [\d:]+\] \w+\.(ERROR|INFO|DEBUG|WARNING)", body, re.M) else None


def _php_error_log(body):
    return "a PHP error log" if re.search(rb"PHP (Fatal error|Warning|Notice|Parse error):", body) and not _looks_like_html(body) else None


def _npm_debug(body):
    return "an npm debug log" if re.search(rb"^\d+ verbose cli ", body, re.M) else None


def _sql_dump(body):
    if _looks_like_html(body):
        return None
    if re.search(rb"^(-- MySQL dump|-- PostgreSQL database dump|-- phpMyAdmin SQL Dump|CREATE TABLE|INSERT INTO)",
                 body, re.M | re.I):
        return "an SQL database dump"
    return None


def _zip(body):
    return "a zip archive" if body.startswith(b"PK\x03\x04") else None


def _gzip(body):
    return "a gzip archive" if body.startswith(b"\x1f\x8b\x08") else None


def _tar(body):
    return "a tar archive" if len(body) > 262 and body[257:262] == b"ustar" else None


def _es_indices(body):
    if re.match(rb"^(green|yellow|red)\s+(open|close)\s+\S+", body.lstrip()):
        n = len([ln for ln in body.strip().split(b"\n") if ln.strip()])
        return f"Elasticsearch index list ({n} indices, open to anyone)"
    return None


CHECKS = {
    "git_head": _git_head, "git_config": _git_config, "svn_entries": _svn_entries, "sqlite": _sqlite,
    "hg_requires": _hg_requires, "bzr": _bzr, "ds_store": _ds_store, "env": _env, "htpasswd": _htpasswd,
    "npmrc": _npmrc, "aws_credentials": _aws_credentials, "docker_auth": _docker_auth,
    "git_credentials": _git_credentials, "private_key": _private_key, "php_config": _php_config,
    "iis_config": _iis_config, "sftp_config": _sftp_config, "compose": _compose, "dockerfile": _dockerfile,
    "phpinfo": _phpinfo, "apache_status": _apache_status, "apache_info": _apache_info,
    "nginx_status": _nginx_status, "spring_env": _spring_env, "hprof": _hprof, "elmah": _elmah,
    "trace_axd": _trace_axd, "web_xml": _web_xml, "pprof": _pprof, "expvar": _expvar,
    "symfony_profiler": _symfony_profiler, "laravel_log": _laravel_log, "php_error_log": _php_error_log,
    "npm_debug": _npm_debug, "sql_dump": _sql_dump, "zip": _zip, "gzip": _gzip, "tar": _tar,
    "es_indices": _es_indices,
}

# How bad each kind is when found, for sorting and for the report. "secrets":
# credentials or keys are readable; "source": code or its history; "info":
# configuration or internals that help an attacker.
SEVERITY = {k: "info" for k in CHECKS}
SEVERITY.update({k: "secrets" for k in (
    "env", "htpasswd", "npmrc", "aws_credentials", "docker_auth", "git_credentials", "private_key",
    "php_config", "iis_config", "sftp_config", "spring_env", "hprof", "sql_dump", "sqlite")})
SEVERITY.update({k: "source" for k in (
    "git_head", "git_config", "svn_entries", "hg_requires", "bzr", "zip", "gzip", "tar")})
SEVERITY_ORDER = {"secrets": 0, "source": 1, "info": 2}
LEAD = "lead"

# --- The list ----------------------------------------------------------------
# (path, kind). {host} is the host itself and {label} its first label
# (shop for shop.example.com): the backup names people actually use.

ARCHIVE_NAMES = ("backup", "site", "www", "web", "wwwroot", "app", "old", "{host}", "{label}")
ARCHIVE_EXTS = (("zip", "zip"), ("tar.gz", "gzip"), ("tar", "tar"))
SQL_NAMES = ("dump", "db", "database", "backup", "data", "mysql", "{label}")

PATHS = [
    ("/.git/HEAD", "git_head"), ("/.git/config", "git_config"),
    ("/.svn/entries", "svn_entries"), ("/.svn/wc.db", "sqlite"),
    ("/.hg/requires", "hg_requires"), ("/.bzr/README", "bzr"), ("/.DS_Store", "ds_store"),
    *[(p, "env") for p in ("/.env", "/.env.local", "/.env.production", "/.env.prod", "/.env.dev",
                           "/.env.development", "/.env.staging", "/.env.backup", "/.env.bak",
                           "/.env.old", "/.env.save", "/.env.example", "/app/.env", "/api/.env",
                           "/backend/.env", "/admin/.env")],
    ("/.htpasswd", "htpasswd"), ("/.npmrc", "npmrc"), ("/.aws/credentials", "aws_credentials"),
    ("/.docker/config.json", "docker_auth"), ("/.dockercfg", "docker_auth"),
    ("/.git-credentials", "git_credentials"),
    *[(p, "private_key") for p in ("/id_rsa", "/id_ecdsa", "/id_ed25519", "/.ssh/id_rsa",
                                   "/server.key", "/private.key", "/key.pem")],
    *[(p, "php_config") for p in ("/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
                                  "/wp-config.php.save", "/wp-config.bak", "/wp-config.txt",
                                  "/config.php.bak", "/config.php~", "/configuration.php.bak",
                                  "/config.inc.php.bak", "/settings.php.bak")],
    ("/web.config.bak", "iis_config"), ("/web.config.old", "iis_config"),
    ("/.vscode/sftp.json", "sftp_config"), ("/sftp-config.json", "sftp_config"),
    ("/.ftpconfig", "sftp_config"),
    ("/docker-compose.yml", "compose"), ("/docker-compose.yaml", "compose"),
    ("/docker-compose.prod.yml", "compose"), ("/Dockerfile", "dockerfile"),
    *[(p, "phpinfo") for p in ("/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo", "/test.php", "/i.php")],
    ("/server-status", "apache_status"), ("/server-info", "apache_info"), ("/nginx_status", "nginx_status"),
    ("/actuator/env", "spring_env"), ("/env", "spring_env"), ("/manage/env", "spring_env"),
    ("/actuator/heapdump", "hprof"), ("/heapdump", "hprof"),
    ("/elmah.axd", "elmah"), ("/trace.axd", "trace_axd"), ("/WEB-INF/web.xml", "web_xml"),
    ("/debug/pprof/", "pprof"), ("/debug/vars", "expvar"), ("/_profiler/", "symfony_profiler"),
    ("/storage/logs/laravel.log", "laravel_log"), ("/error_log", "php_error_log"),
    ("/php_errors.log", "php_error_log"), ("/npm-debug.log", "npm_debug"),
    ("/_cat/indices", "es_indices"),
    *[(f"/{n}.sql", "sql_dump") for n in SQL_NAMES],
    *[(f"/{n}.{ext}", kind) for n in ARCHIVE_NAMES for ext, kind in ARCHIVE_EXTS],
    # leads: no fixed content, reported only when they answer unlike a made-up path
    *[(p, LEAD) for p in (
        "/admin", "/admin/", "/administrator/", "/login", "/wp-admin/", "/wp-login.php", "/user/login",
        "/console", "/dashboard", "/manager/html", "/jenkins/", "/script", "/grafana/", "/kibana/",
        "/phpmyadmin/", "/pma/", "/adminer.php", "/debug", "/_debug", "/__debug__/", "/internal",
        "/private", "/api", "/api/v1", "/api/internal", "/graphql", "/graphiql", "/metrics",
        "/actuator", "/health", "/telescope", "/horizon", "/jmx-console/", "/web-console/", "/solr/",
        "/upload", "/uploads/", "/backup/", "/test/", "/staging/")],
]


def host_paths(host: str, extra: list[str] | None = None) -> list[tuple[str, str]]:
    """The list for one host: {host}/{label} filled in, duplicates dropped
    (keeping the first, so a file check wins over a lead), then any --wordlist
    paths as leads."""
    label = host.split(".")[0]
    out, seen = [], set()
    for path, kind in PATHS + [(p, LEAD) for p in (extra or [])]:
        path = path.replace("{host}", host).replace("{label}", label)
        if path not in seen:
            seen.add(path)
            out.append((path, kind))
    return out


def max_requests(extra_count: int = 0) -> int:
    """The most requests one host can take: calibration, one HTTP retry, the list."""
    return CALIBRATION + 1 + len(PATHS) + extra_count


MAX_REQUESTS = max_requests()

BAD_PATH_RE = re.compile(r"[\s#?\\]|\.\.|://|%2e|%2f|%5c|%25|%00", re.I)
# a path may only use these characters (RFC 3986 path characters, and % only
# before two hex digits): no control characters, nothing outside ASCII
PLAIN_PATH_RE = re.compile(r"^/(?!/)(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$")


class WordlistError(ValueError):
    pass


def load_wordlist(path: str) -> list[str]:
    """Paths from a --wordlist file (SecLists-style: one per line, # comments).
    Each must be a plain path: printable ASCII path characters only, no
    "..", no query, no "://", no leading "//", no backslash and no encoded
    dot, slash, percent or NUL, so it can only ever name a path on the host
    given."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise WordlistError(f"can't read {path}: {e.strerror}")
    out, bad = [], []
    for line in lines:
        p = line.strip()
        if not p or p.startswith("#"):
            continue
        p = p if p.startswith("/") else "/" + p
        if BAD_PATH_RE.search(p) or not PLAIN_PATH_RE.match(p) or len(p) > 200:
            bad.append(p)
            continue
        out.append(p)
    if bad:
        raise WordlistError(f"{len(bad)} line(s) aren't a plain path (first: {bad[0][:60]!r}); "
                            "remove them, nothing was sent")
    out = list(dict.fromkeys(out))
    if len(out) > MAX_WORDLIST:
        raise WordlistError(f"{len(out)} paths is more than {MAX_WORDLIST}; split the file")
    return out


# --- Sending -----------------------------------------------------------------

class _Budget:
    def __init__(self, n: int):
        self.left = n

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def _read(resp, deadline: float) -> tuple[bytes, bool]:
    """Up to MAX_BODY_BYTES of the body, and whether there was more. read1
    returns as soon as any bytes arrive (iter_content waits for a whole
    chunk), so the deadline is checked after every few bytes: a server that
    sends one byte every few seconds can't hold a request past it. Each wait
    is still bounded by the request's timeout."""
    chunks, size = [], 0
    while size < MAX_BODY_BYTES:
        if CLOCK() > deadline:
            return b"".join(chunks), True
        chunk = resp.raw.read1(CHUNK, decode_content=True)
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)[:MAX_BODY_BYTES], True


def _get(url, host, *, scope, limiter, research, on_request, timeout, budget, stop_at):
    """One GET with every guard, in this order: scope (nothing sent if it
    fails), the run's time limit, the host's cap, the --rate slot, the log
    line, then the request. Returns {"status", "headers", "body", "length"}."""
    rule = check_url(scope, url)  # OutOfScope: no log line, no request
    if stop_at is not None and CLOCK() > stop_at:
        raise TimeLimit("the run's time limit passed")
    if not budget.take():
        raise RequestCapReached("this host's request cap is used up")
    limiter.wait()
    if stop_at is not None and CLOCK() > stop_at:
        raise TimeLimit("the run's time limit passed")
    if on_request:
        on_request(host, url, rule)
    resp = requests.get(url, headers=request_headers(research), timeout=timeout,
                        allow_redirects=False, stream=True)
    try:
        deadline = CLOCK() + 2 * timeout
        if stop_at is not None:
            deadline = min(deadline, stop_at)
        body, more = _read(resp, deadline)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return {"status": resp.status_code, "headers": headers, "body": body,
                "length": _length(headers, body, more)}
    finally:
        resp.close()


def _length(headers, body, more=False):
    """The body's full length: Content-Length, else what was read, else None
    when the body was cut off and its real length is unknown."""
    try:
        return int(headers.get("content-length"))
    except (TypeError, ValueError):
        return None if more else len(body)


# --- Telling a real answer from "not found" ----------------------------------

def _shape(answer: dict, token: str | None = None) -> tuple:
    """What a not-found answer looks like: its status and its body with the
    made-up path taken out (pages often echo the path back)."""
    body = answer["body"]
    if token:
        body = body.replace(token.encode(), b"")
    return answer["status"], hash(body)


def _like(answer: dict, baseline: list[dict], path: str) -> bool:
    """Does this answer look like the host's not-found? Same status and
    either the same body (path taken out) or a length within 5%."""
    if answer["status"] in (404, 410):
        return True
    for b in baseline:
        if answer["status"] != b["status"]:
            continue
        if 300 <= answer["status"] < 400:   # a redirect is told apart by where it goes, nothing else
            if answer["headers"].get("location", "").replace(path, "") == b["location"]:
                return True
            continue
        if _shape(answer, path.lstrip("/")) == (b["status"], b["shape"][1]):
            return True
        n, m = answer["length"], b["length"]
        if n is not None and m is not None and (max(n, m) == 0 or abs(n - m) <= 0.05 * max(n, m)):
            return True
    return False


def calibration_paths(token: str) -> list[str]:
    """The made-up paths: a plain one, a dot-file and a file with an
    extension, since sites often answer each kind of path differently."""
    return [f"/{token}", f"/.{token}", f"/{token}.zip"][:CALIBRATION]


def _baseline(path: str, a: dict) -> dict:
    return {"status": a["status"], "length": a["length"], "shape": _shape(a, path.lstrip("/")),
            "location": a["headers"].get("location", "").replace(path, ""), "body": a["body"]}


STOPS = (OutOfScope, RequestCapReached, TimeLimit)


AUTH_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,29}")


def _lead(path: str, url: str, a: dict) -> dict:
    """A lead's record. The target writes the Location and WWW-Authenticate
    headers, so only their safe parts are kept: a redirect's address without
    its query (which can carry tokens or SSO state), and the login scheme's
    name only."""
    lead = {"path": path, "url": url, "status": a["status"], "length": a["length"]}
    if 300 <= a["status"] < 400:
        loc = a["headers"].get("location", "")
        bare = loc.split("#", 1)[0].split("?", 1)[0]
        lead["location"] = bare[:200]   # recorded, never followed
        if bare != loc:
            lead["location_query_dropped"] = True
    if a["status"] == 401:
        m = AUTH_SCHEME_RE.match(a["headers"].get("www-authenticate", "").strip())
        lead["auth"] = m.group(0) if m else "unknown"
    return lead


def _encoded_tar(a: dict, body: bytes) -> bool:
    """A .tar.gz served with Content-Encoding: gzip arrives already
    decompressed by requests, so it's a tar by then."""
    return a["headers"].get("content-encoding", "").strip().lower() in ("gzip", "x-gzip") and bool(_tar(body))


def judge_file(path: str, kind: str, answer: dict) -> str | None:
    """What a 200 answer for this file path is, when its content passes that
    kind's check ("a Git HEAD file..."), else None. The one place that
    decides "this is the real file": the list run and recheck_file() (what
    Akashi re-asks, v1.27) both use it, so they can never disagree."""
    # a not-found page that echoes the path back must not pass a check because of the path
    body = answer["body"].replace(path.encode(), b"").replace(path.lstrip("/").encode(), b"")
    what = CHECKS[kind](body)
    if not what and kind == "gzip" and _encoded_tar(answer, body):
        what = "a gzip archive (the server decompressed it on the way: a tar inside)"
    return what


def check_host(host, timeout=8, on_request=None, *, scope, limiter=ratemod.UNLIMITED, research=None,
               extra=None, stop_at=None, progress=None):
    """Run the list on one host. Returns a dict:
    {"host", "scheme" ("https", "http" or None if neither answered), "found"
    [{"path", "url", "kind", "severity", "what", "status"}], "leads" [{"path",
    "url", "status", "length", "location"?}], "untrusted" (file checks a
    made-up path passed, so skipped here), "calibration" (statuses), "tried",
    "requests" (sent, matching the audit log), "stopped" (why it ended early,
    or None), "https_error"}."""
    sent = [0]

    def logged(h, url, rule):
        sent[0] += 1
        if on_request:
            on_request(h, url, rule)

    budget = _Budget(max_requests(len(extra or [])))

    def get(url):
        return _get(url, host, scope=scope, limiter=limiter, research=research, on_request=logged,
                    timeout=timeout, budget=budget, stop_at=stop_at)

    out = {"host": host, "scheme": None, "found": [], "leads": [], "untrusted": [],
           "calibration": [], "tried": 0, "requests": 0, "stopped": None, "https_error": None,
           "collected_at": now_utc()}

    def done(**changes):
        out.update(changes, requests=sent[0])
        return out

    made_up = calibration_paths(TOKEN())
    base, baseline = f"https://{host}", []
    # The first made-up path also decides the scheme, the same rule as
    # --fingerprint: plain HTTP once, only when HTTPS couldn't connect (TLS
    # broke, or the connection was refused or reset), never after a timeout.
    try:
        baseline.append(_baseline(made_up[0], get(base + made_up[0])))
        out["scheme"] = "https"
    except STOPS as e:
        return done(stopped=str(e))
    except requests.RequestException as e:
        if not _retry_on_http(e):
            return done()
        out["https_error"] = type(e).__name__
        base = f"http://{host}"
        try:
            baseline.append(_baseline(made_up[0], get(base + made_up[0])))
            out["scheme"] = "http"
        except STOPS as e2:
            return done(stopped=str(e2))
        except requests.RequestException:
            return done()
    for path in made_up[1:]:
        try:
            baseline.append(_baseline(path, get(base + path)))
        except STOPS as e:
            return done(stopped=str(e))
        except requests.RequestException:
            continue
    # a file check a made-up path passes can't be trusted on this host
    untrusted = {k for b in baseline if b["status"] < 400 for k, check in CHECKS.items() if check(b["body"])}
    out["calibration"] = [b["status"] for b in baseline]
    out["untrusted"] = sorted(untrusted)
    for path, kind in host_paths(host, extra):
        if kind in untrusted:
            if progress:
                progress()
            continue
        url = base + path
        try:
            a = get(url)
        except STOPS as e:
            out["stopped"] = str(e)
            break
        except requests.RequestException:
            out["tried"] += 1
            if progress:
                progress()
            continue
        out["tried"] += 1
        if progress:
            progress()
        if kind == LEAD:
            if a["status"] in (200, 204, 301, 302, 303, 307, 308, 401, 403) and not _like(a, baseline, path):
                out["leads"].append(_lead(path, url, a))
            continue
        if a["status"] != 200:
            continue
        what = judge_file(path, kind, a)
        if what:
            severity = SEVERITY[kind]
            if kind == "env" and path.endswith(".example"):
                severity, what = "info", what + ", a template"
            out["found"].append({"path": path, "url": url, "kind": kind, "severity": severity,
                                 "what": what, "status": a["status"]})
    out["found"].sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["path"]))
    out["requests"] = sent[0]
    return out


def check_all(enrichment, workers=4, on_request=None, max_hosts=MAX_HOSTS, timeout=8, *, scope,
              limiter=ratemod.UNLIMITED, research=None, extra=None, time_limit=None, progress=None):
    """Run the list on every host from --enrich that has a public IP.
    One limiter for the whole run (so --rate is a total). time_limit, if
    given, is the most seconds the whole run may take: past it nothing more
    is sent and each host says it stopped. Returns {"hosts": {host: result},
    "found" (count), "leads" (count), "requested", "checked", "requests",
    "skipped", "paths" (list length per host)}."""
    import ipaddress

    hosts = sorted(h for h, e in enrichment["hosts"].items()
                   if any(ipaddress.ip_address(ip).is_global for ip in e["ips"]))
    skipped = max(0, len(hosts) - max_hosts)
    hosts = hosts[:max_hosts]
    stop_at = CLOCK() + time_limit if time_limit else None

    def run(host):
        return check_host(host, timeout=timeout, on_request=on_request, scope=scope, limiter=limiter,
                          research=research, extra=extra, stop_at=stop_at, progress=progress)

    results = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for r in pool.map(run, hosts):
            results[r["host"]] = r
    return {"hosts": results, "found": sum(len(r["found"]) for r in results.values()),
            "leads": sum(len(r["leads"]) for r in results.values()),
            "requested": hosts, "checked": len(hosts),
            "requests": sum(r["requests"] for r in results.values()), "skipped": skipped,
            "paths": len(PATHS) + len(extra or [])}


# --- Re-checking one file (v1.27, for Akashi) --------------------------------
#
# Akashi proves an exposed_file path by asking again, right now, for each file
# Monomi found. It sends the same made-up paths first (a site that changed to
# serving one page for every URL must not prove anything), then the file
# itself, through the same guards as the list run: scope per request, no
# redirect followed, at most MAX_BODY_BYTES read, the same file check.

# What recheck_file() can say. Akashi turns these into verdicts, so the words
# never change once released (tests/test_contract.py locks them).
STILL_SERVED = "still_served"  # the file answered 200 and is still the real thing
GONE = "gone"                  # not found now, blocked for that path alone, or no longer the real file
UNTRUSTED = "untrusted"        # a made-up path passes the same check: this host can't tell
UNCLEAR = "unclear"            # no clean answer (a timeout, 429, 5xx, every path blocked)
RECHECK_RESULTS = (STILL_SERVED, GONE, UNTRUSTED, UNCLEAR)
RECHECK_REQUESTS = CALIBRATION + 1
BLOCKED = (301, 302, 303, 307, 308, 401, 403)  # "not for you": the fix, when only this path gets it


def recheck_file(url: str, kind: str, *, scope, research=None, on_request=None, timeout=8) -> dict:
    """Ask for one file again: CALIBRATION made-up paths on the same host,
    then the file. Returns {"url", "kind", "result" (one of RECHECK_RESULTS),
    "why" (one line), "what" (for still_served), "status" (the file's HTTP
    status, or None), "calibration" (made-up path statuses), "requests" (sent)}.

    An out-of-scope URL raises scope.OutOfScope before anything is sent.
    A kind that isn't a file check (a lead, a typo) is a ValueError: there is
    nothing fixed to compare a lead with."""
    from urllib.parse import urlsplit
    from monomi.scope import request_host

    if kind not in CHECKS:
        raise ValueError(f"{kind!r} is not a file kind content.py checks")
    check_url(scope, url)  # refuse a bad URL before working anything out from it
    parts = urlsplit(url)
    path = parts.path or "/"
    base = f"{parts.scheme}://{parts.netloc}"
    host = request_host(url)
    sent = [0]

    def logged(h, u, rule):
        sent[0] += 1
        if on_request:
            on_request(h, u, rule)

    budget = _Budget(RECHECK_REQUESTS)

    def get(u):
        return _get(u, host, scope=scope, limiter=ratemod.UNLIMITED, research=research, on_request=logged,
                    timeout=timeout, budget=budget, stop_at=None)

    out = {"url": url, "kind": kind, "result": UNCLEAR, "why": "", "what": None, "status": None,
           "calibration": [], "requests": 0}

    def done(result, why, **changes):
        out.update(changes, result=result, why=why, requests=sent[0])
        return out

    baseline = []
    for p in calibration_paths(TOKEN()):
        try:
            a = get(base + p)
        except requests.RequestException as e:
            if isinstance(e, OutOfScope):
                raise
            out["calibration"].append(type(e).__name__)
            continue
        baseline.append(a)
        out["calibration"].append(a["status"])
    if any(b["status"] < 400 and CHECKS[kind](b["body"]) for b in baseline):
        return done(UNTRUSTED, f"a made-up path on {host} passes the {kind} check too, so this host "
                    "can't show whether the file is really there")
    try:
        a = get(url)
    except requests.RequestException as e:
        if isinstance(e, OutOfScope):
            raise
        return done(UNCLEAR, f"the request didn't complete ({type(e).__name__})")
    status = a["status"]
    if status == 200:
        what = judge_file(path, kind, a)
        if what:
            return done(STILL_SERVED, f"{path} still answers 200 with {what}", what=what, status=status)
        return done(GONE, f"{path} answers 200, but no longer with a real {kind} file", status=status)
    if status in (404, 410):
        return done(GONE, f"{path} is not found now (HTTP {status})", status=status)
    if status in BLOCKED:
        if not baseline or all(b["status"] == status for b in baseline):
            return done(UNCLEAR, f"{path} answers HTTP {status} and no made-up path answered "
                        "differently, so this can't show whether the file was removed or the host "
                        "blocks everyone",
                        status=status)
        return done(GONE, f"{path} is refused now (HTTP {status}), while made-up paths aren't",
                    status=status)
    return done(UNCLEAR, f"{path} answered HTTP {status}, which can't settle it", status=status)
