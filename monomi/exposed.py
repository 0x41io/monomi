"""
Exposed developer files: API specs and JavaScript source maps a site serves
to anyone. Monomi's second opt-in ACTIVE check (after --fingerprint).

An OpenAPI/Swagger spec is a full map of an API's endpoints; a JS source
map (.map) rebuilds the original source layout, and sometimes the source
code itself (sourcesContent). Neither is a flaw on its own, but both hand
an attacker (or a bug-bounty hunter) a shortcut, so programs often want to
know when they're public.

Only runs with --exposed-files. For each host it sends a small, fixed set
of GET requests (see MAX_REQUESTS): the homepage, a short list of
well-known spec paths, a few of the homepage's same-host scripts, and the
.map files those scripts point to. The homepage goes first and decides the
scheme (v1.24): HTTPS, or plain HTTP once when HTTPS fails with a TLS error
or is refused (the same rule as --fingerprint), and the spec paths follow
over whichever answered. A host that answers neither gets nothing more. It never POSTs, never follows a spec to call the API,
and never leaves the hosts it was given. A file counts as a finding only
when it actually parses as what it claims to be, so soft-404 pages (a 200
HTML page for any path) are not mistaken for specs. Source code found in a
map is reported as present, never saved or returned.
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests

from monomi import rate as ratemod
from monomi.common import now_utc
from monomi.fingerprint import _retry_on_http
from monomi.research import request_headers
from monomi.scope import OutOfScope, check_url, named_host, normalize_host, request_host

# Well-known places an OpenAPI/Swagger spec is served, tried in order.
SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v3/api-docs",
    "/v2/api-docs", "/swagger/v1/swagger.json", "/api-docs",
]

MAX_SPEC_BYTES = 2 * 1024 * 1024   # a spec past this is reported, not parsed
MAX_MAP_BYTES = 5 * 1024 * 1024    # source maps are bigger (they hold code)
MAX_HTML_BYTES = 512 * 1024        # only need the homepage's <script> tags
MAX_SCRIPTS = 3                    # same-host scripts checked per host
MAX_MAPS = 3                       # .map files fetched per host
MAX_HOSTS = 10                     # hosts per call (active: stays small)

# Worst case per host: homepage over HTTPS, then HTTP + 6 spec paths + 3 scripts + 3 maps.
MAX_REQUESTS = 2 + len(SPEC_PATHS) + MAX_SCRIPTS + MAX_MAPS

# <script src="..."> — captures the URL inside single or double quotes.
SCRIPT_SRC_RE = re.compile(r"""<script[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
# //# sourceMappingURL=app.js.map  (also the older //@ form)
SOURCE_MAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""")
# first 20/10 is enough to make the point without dumping the whole file
PATHS_SHOWN = 20
SOURCES_SHOWN = 10


def _fetch(url, timeout, on_request, host, want_body=False, cap=0, *, scope,
           limiter=ratemod.UNLIMITED, research=None):
    """One GET. Returns {"url", "status", "headers", "body" (bytes|None),
    "truncated"}; raises requests.RequestException if the host can't answer.

    scope (required, no default): the host is read from `url` itself (not
    the `host` label) and checked first; out of scope raises
    scope.OutOfScope, a requests error, so callers skip it like a host that
    didn't answer, and nothing is sent. This covers the spec paths, the
    homepage, scripts and source maps alike.
    on_request(host, url, scope_rule), if given, is called right before the
    request so the audit log is written. Only `cap` bytes of the body are
    read (truncated=True if there was more), so one huge file can't blow up
    memory or the time budget.
    limiter and research: see fingerprint.fetch_headers (same order: scope
    check, wait for the --rate slot, log, send).
    """
    rule = check_url(scope, url)  # raises OutOfScope: no log line, no request
    limiter.wait()
    if on_request:
        on_request(host, url, rule)
    resp = requests.get(
        url,
        headers=request_headers(research),
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    try:
        body, truncated = None, False
        if want_body:
            chunks, size = [], 0
            for chunk in resp.iter_content(8192):
                chunks.append(chunk)
                size += len(chunk)
                if size > cap:
                    truncated = True
                    break
            body = b"".join(chunks)[:cap]
        return {
            "url": url,
            "status": resp.status_code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "body": body,
            "truncated": truncated,
        }
    finally:
        resp.close()


def _json_body(result):
    """Parse a fetched body as JSON, or None if it isn't JSON (or was cut off)."""
    if not result or result["truncated"] or not result["body"]:
        return None
    try:
        return json.loads(result["body"].decode("utf-8", "replace"))
    except ValueError:
        return None


def read_openapi(data):
    """Turn a parsed spec into a finding, or None if it isn't really one.

    The strict part: a real spec has an openapi/swagger VERSION string and
    a `paths` OBJECT. A soft-404 HTML page never parses as JSON, and a
    random JSON file almost never has both, so this is what keeps us from
    inventing a finding.
    """
    if not isinstance(data, dict):
        return None
    version = data.get("openapi") or data.get("swagger")
    paths = data.get("paths")
    if not isinstance(version, str) or not isinstance(paths, dict):
        return None
    kind = "OpenAPI" if "openapi" in data else "Swagger"
    methods = sum(len(ops) for ops in paths.values() if isinstance(ops, dict))
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    servers = [s.get("url") for s in data.get("servers", [])
               if isinstance(s, dict) and isinstance(s.get("url"), str)]
    components = data.get("components")
    # does it describe any way to log in? (a hint at how much it exposes)
    declares_auth = bool(data.get("securityDefinitions")) or (
        isinstance(components, dict) and bool(components.get("securitySchemes")))
    return {
        "type": kind,
        "version": version,
        "title": info.get("title") if isinstance(info.get("title"), str) else None,
        "endpoint_count": len(paths),
        "method_count": methods,
        "paths": sorted(p for p in paths if isinstance(p, str))[:PATHS_SHOWN],
        "servers": servers[:PATHS_SHOWN],
        "declares_auth": declares_auth,
    }


def read_source_map(data):
    """Turn a parsed .map into a finding, or None if it isn't a v3 source map.

    has_source_content is the bigger leak: the original CODE is embedded, not
    just the file names. The code itself is never copied into the finding.
    """
    if not isinstance(data, dict):
        return None
    if data.get("version") != 3 or not isinstance(data.get("sources"), list):
        return None
    sources = [s for s in data["sources"] if isinstance(s, str)]
    contents = data.get("sourcesContent")
    has_code = isinstance(contents, list) and any(isinstance(c, str) and c for c in contents)
    return {
        "source_count": len(sources),
        "sources": sources[:SOURCES_SHOWN],
        "has_source_content": has_code,
    }


def _on_host(url, host) -> bool:
    """Is this http(s) URL on `host`, as BOTH parsers read it?

    Asks where `requests` would really connect (scope.request_host), not just
    urlparse: before v1.25, <script src="https://evil.test\\@host/x.js"> passed
    this rule and the scope check while the request went to evil.test."""
    if urlparse(url).scheme not in ("http", "https"):
        return False
    real = request_host(url)
    return real is not None and real == named_host(url) == normalize_host(host)


def _same_host_scripts(html, base_url, host):
    """The homepage's <script src> URLs that live on this same host.

    Cross-host scripts (a CDN, Google) aren't the target's to leak, so
    they're skipped. Relative paths are resolved against the page URL.
    """
    out = []
    for src in SCRIPT_SRC_RE.findall(html):
        try:
            full = urljoin(base_url, src)
        except ValueError:
            continue  # not a URL at all (e.g. a broken [IPv6] host): skipped, never sent
        if _on_host(full, host) and full not in out:
            out.append(full)
    return out


def _map_urls(js_result, host):
    """Where a script says its source map is: the sourceMappingURL comment
    (resolved against the script URL) and the SourceMap/X-SourceMap header.

    Only URLs on this same host are kept. Both come from the target, so a
    script could point its map anywhere (another site, a cloud metadata
    address); fetching that would leave the hosts Monomi was given.
    """
    urls, js_url = [], js_result["url"]
    headers = js_result["headers"]
    body = (js_result["body"] or b"").decode("utf-8", "replace")
    refs = [ref for ref in SOURCE_MAP_RE.findall(body)
            if not ref.startswith("data:")]  # inline maps are already in the page
    refs += [headers[h] for h in ("sourcemap", "x-sourcemap") if headers.get(h)]
    for ref in refs:
        try:
            urls.append(urljoin(js_url, ref))
        except ValueError:
            continue  # not a URL at all: skipped, never sent
    seen, unique = set(), []
    for u in urls:
        if not _on_host(u, host):
            continue  # same rule as _same_host_scripts
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def _homepage(host, fetch):
    """The homepage, which decides the scheme for everything after it (v1.24).
    Returns (result or None, scheme or None, the HTTPS failure's name or None).

    HTTPS first. When it fails in a way plain HTTP might not (a TLS error, or
    nothing listening on 443: fingerprint._retry_on_http, the same rule as
    --fingerprint), http:// once. Never after a timeout (a second wait could
    push an MCP call past its limit) or when the scope refused the URL."""
    try:
        return fetch(f"https://{host}/", want_body=True, cap=MAX_HTML_BYTES), "https", None
    except OutOfScope:
        return None, None, None
    except requests.RequestException as e:
        https_error = type(e).__name__
        if not _retry_on_http(e):
            return None, None, https_error
    try:
        return fetch(f"http://{host}/", want_body=True, cap=MAX_HTML_BYTES), "http", https_error
    except requests.RequestException:
        return None, None, https_error


def _find_spec(host, fetch, scheme="https"):
    """Try the spec paths in order; return (finding, requests_sent).
    Stops at the first path that really parses as a spec."""
    sent = 0
    for path in SPEC_PATHS:
        sent += 1
        try:
            result = fetch(f"{scheme}://{host}{path}", want_body=True, cap=MAX_SPEC_BYTES)
        except requests.RequestException:
            continue
        spec = read_openapi(_json_body(result))
        if spec:
            spec["url"] = result["url"]
            return spec, sent
    return None, sent


def _find_source_maps(host, fetch, home):
    """Homepage (already fetched, see _homepage) -> same-host scripts -> their
    .map files. Returns (list of map findings, requests_sent)."""
    sent = 0
    html = (home["body"] or b"").decode("utf-8", "replace")
    scripts = _same_host_scripts(html, home["url"], host)[:MAX_SCRIPTS]

    candidates, maps = [], []
    for js_url in scripts:
        sent += 1
        try:
            js = fetch(js_url, want_body=True, cap=MAX_SPEC_BYTES)
        except requests.RequestException:
            continue
        for map_url in _map_urls(js, host):
            if map_url not in candidates:
                candidates.append((map_url, js_url))

    for map_url, js_url in candidates[:MAX_MAPS]:
        sent += 1
        try:
            result = fetch(map_url, want_body=True, cap=MAX_MAP_BYTES)
        except requests.RequestException:
            continue
        found = read_source_map(_json_body(result))
        if found:
            found["map_url"] = map_url
            found["from_script"] = js_url
            maps.append(found)
    return maps, sent


def _answer(fetch, outcomes):
    """fetch, but every call's outcome is added to `outcomes`: the HTTP
    status, "out of scope" (nothing sent) or "no answer"."""
    def wrapped(url, want_body=False, cap=0):
        try:
            result = fetch(url, want_body=want_body, cap=cap)
        except OutOfScope:
            outcomes.append("out of scope")
            raise
        except requests.RequestException:
            outcomes.append("no answer")
            raise
        outcomes.append(result["status"])
        return result
    return wrapped


def check_host(host, timeout=8, on_request=None, *, scope,
               limiter=ratemod.UNLIMITED, research=None, coverage=None):
    """Check one host for an exposed spec and source maps.
    Returns (finding dict or None, requests_sent). None = nothing found.
    scope is required (see _fetch). requests_sent counts the requests that
    really went out (the moment each is logged), so a URL the scope blocked
    is never counted and the number always matches the audit log.
    coverage, if given (a dict), is filled with what was checked (v1.23), so
    a clean result can say what "nothing found" covers: {"spec_paths":
    {"tried", "answered"}, "homepage": its status, "no answer" or "out of
    scope", "scheme": "https", "http" or None (nothing answered), "https_error":
    why HTTPS failed when it fell back to HTTP (or None), "scripts_and_maps":
    the scripts and .map files requested, "requests"}."""
    sent_count = [0]

    def sent_now(h, url, rule):
        sent_count[0] += 1
        if on_request:
            on_request(h, url, rule)

    def fetch(url, want_body=False, cap=0):
        return _fetch(url, timeout, sent_now, host, want_body=want_body, cap=cap,
                      scope=scope, limiter=limiter, research=research)

    home_outcomes, spec_outcomes, page_outcomes = [], [], []
    home, scheme, https_error = _homepage(host, _answer(fetch, home_outcomes))
    spec, maps = None, []
    if home is not None:  # nothing more for a host that answered neither scheme
        spec, _ = _find_spec(host, _answer(fetch, spec_outcomes), scheme)
        maps, _ = _find_source_maps(host, _answer(fetch, page_outcomes), home)
    sent = sent_count[0]
    if coverage is not None:
        coverage.update({
            "spec_paths": {"tried": len(spec_outcomes),
                           "answered": sum(isinstance(o, int) for o in spec_outcomes)},
            "homepage": home_outcomes[-1] if home_outcomes else "not requested",
            "scheme": scheme, "https_error": https_error,
            "scripts_and_maps": len(page_outcomes),
            "requests": sent})
    if not spec and not maps:
        return None, sent
    return {"host": host, "spec": spec, "source_maps": maps,
            "collected_at": now_utc()}, sent


def check_all(enrichment, workers=8, on_request=None, max_hosts=MAX_HOSTS, timeout=8, *, scope,
              limiter=ratemod.UNLIMITED, research=None):
    """Check every host from --enrich that has a public IP.
    scope is required (see _fetch); limiter and research too (one limiter
    for the whole run, so --rate is a total across threads).

    Returns {"hosts": {host: finding}, "requested", "checked", "requests",
    "skipped", "coverage"}. "hosts" holds only hosts where something was found (never
    invent a finding); "requested" is every host actually contacted (so the
    caller can report the ones with no public IP); "requests" counts every
    request sent, matching the audit log; "coverage" is what was checked on
    each requested host (see check_host), found or not.
    """
    import ipaddress

    hosts = sorted(
        host for host, e in enrichment["hosts"].items()
        if any(ipaddress.ip_address(ip).is_global for ip in e["ips"])
    )
    skipped = max(0, len(hosts) - max_hosts)
    hosts = hosts[:max_hosts]

    coverage = {host: {} for host in hosts}  # one dict per host: each thread fills its own

    def run(host):
        return host, check_host(host, timeout=timeout, on_request=on_request, scope=scope,
                                limiter=limiter, research=research, coverage=coverage[host])

    found, sent = {}, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, (finding, n) in pool.map(run, hosts):
            sent += n
            if finding:
                found[host] = finding
    return {"hosts": found, "requested": hosts, "checked": len(hosts),
            "requests": sent, "skipped": skipped, "coverage": coverage}
