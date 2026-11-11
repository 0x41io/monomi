"""Tests for exposed.py: validating specs and maps, and the fetch flow.
Every request is faked, so nothing touches the network."""

import json
from urllib.parse import urlparse

import pytest
import requests

import exposed


# ---------- read_openapi: only a real spec counts ----------

OPENAPI = {"openapi": "3.0.1", "info": {"title": "Lab API"},
           "paths": {"/users": {"get": {}, "post": {}}, "/health": {"get": {}}}}


def test_openapi_spec_is_read():
    spec = exposed.read_openapi(OPENAPI)
    assert spec["type"] == "OpenAPI" and spec["version"] == "3.0.1"
    assert spec["title"] == "Lab API"
    assert spec["endpoint_count"] == 2 and spec["method_count"] == 3
    assert spec["paths"] == ["/health", "/users"] and spec["declares_auth"] is False


def test_swagger_2_spec_is_read():
    data = {"swagger": "2.0", "paths": {"/v1/x": {"get": {}}},
            "securityDefinitions": {"apiKey": {}}}
    spec = exposed.read_openapi(data)
    assert spec["type"] == "Swagger" and spec["version"] == "2.0"
    assert spec["declares_auth"] is True


def test_openapi_reads_components_security_schemes():
    data = {"openapi": "3.1.0", "paths": {},
            "components": {"securitySchemes": {"bearer": {}}}}
    assert exposed.read_openapi(data)["declares_auth"] is True


def test_openapi_lists_server_urls():
    data = {"openapi": "3.0.0", "paths": {"/x": {"get": {}}},
            "servers": [{"url": "https://internal.api.lab/"}, {"url": "/v2"}]}
    assert exposed.read_openapi(data)["servers"] == ["https://internal.api.lab/", "/v2"]


@pytest.mark.parametrize("data", [
    {"paths": {"/x": {}}},                    # no version string
    {"openapi": "3.0.0"},                     # no paths object
    {"openapi": "3.0.0", "paths": []},        # paths isn't an object
    {"message": "Not Found"},                 # a JSON soft-404
    {"openapi": 3, "paths": {}},              # version isn't a string
    "not even a dict",
])
def test_non_specs_are_rejected(data):
    assert exposed.read_openapi(data) is None


def test_long_spec_shows_only_the_first_paths():
    paths = {f"/p{i}": {"get": {}} for i in range(50)}
    spec = exposed.read_openapi({"openapi": "3.0.0", "paths": paths})
    assert spec["endpoint_count"] == 50 and len(spec["paths"]) == exposed.PATHS_SHOWN


# ---------- read_source_map: v3 only, code flagged but never copied ----------

def test_source_map_without_code_is_read():
    data = {"version": 3, "sources": ["src/app.ts", "src/api.ts"]}
    found = exposed.read_source_map(data)
    assert found["source_count"] == 2 and found["sources"] == ["src/app.ts", "src/api.ts"]
    assert found["has_source_content"] is False


def test_source_map_with_code_is_flagged_but_code_not_kept():
    data = {"version": 3, "sources": ["src/secret.ts"],
            "sourcesContent": ["const KEY = 'do not leak';"]}
    found = exposed.read_source_map(data)
    assert found["has_source_content"] is True
    # the finding records that code is present, never the code itself
    assert "do not leak" not in json.dumps(found)


@pytest.mark.parametrize("data", [
    {"version": 2, "sources": []},            # wrong version
    {"sources": ["a.ts"]},                    # no version
    {"version": 3},                           # no sources list
    {"version": 3, "sources": "a.ts"},        # sources isn't a list
    42,
])
def test_non_source_maps_are_rejected(data):
    assert exposed.read_source_map(data) is None


# ---------- HTML and map-reference parsing ----------

def test_same_host_scripts_only():
    html = ('<script src="/static/app.js"></script>'
            '<script src="https://lab/bundle.js"></script>'
            '<script src="https://cdn.other/jquery.js"></script>'
            '<script src="https://lab/static/app.js"></script>')  # dup of the first
    out = exposed._same_host_scripts(html, "https://lab/", "lab")
    assert out == ["https://lab/static/app.js", "https://lab/bundle.js"]


def test_map_url_from_comment_and_header():
    js = {"url": "https://lab/static/app.js",
          "headers": {"sourcemap": "app.js.map"},
          "body": b"console.log(1)\n//# sourceMappingURL=app.min.js.map\n"}
    urls = exposed._map_urls(js, "lab")
    assert urls == ["https://lab/static/app.min.js.map", "https://lab/static/app.js.map"]


def test_inline_data_map_is_ignored():
    js = {"url": "https://lab/app.js", "headers": {},
          "body": b"//# sourceMappingURL=data:application/json;base64,eyJ2 ..."}
    assert exposed._map_urls(js, "lab") == []


# ---------- the fetch flow (fake HTTP) ----------

class Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def close(self):
        pass


def fake_site(monkeypatch, pages):
    """pages: {url: Resp or an exception instance}. Returns URLs requested."""
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        page = pages.get(url)
        if isinstance(page, Exception):
            raise page
        if page is None:
            return Resp(404, body=b"not found")
        return page
    monkeypatch.setattr(exposed.requests, "get", get)
    return sent


def test_check_host_finds_a_spec_and_stops_early(monkeypatch):
    pages = {"https://lab/openapi.json": Resp(body=json.dumps(OPENAPI).encode()),
             "https://lab/": Resp(body=b"<html>no scripts</html>")}
    sent = fake_site(monkeypatch, pages)
    finding, n = exposed.check_host("lab")
    assert finding["spec"]["type"] == "OpenAPI" and finding["source_maps"] == []
    # stopped at the first spec path, so the later ones were never requested
    assert "https://lab/swagger.json" not in sent
    assert "collected_at" in finding


def test_check_host_finds_a_source_map(monkeypatch):
    smap = {"version": 3, "sources": ["src/app.ts"], "sourcesContent": ["x"]}
    pages = {
        "https://lab/": Resp(body=b'<script src="/app.js"></script>'),
        "https://lab/app.js": Resp(headers={"sourcemap": "app.js.map"}, body=b"x=1"),
        "https://lab/app.js.map": Resp(body=json.dumps(smap).encode()),
    }
    fake_site(monkeypatch, pages)
    finding, n = exposed.check_host("lab")
    assert finding["spec"] is None
    [m] = finding["source_maps"]
    assert m["map_url"] == "https://lab/app.js.map" and m["has_source_content"] is True
    assert m["from_script"] == "https://lab/app.js"


def test_clean_host_is_no_finding(monkeypatch):
    # everything 404s, homepage has no scripts: nothing found, no invented finding
    fake_site(monkeypatch, {"https://lab/": Resp(body=b"<html></html>")})
    finding, n = exposed.check_host("lab")
    assert finding is None and n == len(exposed.SPEC_PATHS) + 1


def test_soft_404_html_is_not_a_spec(monkeypatch):
    # the classic trap: every path returns 200 with an HTML page
    def get(url, **kwargs):
        return Resp(200, body=b"<html>page</html>")
    monkeypatch.setattr(exposed.requests, "get", get)
    finding, n = exposed.check_host("lab")
    assert finding is None


def test_truncated_spec_is_not_parsed(monkeypatch):
    big = b'{"openapi":"3.0.0","paths":{}}' + b" " * (exposed.MAX_SPEC_BYTES)
    pages = {"https://lab/openapi.json": Resp(body=big),
             "https://lab/": Resp(body=b"<html></html>")}
    fake_site(monkeypatch, pages)
    finding, n = exposed.check_host("lab")
    assert finding is None  # over the cap -> truncated -> never parsed as JSON


def test_every_request_is_logged_and_counted(monkeypatch):
    pages = {"https://lab/openapi.json": Resp(body=json.dumps(OPENAPI).encode()),
             "https://lab/": Resp(body=b'<script src="/a.js"></script>'),
             "https://lab/a.js": Resp(body=b"//# sourceMappingURL=a.js.map"),
             "https://lab/a.js.map": Resp(body=b'{"version":3,"sources":[]}')}
    sent = fake_site(monkeypatch, pages)
    logged = []
    finding, n = exposed.check_host("lab", on_request=lambda host, url: logged.append((host, url)))
    assert n == len(sent) == len(logged)          # count matches the log exactly
    assert all(host == "lab" for host, _ in logged)
    assert logged[0] == ("lab", "https://lab/openapi.json")


def test_connection_errors_dont_crash_the_host(monkeypatch):
    pages = {"https://lab/openapi.json": requests.ConnectionError("refused"),
             "https://lab/": requests.Timeout("slow")}
    fake_site(monkeypatch, pages)
    finding, n = exposed.check_host("lab")
    assert finding is None and n == len(exposed.SPEC_PATHS) + 1


# ---------- check_all: public hosts only, requests counted ----------

def test_check_all_skips_private_and_unresolved(monkeypatch):
    fake_site(monkeypatch, {})  # everything 404s
    enrichment = {"hosts": {
        "pub": {"ips": ["8.8.8.8"]},
        "intranet": {"ips": ["10.0.0.5"]},
        "gone": {"ips": []},
    }}
    out = exposed.check_all(enrichment)
    assert out["checked"] == 1 and out["hosts"] == {}
    assert out["requests"] == len(exposed.SPEC_PATHS) + 1  # only "pub" was touched


def test_check_all_keeps_findings_and_counts_requests(monkeypatch):
    pages = {"https://pub/openapi.json": Resp(body=json.dumps(OPENAPI).encode()),
             "https://pub/": Resp(body=b"<html></html>")}
    fake_site(monkeypatch, pages)
    out = exposed.check_all({"hosts": {"pub": {"ips": ["8.8.8.8"]}}})
    assert list(out["hosts"]) == ["pub"]
    assert out["requests"] == 2  # first spec path hits, homepage has no scripts


def test_active_user_agent_is_sent(monkeypatch):
    seen = {}

    def get(url, **kwargs):
        seen["ua"] = kwargs["headers"]["User-Agent"]
        return Resp(404)
    monkeypatch.setattr(exposed.requests, "get", get)
    exposed._fetch("https://lab/x", 8, None, "lab")
    assert "active security check" in seen["ua"] and "passive" not in seen["ua"]


# ---------- maps on other hosts are never fetched (found in review, v1.11.1) ----------

def test_cross_host_map_urls_are_dropped():
    js = {"url": "https://lab/app.js",
          "headers": {"sourcemap": "http://169.254.169.254/latest/meta-data"},
          "body": b"//# sourceMappingURL=https://evil.example/x.map"}
    assert exposed._map_urls(js, "lab") == []


def test_non_web_scheme_map_urls_are_dropped():
    js = {"url": "https://lab/app.js", "headers": {},
          "body": b"//# sourceMappingURL=file:///etc/passwd"}
    assert exposed._map_urls(js, "lab") == []


def test_check_host_never_requests_another_host(monkeypatch):
    pages = {"https://lab/": Resp(body=b'<script src="/app.js"></script>'),
             "https://lab/app.js": Resp(
                 headers={"x-sourcemap": "http://169.254.169.254/latest/meta-data"},
                 body=b"//# sourceMappingURL=https://evil.example/x.map")}
    sent = fake_site(monkeypatch, pages)
    exposed.check_host("lab")
    assert all(urlparse(u).hostname == "lab" for u in sent), sent
