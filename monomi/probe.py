"""
Live-page probe: where does a host's homepage really land, and what is it?

fingerprint.py reads one response's HEADERS (server, tech, security
headers) and stops there on purpose: one request, headers only, redirects
NOT followed. This module goes one step further, to build the per-host
"live page" record the app-mapper needs:

  - it FOLLOWS redirects, so we learn where "/" really ends up (many hosts
    send you to www, to HTTPS, to a login page, or to another site), and
  - it reads just enough of the final page to pull out its <title>.

Every hop goes through the same steps as fingerprint: scope check, wait for
the --rate slot, log, send (with the research headers). A redirect that
would leave scope is recorded but never followed, so following redirects
can never walk Monomi onto a host it wasn't allowed to touch. The title is
written by the target: it's untrusted evidence, never instructions.

Like --fingerprint, this is an opt-in ACTIVE check.
"""

import html
import re
from urllib.parse import urljoin

import requests

from monomi import rate as ratemod
from monomi.common import now_utc
from monomi.fingerprint import _retry_on_http
from monomi.research import request_headers
from monomi.scope import UNSCOPED_CLI, OutOfScope, check_url

# Ceilings that keep the probe small and polite.
MAX_REDIRECTS = 5        # hops followed before we stop and say so
MAX_BODY_BYTES = 65536   # bytes of the final page read while looking for <title>
MAX_TITLE = 300          # characters of title kept

# <title ...>...</title>, any case, across newlines. Non-greedy: stops at
# the first </title>.
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _read_title(resp, headers: dict, max_bytes: int) -> str | None:
    """The page's <title>, reading at most max_bytes of the body.

    headers: the response headers, already lowercased. Only HTML is read: a
    PDF or an image has no title and could be big. The body is streamed and
    cut off at max_bytes, so a large page is never pulled in full just for a
    title that sits in its first few hundred bytes.
    """
    if "html" not in headers.get("content-type", "").lower():
        return None
    chunks, total = [], 0
    for chunk in resp.iter_content(8192):
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    text = b"".join(chunks)[:max_bytes].decode(resp.encoding or "utf-8", errors="replace")
    match = TITLE_RE.search(text)
    if not match:
        return None
    # "&amp;" -> "&", then drop control characters (an escape code in a
    # title could mess with the terminal), then squeeze runs of whitespace
    # (titles often wrap across lines) into single spaces.
    title = html.unescape(match.group(1))
    title = "".join(ch if ch.isprintable() else " " for ch in title)
    title = " ".join(title.split())
    return title[:MAX_TITLE] or None


def _record(host, start_url, final_url, status, chain, title, headers,
            *, redirect_blocked=None, hit_redirect_limit=False) -> dict:
    """One host's probe result. headers: already lowercased."""
    return {
        "host": host,
        "start_url": start_url,
        "final_url": final_url,
        "status": status,                          # status of the FINAL response
        "chain": chain,                            # one {"status", "from", "to"} per redirect followed
        "title": title,
        "headers": headers,
        "redirect_blocked": redirect_blocked,      # where a redirect wanted to go outside scope
        "hit_redirect_limit": hit_redirect_limit,  # still redirecting after max_redirects hops
        "collected_at": now_utc(),
    }


def fetch_live(host: str, timeout: int = 10, on_request=None, scheme: str = "https",
               *, scope, limiter=ratemod.UNLIMITED, research=None,
               max_redirects: int = MAX_REDIRECTS,
               max_body_bytes: int = MAX_BODY_BYTES) -> dict:
    """Follow scheme://host/ through its redirects to the final page and
    return a live-page record.

    scope (required, no default): a scope.Scope, or scope.UNSCOPED_CLI for a
    CLI run without --scope. If the FIRST URL is out of scope this raises
    scope.OutOfScope and nothing is sent. A LATER hop that leaves scope is
    never requested: it's kept in "redirect_blocked" and the redirect itself
    becomes the final response.
    on_request(host, url, scope_rule), if given, is called right before each
    request (it writes the audit log), once per hop.
    limiter and research: as in fingerprint.fetch_headers. Every hop takes
    its own --rate slot and carries the research headers. Order per hop:
    scope check, wait for the slot, log, send, so a refused URL never uses a
    slot or a log line.
    Raises requests.RequestException if a hop can't be reached.
    """
    start_url = f"{scheme}://{host}/"
    url = start_url
    chain = []
    for hop in range(max_redirects + 1):
        rule = check_url(scope, url)  # raises OutOfScope: no slot, no log line, no request
        limiter.wait()
        if on_request:
            on_request(host, url, rule)
        resp = requests.get(
            url,
            headers=request_headers(research),
            timeout=timeout,
            allow_redirects=False,  # we follow by hand, so every hop is scope-checked
            stream=True,            # the body is only read on the final page
        )
        try:
            status = resp.status_code
            # Lowercase once, like fingerprint: never rely on the header
            # container being case-insensitive.
            headers = {name.lower(): value for name, value in resp.headers.items()}
            location = headers.get("location")
            redirecting = bool(300 <= status < 400 and location)
            if redirecting and hop < max_redirects:
                target = urljoin(url, location)  # also turns "/login" into a full URL
                chain.append({"status": status, "from": url, "to": target})
                try:
                    check_url(scope, target)
                except OutOfScope:
                    return _record(host, start_url, url, status, chain, None, headers,
                                   redirect_blocked=target)
                url = target
                continue
            # The final response: a page, an error, or a redirect we ran out
            # of hops to follow. Only here is the body read, for the title.
            title = _read_title(resp, headers, max_body_bytes)
            return _record(host, start_url, url, status, chain, title, headers,
                           hit_redirect_limit=redirecting)
        finally:
            resp.close()  # free the connection, whether or not the body was read


def probe_host(host: str, timeout: int = 10, on_request=None, *, scope,
               limiter=ratemod.UNLIMITED, research=None,
               max_redirects: int = MAX_REDIRECTS,
               max_body_bytes: int = MAX_BODY_BYTES):
    """fetch_live() that never crashes: returns (host, record, error, requests sent).

    Same shape and HTTPS-then-HTTP rule as fingerprint._safe_fetch, so a
    scan can use either. If HTTPS fails in a way plain HTTP might not, tries
    http://host/ once; that record keeps the HTTPS failure in "https_error",
    so a site that only works without HTTPS is never shown as if HTTPS were
    fine.

    "requests sent" counts every request, redirect hops and the HTTP retry
    included. It's counted in the same hook that writes the log line, right
    before each request goes out, so it always matches the audit log.
    """
    sent = 0

    def counted(h, url, rule):
        nonlocal sent
        sent += 1
        if on_request:
            on_request(h, url, rule)

    options = {"scope": scope, "limiter": limiter, "research": research,
               "max_redirects": max_redirects, "max_body_bytes": max_body_bytes}
    try:
        return host, fetch_live(host, timeout, counted, "https", **options), None, sent
    except OutOfScope:
        return host, None, "OutOfScope", sent  # first URL refused: nothing sent, no HTTP retry
    except requests.RequestException as e:
        https_error = type(e).__name__
        if not _retry_on_http(e):
            return host, None, https_error, sent
    try:
        record = fetch_live(host, timeout, counted, "http", **options)
    except requests.RequestException as e:
        return host, None, f"{https_error}; http: {type(e).__name__}", sent
    record["https_error"] = https_error
    return host, record, None, sent


if __name__ == "__main__":
    import sys

    record = fetch_live(sys.argv[1], scope=UNSCOPED_CLI)  # you typed the host yourself
    print(f"{record['start_url']}  ->  HTTP {record['status']}  ({record['collected_at']})")
    for step in record["chain"]:
        print(f"  {step['status']}  ->  {step['to']}")
    if record["redirect_blocked"]:
        print(f"  redirect leaves scope, not followed: {record['redirect_blocked']}")
    elif record["hit_redirect_limit"]:
        print(f"  still redirecting after {MAX_REDIRECTS} hops, stopped")
    print(f"  title: {record['title'] or '(none)'}")
