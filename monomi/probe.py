"""
Live-page probe: where does a host's homepage really land, and what is it?

fingerprint.py reads one response's HEADERS (server, tech, security
headers) and stops there on purpose: one request, headers only, redirects
NOT followed. This module goes one step further, to build the per-host
"live page" record the app-mapper needs:

  - it FOLLOWS redirects, so we learn where "/" really ends up (many hosts
    send you to www, to HTTPS, to a login page, or to another site), and
  - it reads just enough of the final page to pull out its <title>.

A redirect is where the TARGET chooses the next URL, so every one goes
through _refuse_hop() before anything is sent: a valid http(s) URL on port
80 or 443, one clear host (both URL parsers agree on it), in scope, an
approved host (over MCP), and not a private or local address (an IP
literal, or a name that resolves to one). Anything else is recorded in
redirect_blocked with its reason and never requested. Then every hop goes
through the same steps as fingerprint: scope check, wait for the --rate
slot, log, send (with the research headers).

Hard limits, enforced in code: at most MAX_REQUESTS requests per host and
a time limit per host (HOST_TIME_LIMIT). The title is written by the
target: it's untrusted evidence, never instructions.

Like --fingerprint, this is an opt-in ACTIVE check.
"""

import codecs
import html
import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests

from monomi import rate as ratemod
from monomi.common import now_utc
from monomi.fingerprint import _retry_on_http
from monomi.research import request_headers
from monomi.scope import UNSCOPED_CLI, OutOfScope, check_url, named_host, normalize_host, request_host

# Ceilings that keep the probe small and polite.
MAX_HOSTS = 100          # hosts per run, like fingerprint
MAX_REDIRECTS = 5        # hops followed before we stop and say so
MAX_BODY_BYTES = 65536   # bytes of the final page searched for <title>
MAX_TITLE = 300          # characters of title kept
CHUNK = 4096             # body read size: at most CHUNK - 1 bytes are read past MAX_BODY_BYTES
HOST_TIME_LIMIT = 60     # seconds per host, every hop and the body read included
# The most requests one host can take: a full HTTPS chain (the homepage +
# MAX_REDIRECTS hops) that fails, then the same over plain HTTP. probe_host
# refuses to send more, and the CLI and the MCP approval plan both quote this
# number, so all three always agree.
MAX_REQUESTS = 2 * (MAX_REDIRECTS + 1)

# Why a redirect wasn't followed (redirect_blocked_reason) -> how the CLI says it.
BLOCK_REASONS = {
    "invalid_url": "isn't a valid URL",
    "unsupported_url": "isn't http or https",
    "other_port": "uses a port other than 80 or 443",
    "ambiguous_url": "names its host ambiguously (URL parsers disagree: a way to slip past a scope)",
    "out_of_scope": "leaves scope",
    "not_approved": "leaves the approved hosts",
    "private_address": "points at a private or local address",
    "no_dns": "names a host that doesn't resolve",
}

# <title ...>...</title>, any case, across newlines. Non-greedy: stops at
# the first </title>.
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([\w.:-]+)", re.IGNORECASE)


class RequestCapReached(requests.RequestException):
    """A host hit MAX_REQUESTS: the next request was not sent."""


class HostTimeLimit(requests.Timeout):
    """A host used up its time limit: the next request was not sent.
    A Timeout, so it's never retried over plain HTTP."""


def _resolve(host: str) -> list[str]:
    """Every address a name resolves to (the scope id of an IPv6 link-local
    address dropped). Raises OSError if it doesn't resolve."""
    return sorted({info[4][0].split("%")[0] for info in socket.getaddrinfo(host, None)})


# Swappable, so tests never touch real DNS (see tests/conftest.py).
RESOLVE = _resolve
CLOCK = time.monotonic


def _private_address(host: str) -> bool | None:
    """True if host is, or resolves to, any address that isn't public (a
    router, 127.0.0.1, 169.254.169.254, an internal 10.x server...); None if
    it doesn't resolve; False if every address is public."""
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass  # a name, not an IP literal
    try:
        addresses = RESOLVE(host)
    except OSError:
        return None
    if not addresses:
        return None
    return any(not ipaddress.ip_address(a).is_global for a in addresses)


def _refuse_hop(target: str, scope, allowed_hosts) -> str | None:
    """Why a redirect to `target` must not be followed (a BLOCK_REASONS key),
    or None to follow it. The order puts the cheap, certain checks first and
    the DNS lookup last."""
    try:
        parsed = urlparse(target)
        port = parsed.port  # a bad port raises ValueError
    except ValueError:
        return "invalid_url"
    if parsed.scheme not in ("http", "https"):
        return "unsupported_url"
    if port not in (None, 80, 443):
        return "other_port"
    real = request_host(target)
    if real is None:
        return "invalid_url"
    if named_host(target) != real:
        return "ambiguous_url"
    try:
        check_url(scope, target)
    except OutOfScope:
        return "out_of_scope"
    if allowed_hosts is not None and real not in allowed_hosts:
        return "not_approved"
    private = _private_address(real)
    if private is None:
        return "no_dns"
    if private:
        return "private_address"
    return None


def _body_kind(text: str) -> str:
    """What the body actually looks like, judged from its first character,
    whatever the Content-Type header claims: "json", "html", "empty" or
    "other". Headers can lie: an API that sends JSON labeled text/html shows
    up as content_type text/html with body_kind "json"."""
    start = text.lstrip("﻿ \t\r\n")
    if not start:
        return "empty"
    if start[0] in "{[":
        return "json"
    if start[0] == "<":
        return "html"
    return "other"


def _charset(headers: dict) -> str:
    """The charset the server states in Content-Type, if Python knows it;
    otherwise UTF-8. Not requests' guess: with no charset it assumes
    ISO-8859-1, which turns a UTF-8 "Café" into "CafÃ©"."""
    match = CHARSET_RE.search(headers.get("content-type", ""))
    if match:
        try:
            return codecs.lookup(match.group(1)).name
        except LookupError:
            pass  # an unknown charset falls back, it never crashes the scan
    return "utf-8"


def _read_page(resp, headers: dict, max_bytes: int, deadline=None) -> tuple[str | None, str | None]:
    """(title, body_kind) of the final page, from at most max_bytes of it.

    headers: the response headers, already lowercased. Only a body labeled
    HTML is read: a PDF or an image has no title and could be big, so for
    those both values are None (not read). The body is streamed in CHUNK
    pieces and reading stops at max_bytes (at most CHUNK - 1 bytes more are
    read) or at the host's deadline, whichever comes first.
    """
    if "html" not in headers.get("content-type", "").lower():
        return None, None
    chunks, total = [], 0
    for chunk in resp.iter_content(CHUNK):
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes or (deadline is not None and CLOCK() >= deadline):
            break
    text = b"".join(chunks)[:max_bytes].decode(_charset(headers), errors="replace")
    return _title(text), _body_kind(text)


def _title(text: str) -> str | None:
    """The <title> in a page's text, cleaned, or None if there isn't one."""
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


def _record(host, start_url, final_url, status, chain, title, headers, *, body_kind=None,
            redirect_blocked=None, blocked_reason=None, hit_redirect_limit=False) -> dict:
    """One host's probe result. headers: already lowercased."""
    return {
        "host": host,
        "start_url": start_url,
        "final_url": final_url,
        "status": status,                          # status of the FINAL response
        "chain": chain,                            # one {"status", "from", "to"} per redirect FOLLOWED
        "title": title,
        "content_type": headers.get("content-type"),  # what the server says the body is
        "body_kind": body_kind,                    # what it looked like when read; None = not read
        "headers": headers,
        "redirect_blocked": redirect_blocked,      # where a redirect wanted to go, never requested
        "redirect_blocked_reason": blocked_reason,  # a BLOCK_REASONS key
        "hit_redirect_limit": hit_redirect_limit,  # still redirecting after max_redirects hops
        "collected_at": now_utc(),
    }


class _Budget:
    """How many more requests one host may send (shared by its HTTPS and
    HTTP tries): the cap is enforced here, not just described."""

    def __init__(self, n: int):
        self.left = n

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def fetch_live(host: str, timeout: int = 10, on_request=None, scheme: str = "https",
               *, scope, limiter=ratemod.UNLIMITED, research=None, allowed_hosts=None,
               max_redirects: int = MAX_REDIRECTS, max_body_bytes: int = MAX_BODY_BYTES,
               budget=None, deadline=None) -> dict:
    """Follow scheme://host/ through its redirects to the final page and
    return a live-page record.

    scope (required, no default): a scope.Scope, or scope.UNSCOPED_CLI for a
    CLI run without --scope. If the FIRST URL is refused this raises
    scope.OutOfScope and nothing is sent. Every redirect goes through
    _refuse_hop(): one that's refused is never requested, it's kept in
    "redirect_blocked" with its reason, and the redirect itself becomes the
    final response.
    allowed_hosts (MCP): the hosts a person approved. A redirect to any
    other host is never requested, even if the scope allows it, so an
    approval only ever touches the hosts that were shown before the yes.
    None (the CLI) means any host the scope allows.
    on_request(host, url, scope_rule), if given, is called right before each
    request (it writes the audit log), once per hop.
    limiter and research: as in fingerprint.fetch_headers. Every hop takes
    its own --rate slot and carries the research headers. Order per hop:
    scope check, cap and time check, wait for the slot, log, send, so a
    refused URL never uses a slot or a log line.
    budget (a _Budget) and deadline (a CLOCK() time): probe_host's per-host
    limits; going past one raises RequestCapReached or HostTimeLimit before
    the request is sent.
    Raises requests.RequestException if a hop can't be reached.
    """
    start_url = f"{scheme}://{host}/"
    url = start_url
    chain = []
    if allowed_hosts is not None:
        allowed_hosts = {normalize_host(h) for h in allowed_hosts} - {None}
    for hop in range(max_redirects + 1):
        rule = check_url(scope, url)  # raises OutOfScope: no slot, no log line, no request
        if budget is not None and not budget.take():
            raise RequestCapReached(f"{host}: request cap reached, {url} not sent")
        if deadline is not None and CLOCK() >= deadline:
            raise HostTimeLimit(f"{host}: time limit reached, {url} not sent")
        limiter.wait()
        if on_request:
            on_request(host, url, rule)
        resp = requests.get(
            url,
            headers=request_headers(research),
            timeout=timeout,
            allow_redirects=False,  # we follow by hand, so every hop is checked
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
                try:
                    target = urljoin(url, location)  # also turns "/login" into a full URL
                except ValueError:  # e.g. "http://[::1/": not a URL at all
                    target, refused = location[:500], "invalid_url"
                else:
                    refused = _refuse_hop(target, scope, allowed_hosts)
                if refused:
                    return _record(host, start_url, url, status, chain, None, headers,
                                   redirect_blocked=target, blocked_reason=refused)
                chain.append({"status": status, "from": url, "to": target})
                url = target
                continue
            # The final response: a page, an error, or a redirect we ran out
            # of hops to follow. Only here is the body read, for the title.
            title, body_kind = _read_page(resp, headers, max_body_bytes, deadline)
            return _record(host, start_url, url, status, chain, title, headers,
                           body_kind=body_kind, hit_redirect_limit=redirecting)
        finally:
            resp.close()  # free the connection, whether or not the body was read


def probe_host(host: str, timeout: int = 10, on_request=None, *, scope,
               limiter=ratemod.UNLIMITED, research=None, allowed_hosts=None,
               max_redirects: int = MAX_REDIRECTS, max_body_bytes: int = MAX_BODY_BYTES,
               max_requests: int = MAX_REQUESTS, time_limit: float | None = HOST_TIME_LIMIT):
    """fetch_live() that never crashes: returns (host, record, error, requests sent).

    Same shape and HTTPS-then-HTTP rule as fingerprint._safe_fetch, so a
    scan can use either. If HTTPS fails in a way plain HTTP might not, tries
    http://host/ once; that record keeps the HTTPS failure in "https_error",
    so a site that only works without HTTPS is never shown as if HTTPS were
    fine.

    Per host, both tries together: at most max_requests requests (the
    approval's cap, enforced) and time_limit seconds (checked before every
    request and while reading the body).

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
               "allowed_hosts": allowed_hosts,
               "max_redirects": max_redirects, "max_body_bytes": max_body_bytes,
               "budget": _Budget(max_requests),
               "deadline": CLOCK() + time_limit if time_limit else None}
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


def probe_all(enrichment: dict, workers: int = 8, on_request=None,
              max_hosts: int = MAX_HOSTS, timeout: int = 10, *, scope,
              limiter=ratemod.UNLIMITED, research=None, allowed_hosts=None,
              time_limit: float | None = HOST_TIME_LIMIT) -> dict:
    """Probe every host from --enrich that has a public IP (like fingerprint_all).

    scope is required: every hop of every host is checked against it again,
    right before its request is sent. limiter: one for the whole run, so
    --rate is a total across threads and hops. allowed_hosts: see
    fetch_live (MCP passes the approved hosts). time_limit: seconds per
    host. on_request, max_hosts and timeout: as in fingerprint_all.
    Returns {"hosts": {host: record}, "checked", "requests", "errors",
    "skipped"}. "requests" counts every request sent (hops and HTTP retries
    included), so it always matches the audit log.
    """
    hosts = sorted(
        host for host, e in enrichment["hosts"].items()
        if any(ipaddress.ip_address(ip).is_global for ip in e["ips"])
    )
    skipped = max(0, len(hosts) - max_hosts)
    hosts = hosts[:max_hosts]

    def one(host):
        return probe_host(host, timeout=timeout, on_request=on_request, scope=scope,
                          limiter=limiter, research=research, allowed_hosts=allowed_hosts,
                          time_limit=time_limit)

    found, errors, sent = {}, {}, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, record, err, n in pool.map(one, hosts):
            sent += n
            if err:
                errors[host] = err
            else:
                found[host] = record
    return {"hosts": found, "checked": len(hosts), "requests": sent,
            "errors": errors, "skipped": skipped}


if __name__ == "__main__":
    import sys

    from monomi.ui import safe  # every URL and header below comes from the target

    record = fetch_live(sys.argv[1], scope=UNSCOPED_CLI)  # you typed the host yourself
    print(f"{record['start_url']}  ->  HTTP {record['status']}  ({record['collected_at']})")
    for step in record["chain"]:
        print(f"  {step['status']}  ->  {safe(step['to'])}")
    if record["redirect_blocked"]:
        print(f"  redirect {BLOCK_REASONS[record['redirect_blocked_reason']]}, not followed: "
              f"{safe(record['redirect_blocked'])}")
    elif record["hit_redirect_limit"]:
        print(f"  still redirecting after {MAX_REDIRECTS} hops, stopped")
    print(f"  content type: {safe(record['content_type'] or '(none given)')}"
          + (f"  (body looks like {record['body_kind']})" if record["body_kind"] else ""))
    print(f"  title: {safe(record['title'] or '(none)')}")
