"""
Shared DNS lookups for every Monomi check (takeover, enrich, ...).

One place for how Monomi asks DNS questions, so every tool gets the same
answer for the same host. Order of trust:
  1. the system resolver (normal DNS, port 53)
  2. public DNS servers (1.1.1.1, 8.8.8.8) if the system one doesn't answer
  3. DNS-over-HTTPS (Cloudflare, then Google) if neither answers, and to
     double-check any "no such name" (NXDOMAIN) before believing it

Only asks DNS servers, never the target itself, so it stays passive.
"""

import re
import time

import dns.exception
import dns.resolver
import requests

FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

# DNS-over-HTTPS: the same DNS question sent over HTTPS (port 443), so a
# local DNS relay (like WSL's) can't intercept it or replay a stale answer.
# Two providers, so one provider's rate limit or stale cache isn't the last word.
DOH_SERVERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/resolve",
}
DOH_TYPE_CODES = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16}   # DoH JSON gives record types as numbers
RETRY_PAUSE = 2   # seconds to wait before one last try when every DoH server failed


class DNSLookupError(Exception):
    """No DNS server answered at all (different from 'no record exists')."""


class NoSuchHost(Exception):
    """DNS answered NXDOMAIN: the hostname itself doesn't exist."""


class ConflictingAnswers(DNSLookupError):
    """System DNS and DNS-over-HTTPS disagree about whether a name exists."""


class ServerFailure(DNSLookupError):
    """A DNS server answered SERVFAIL: it tried, but couldn't get an answer
    (a broken zone, or a provider refusing under load). Still unknown."""


def _resolvers():
    """System DNS first, then public DNS (WSL's relay can time out)."""
    system = dns.resolver.Resolver()
    public = dns.resolver.Resolver(configure=False)
    public.nameservers = FALLBACK_NAMESERVERS
    return (system, public)


def _ask_doh(url: str, name: str, rtype: str) -> tuple[str, list[str]]:
    """Ask one DNS-over-HTTPS server one DNS question.

    Returns ("nxdomain", []) if the name doesn't exist, otherwise
    ("ok", [records of that type]), e.g. ("ok", ["app.cloud.test"]).
    Raises ServerFailure on SERVFAIL, DNSLookupError on any other failure.
    """
    try:
        resp = requests.get(
            url,
            params={"name": name, "type": rtype},
            headers={"accept": "application/dns-json"},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise DNSLookupError(f"DNS-over-HTTPS lookup failed for {name}: {e}")

    status = data.get("Status")
    if status == 3:                      # 3 = NXDOMAIN, "no such name"
        return "nxdomain", []
    if status == 2:                      # 2 = SERVFAIL, the server couldn't get an answer
        raise ServerFailure(f"DNS-over-HTTPS returned SERVFAIL for {name}")
    if status != 0:                      # 0 = NOERROR; anything else is a failure
        raise DNSLookupError(f"DNS-over-HTTPS returned status {status} for {name}")
    wanted = DOH_TYPE_CODES[rtype]
    answers = [a["data"] for a in data.get("Answer", []) if a.get("type") == wanted]
    if rtype == "TXT":
        # TXT is text, not a name: keep its case (DKIM keys are case-sensitive)
        return "ok", [txt_text(d) for d in answers]
    return "ok", [d.rstrip(".").lower() for d in answers]


# One quoted chunk of a TXT answer, e.g. "v=spf1 -all" (\" inside is an escaped quote)
TXT_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')
# An escape inside a chunk: \" or \\ (a character) or \032 (a byte as 3 digits)
TXT_ESCAPE = re.compile(r"\\(\d{3}|.)")


def txt_text(data: str) -> str:
    """Turn one DoH TXT answer into the record's text.

    Cloudflare wraps TXT data in quotes and shows a long record as several
    quoted chunks ("v=spf1 include:a" " ~all"); Google gives the bare text.
    The chunks are joined back into one string, like dnspython does.
    """
    chunks = TXT_CHUNK.findall(data)
    if not chunks:
        return data
    return "".join(TXT_ESCAPE.sub(_unescape, c) for c in chunks)


def _unescape(m) -> str:
    """An escaped 3-digit number becomes that character; any other escaped character stays as itself."""
    code = m.group(1)
    return chr(int(code)) if code.isdigit() else code


def doh_lookup(name: str, rtype: str) -> tuple[str, list[str]]:
    """Ask DNS-over-HTTPS one question: Cloudflare, then Google, then one retry.

    Returns the first clear answer, same shape as _ask_doh(). If every server
    fails, waits RETRY_PAUSE and asks the first one once more (a busy
    server often answers a moment later). Raises ServerFailure if any server
    said SERVFAIL, otherwise DNSLookupError.
    """
    urls = list(DOH_SERVERS.values())
    failures = []
    for attempt, url in enumerate(urls + urls[:1]):
        if attempt == len(urls):         # every server failed once: pause, then retry
            time.sleep(RETRY_PAUSE)
        try:
            return _ask_doh(url, name, rtype)
        except DNSLookupError as e:
            failures.append(e)
    if any(isinstance(e, ServerFailure) for e in failures):
        raise ServerFailure(f"DNS-over-HTTPS servers returned SERVFAIL for {name}")
    raise failures[-1]


def _confirm_nxdomain(name: str, rtype: str) -> None:
    """Double-check a "no such name" answer over HTTPS before believing it.

    A local DNS cache (e.g. WSL's) can replay an old NXDOMAIN for a host
    that's live now, and one DoH provider can have cached it too (the 41xlab
    lab). So ask every DoH server: if any says the name exists, raise
    ConflictingAnswers instead of reporting it gone. Servers that can't be
    reached are skipped; if none can, keep the system answer.
    """
    for provider, url in DOH_SERVERS.items():
        try:
            result, _ = _ask_doh(url, name, rtype)
        except DNSLookupError:
            continue
        if result != "nxdomain":
            raise ConflictingAnswers(
                f"conflicting answers for {name}: system DNS says it doesn't exist, "
                f"{provider} DNS-over-HTTPS says it does (often a stale DNS cache)"
            )


def get_cname(name: str) -> str | None:
    """Where a hostname's CNAME points (e.g. an Azure or Heroku app name).

    None means DNS answered and there's no CNAME (a normal A-record host).
    Raises NoSuchHost if the name doesn't exist at all (NXDOMAIN).
    Raises DNSLookupError if no DNS server would answer.
    """
    for resolver in _resolvers():
        try:
            answers = resolver.resolve(name, "CNAME", lifetime=5)
            # str() ends the name with a dot -- drop the trailing dot
            return str(answers[0].target).rstrip(".").lower()
        except dns.resolver.NXDOMAIN:
            _confirm_nxdomain(name, "CNAME")
            raise NoSuchHost(name)
        except dns.resolver.NoAnswer:
            return None
        except dns.exception.DNSException:
            continue
    # no DNS server answered on port 53 (common in WSL): ask over HTTPS instead
    result, records = doh_lookup(name, "CNAME")
    if result == "nxdomain":
        raise NoSuchHost(name)
    return records[0] if records else None


def name_exists(name: str) -> bool:
    """Does this DNS name exist at all?

    False only when DNS says NXDOMAIN ("no such name"); that's the
    dangling signal. Raises DNSLookupError if no DNS server would answer.
    """
    for resolver in _resolvers():
        try:
            resolver.resolve(name, "A", lifetime=5)
            return True
        except dns.resolver.NoAnswer:
            return True   # the name exists, it just has no IPv4 address
        except dns.resolver.NXDOMAIN:
            _confirm_nxdomain(name, "A")   # raises ConflictingAnswers if DoH disagrees
            return False
        except dns.exception.DNSException:
            continue
    # no DNS server answered on port 53 (common in WSL): ask over HTTPS instead
    result, _ = doh_lookup(name, "A")
    return result != "nxdomain"

def _query(name: str, rtype: str) -> tuple[str, list[str]]:
    """Ask DNS one question, with the same fallbacks as everything else here.

    Returns ("ok", [records]) or ("nxdomain", []), the same shape as
    doh_lookup(). An empty list means the name exists but has no record of
    that type. Raises ConflictingAnswers / DNSLookupError like get_cname().
    """
    for resolver in _resolvers():
        try:
            answers = resolver.resolve(name, rtype, lifetime=5)
            return "ok", sorted({r.to_text().rstrip(".").lower() for r in answers})
        except dns.resolver.NoAnswer:
            return "ok", []
        except dns.resolver.NXDOMAIN:
            _confirm_nxdomain(name, rtype)   # raises ConflictingAnswers if DoH disagrees
            return "nxdomain", []
        except dns.exception.DNSException:
            continue
    # no DNS server answered on port 53 (common in WSL): ask over HTTPS instead
    return doh_lookup(name, rtype)


def _why_nxdomain(host: str) -> str:
    """The A lookup said NXDOMAIN: is the host missing, or only its CNAME's target?

    An A lookup follows CNAMEs, so a host whose CNAME points at a deleted
    name also comes back NXDOMAIN, even though the host's own record exists.
    """
    try:
        target = get_cname(host)
    except NoSuchHost:
        return "no_such_host"
    return "dangling_cname" if target else "no_such_host"


def host_status(host: str) -> tuple[str, list[str]]:
    """What DNS says about one hostname, plus any IPv4 addresses found.

    Returns (status, ips). Status is one of:
      "live"            has IPv4 address(es), listed in ips
      "ipv6_only"       exists, IPv6 address only
      "no_address"      exists, no A or AAAA record
      "dangling_cname"  exists, but its CNAME points to a name that doesn't
      "no_such_host"    the name doesn't exist (NXDOMAIN, double-checked
                        over DNS-over-HTTPS when reachable)
      "conflicting"     system DNS and DNS-over-HTTPS disagree: unknown
      "servfail"        DNS servers answered SERVFAIL (broken zone or a
                        provider under load), even after a retry: unknown
      "lookup_failed"   no DNS server answered: unknown
    Never raises: every outcome is a status, so callers can't crash on one host.
    """
    try:
        result, ips = _query(host, "A")
        if result == "nxdomain":
            return _why_nxdomain(host), []
        if ips:
            return "live", ips
        _, ipv6 = _query(host, "AAAA")
        return ("ipv6_only" if ipv6 else "no_address"), []
    except ConflictingAnswers:
        return "conflicting", []
    except ServerFailure:
        return "servfail", []
    except DNSLookupError:
        return "lookup_failed", []
