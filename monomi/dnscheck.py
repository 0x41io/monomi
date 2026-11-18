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
    (a broken zone, or a provider refusing under load). Still unknown.

    Carries what the DoH reply said about why, so a caller can tell a lame
    delegation (a dangling NS delegation, a real takeover class) from a
    transient SERVFAIL under load:
      detail  the extended-error text the resolver gave (may be empty)
      ede     EDE codes seen in it (e.g. 22, 23), as a list
      ns_ips  any nameserver IPs named in it (the refusing servers)
      lame    True only when the text says the zone's own nameservers
              refuse / aren't reachable (a delegation failure), never for a
              bare SERVFAIL with no such wording."""
    detail = ""
    ede = ()
    ns_ips = ()
    lame = False


def _resolvers():
    """System DNS first, then public DNS (WSL's relay can time out)."""
    system = dns.resolver.Resolver()
    public = dns.resolver.Resolver(configure=False)
    public.nameservers = FALLBACK_NAMESERVERS
    return (system, public)


# A SERVFAIL means "couldn't answer". It's a lame (dangling) delegation only
# when the resolver says the zone's own nameservers refuse or can't be reached;
# a plain SERVFAIL under load has none of this wording and stays "unknown".
_DELEGATION_PHRASES = re.compile(
    r"lame delegation"
    r"|no reachable authority at delegation"
    r"|name servers? refused"
    r"|returned refused"
    r"|refused for",
    re.IGNORECASE,
)
_EDE_RE = re.compile(r"EDE\((\d+)\)")        # Cloudflare labels extended errors "EDE(22): ..."
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# EDE 22 = "No Reachable Authority", 23 = "Network Error" (REFUSED at delegation)
_DELEGATION_EDE = {22, 23}


def _doh_extended(data: dict) -> tuple[str, list[int], list[str]]:
    """The extended-error text, EDE codes and nameserver IPs in a SERVFAIL reply.

    "Comment" is a string on Google ("Name servers refused query (lame
    delegation?) [205.251.198.35, ...]") and a list of EDE lines on Cloudflare
    (["EDE(22): No Reachable Authority at delegation ...", ...]); both are
    handled. The IPs are the nameservers that refused, for grading later.
    """
    comment = data.get("Comment", "")
    text = " ".join(str(c) for c in comment) if isinstance(comment, list) else str(comment)
    edes = [int(m) for m in _EDE_RE.findall(text)]
    ips = _IPV4_RE.findall(text)
    return text, edes, ips


def _servfail(name: str, data: dict) -> "ServerFailure":
    """Build a ServerFailure for a SERVFAIL reply, tagged lame if it's a
    delegation failure (by the wording or a delegation EDE code)."""
    text, edes, ips = _doh_extended(data)
    err = ServerFailure(f"DNS-over-HTTPS returned SERVFAIL for {name}")
    err.detail = text
    err.ede = edes
    err.ns_ips = ips
    err.lame = bool(_DELEGATION_PHRASES.search(text)) or any(e in _DELEGATION_EDE for e in edes)
    return err


def _merge_servfails(name: str, failures: list["ServerFailure"]) -> "ServerFailure":
    """One ServerFailure for the whole lookup, keeping the richest detail any
    server gave: lame if any server called it lame, with its text and NS IPs."""
    err = ServerFailure(f"DNS-over-HTTPS servers returned SERVFAIL for {name}")
    lame = next((f for f in failures if f.lame), None)
    src = lame or next((f for f in failures if f.detail), None)
    err.detail = src.detail if src is not None else ""
    err.ede = sorted({c for f in failures for c in f.ede})
    err.ns_ips = list(src.ns_ips) if src is not None else []
    err.lame = lame is not None
    return err


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
        raise _servfail(name, data)
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
    servfails = [e for e in failures if isinstance(e, ServerFailure)]
    if servfails:
        raise _merge_servfails(name, servfails)
    raise failures[-1]


def _confirm_nxdomain(name: str, rtype: str) -> list[str]:
    """Double-check a "no such name" answer over HTTPS before believing it.

    A local DNS cache (e.g. WSL's) can replay an old NXDOMAIN for a host
    that's live now, and one DoH provider can have cached it too (the 41xlab
    lab). So ask every DoH server: if any says the name exists, raise
    ConflictingAnswers instead of reporting it gone. Servers that can't be
    reached are skipped; if none can, keep the system answer.

    Returns the DoH providers that confirmed the NXDOMAIN, e.g.
    ["Cloudflare", "Google"]. An empty list means none could be reached, so
    the answer rests on system DNS alone (the validation gate's check 4).
    """
    confirmed = []
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
        confirmed.append(provider)
    return confirmed


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


def check_exists(name: str) -> tuple[bool, list[str]]:
    """Does this DNS name exist at all, and who confirmed it doesn't?

    Returns (exists, confirmed_by). exists is False only when DNS says
    NXDOMAIN ("no such name"); that's the dangling signal. confirmed_by
    lists the DNS-over-HTTPS providers that agreed the name doesn't exist
    (empty when it exists, or when no DoH server could be reached and the
    answer rests on system DNS alone).
    Raises DNSLookupError if no DNS server would answer.
    """
    for resolver in _resolvers():
        try:
            resolver.resolve(name, "A", lifetime=5)
            return True, []
        except dns.resolver.NoAnswer:
            return True, []   # the name exists, it just has no IPv4 address
        except dns.resolver.NXDOMAIN:
            # raises ConflictingAnswers if DoH disagrees
            return False, _confirm_nxdomain(name, "A")
        except dns.exception.DNSException:
            continue
    # no DNS server answered on port 53 (common in WSL): ask over HTTPS instead
    result, _ = doh_lookup(name, "A")
    if result != "nxdomain":
        return True, []
    # One DoH server said NXDOMAIN: ask every one, like the system DNS case
    return False, _confirm_nxdomain(name, "A")


def name_exists(name: str) -> bool:
    """Does this DNS name exist at all? (check_exists without who confirmed it.)"""
    return check_exists(name)[0]


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


def lame_delegation(name: str) -> dict | None:
    """If this name's SERVFAIL is a lame (dangling) delegation, describe it; else None.

    Returns {"detail", "ede", "ns_ips"} when the DoH servers SERVFAIL *and*
    say the zone's own nameservers refuse / aren't reachable. Returns None for
    a name that resolves, doesn't exist, SERVFAILs only transiently (under
    load, no delegation wording), or can't be looked up at all. Passive: only
    asks DNS-over-HTTPS, never the target.
    """
    try:
        doh_lookup(name, "A")
    except ServerFailure as e:
        if e.lame:
            return {"detail": e.detail, "ede": list(e.ede), "ns_ips": list(e.ns_ips)}
        return None
    except DNSLookupError:
        return None
    return None   # resolved or NXDOMAIN: not a broken delegation


def find_zone_cut(host: str) -> tuple[str, dict] | None:
    """The delegation point above a host whose lookup is a lame delegation.

    Walks up the labels from the host: every ancestor that is itself a lame
    delegation is remembered, and the walk stops at the first ancestor that
    isn't (the live parent zone). Returns (cut, info) for the shallowest lame
    ancestor -- the zone apex that is actually delegated away, e.g.
    "local-dev.example.com" for "alice.local-dev.example.com" -- or None if no
    ancestor is a lame delegation. Stops before a bare registrable-looking
    name (keeps at least two labels), and never queries a TLD.
    """
    labels = host.split(".")
    cut = None
    # host, then parent, grandparent, ...; keep the last two labels as a floor
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        info = lame_delegation(name)
        if info:
            cut = (name, info)      # shallower lame ancestors overwrite deeper ones
        elif cut:
            break                   # crossed up into a resolving parent zone
    return cut
