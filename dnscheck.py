"""
Shared DNS lookups for every Monomi check (takeover, enrich, ...).

One place for how Monomi asks DNS questions, so every tool gets the same
answer for the same host. Order of trust:
  1. the system resolver (normal DNS, port 53)
  2. public DNS servers (1.1.1.1, 8.8.8.8) if the system one doesn't answer
  3. DNS-over-HTTPS to Cloudflare if neither answers, and to double-check
     any "no such name" (NXDOMAIN) before believing it

Only asks DNS servers, never the target itself, so it stays passive.
"""

import dns.exception
import dns.resolver
import requests

FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

# DNS-over-HTTPS: the same DNS question sent over HTTPS (port 443), so a
# local DNS relay (like WSL's) can't intercept it or replay a stale answer.
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_TYPE_CODES = {"A": 1, "CNAME": 5}   # DoH JSON gives record types as numbers


class DNSLookupError(Exception):
    """No DNS server answered at all (different from 'no record exists')."""


class NoSuchHost(Exception):
    """DNS answered NXDOMAIN: the hostname itself doesn't exist."""


class ConflictingAnswers(DNSLookupError):
    """System DNS and DNS-over-HTTPS disagree about whether a name exists."""


def _resolvers():
    """System DNS first, then public DNS (WSL's relay can time out)."""
    system = dns.resolver.Resolver()
    public = dns.resolver.Resolver(configure=False)
    public.nameservers = FALLBACK_NAMESERVERS
    return (system, public)


def doh_lookup(name: str, rtype: str) -> tuple[str, list[str]]:
    """Ask Cloudflare's DNS-over-HTTPS service one DNS question.

    Returns ("nxdomain", []) if the name doesn't exist, otherwise
    ("ok", [records of that type]), e.g. ("ok", ["app.cloud.test"]).
    Raises DNSLookupError if it can't get a clear answer.
    """
    try:
        resp = requests.get(
            DOH_URL,
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
    if status != 0:                      # 0 = NOERROR; anything else is a failure
        raise DNSLookupError(f"DNS-over-HTTPS returned status {status} for {name}")
    wanted = DOH_TYPE_CODES[rtype]
    records = [a["data"].rstrip(".").lower()
               for a in data.get("Answer", []) if a.get("type") == wanted]
    return "ok", records


def _confirm_nxdomain(name: str, rtype: str) -> None:
    """Double-check a "no such name" answer over HTTPS before believing it.

    A local DNS cache (e.g. WSL's) can replay an old NXDOMAIN for a host
    that's live now. If DoH says the name exists, raise ConflictingAnswers
    instead of reporting it gone. If DoH can't be reached, keep the system
    answer (same as before this check existed).
    """
    try:
        result, _ = doh_lookup(name, rtype)
    except DNSLookupError:
        return
    if result != "nxdomain":
        raise ConflictingAnswers(
            f"conflicting answers for {name}: system DNS says it doesn't exist, "
            f"DNS-over-HTTPS says it does (often a stale local DNS cache)"
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
