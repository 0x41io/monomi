"""
Dangling DNS / subdomain takeover check.

A subdomain is "dangling" when its CNAME still points at a third-party
service (GitHub Pages, Heroku, an Azure app, ...) but the thing it points
to has been deleted. On many services anyone can sign up and claim that
deleted name, and then they control what shows up on your subdomain.

This check only does DNS lookups (asked of DNS servers, not the target),
so it stays passive. A hit is a LEAD, not proof: confirming a takeover
means actually claiming the name, which Monomi never does.
"""

from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from common import now_utc

FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

class DNSLookupError(Exception):
    """No DNS server answered at all (different from 'no record exists')."""


class NoSuchHost(Exception):
    """DNS answered NXDOMAIN: the hostname itself doesn't exist."""


def _resolvers():
    """System DNS first, then public DNS (WSL's relay can time out)."""
    system = dns.resolver.Resolver()
    public = dns.resolver.Resolver(configure=False)
    public.nameservers = FALLBACK_NAMESERVERS
    return (system, public)


def get_cname(name: str) -> str | None:
    """Where a hostname's CNAME points, e.g. 'myapp.herokuapp.com'.

    None means DNS answered and there's no CNAME (a normal A-record host).
    Raises NoSuchHost if the name doesn't exist at all (NXDOMAIN).
    Raises DNSLookupError if no DNS server would answer.
    """
    for resolver in _resolvers():
        try:
            answers = resolver.resolve(name, "CNAME", lifetime=5)
            # str() gives 'myapp.herokuapp.com.' -- drop the trailing dot
        except dns.resolver.NXDOMAIN:
            raise NoSuchHost(name)
        except dns.resolver.NoAnswer:
            return None
            return None
        except dns.exception.DNSException:
            continue
    raise DNSLookupError(f"no DNS server answered a CNAME lookup for {name}")


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
            return False
        except dns.exception.DNSException:
            continue
    raise DNSLookupError(f"no DNS server answered a lookup for {name}")


# Services where a deleted resource's name goes NXDOMAIN AND can usually
# be re-claimed by anyone who signs up. Each entry: (CNAME ending, name).
# Source: the community list at github.com/EdOverflow/can-i-take-over-xyz
TAKEOVER_SERVICES = [
    (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.net", "Azure Cloud Services"),
    (".cloudapp.azure.com", "Azure Virtual Machine"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".azureedge.net", "Azure CDN"),
    (".azure-api.net", "Azure API Management"),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk"),
]


# Services whose deleted names can NOT be claimed again: AWS adds a random
# ID to every load balancer and CloudFront name, so nobody can register the
# same name. A dangling CNAME to one of these is a stale DNS record (old
# housekeeping), not a takeover risk. Each entry: (CNAME ending, name).
NOT_CLAIMABLE = [
    (".elb.amazonaws.com", "AWS Elastic Load Balancing"),
    (".cloudfront.net", "AWS CloudFront"),
]


def match_not_claimable(target: str) -> str | None:
    """Which never-claimable service a CNAME target belongs to, if any.

    'internal-lb-1234.us-east-1.elb.amazonaws.com' -> 'AWS Elastic Load Balancing'
    """
    for ending, service in NOT_CLAIMABLE:
        if target.endswith(ending):
            return service
    return None


def match_service(target: str) -> str | None:
    """Which takeover-prone service a CNAME target belongs to, if any.

    'myapp.azurewebsites.net' -> 'Azure App Service'
    'www.example.com'         -> None
    """
    for ending, service in TAKEOVER_SERVICES:
        if target.endswith(ending):
            return service
    return None

def in_domain(name: str, domain: str) -> bool:
    """Is this name the domain itself or under it?

    in_domain('designdelivered.wolt.com', 'wolt.com') -> True
    in_domain('evilwolt.com', 'wolt.com')             -> False
    """
    return name == domain or name.endswith("." + domain)

def inspect_host(host: str, domain: str | None = None) -> dict:
    """Check one hostname and report what was found, clean or not.

    domain: the domain being scanned. A dangling CNAME that points back
    inside it is "stale", not a lead: only its owner can create that name.

    Returns {"status": ..., "cname": ..., "lead": ..., "stale": ...}:
      "no_such_host" -> the hostname itself doesn't exist (NXDOMAIN)
      "no_cname"  -> DNS answered with no CNAME record, so nothing can dangle.
                     Doesn't prove the host is live: some DNS providers
                     (e.g. Cloudflare) answer this way for missing names too
      "cname_ok"  -> CNAME points at a name that exists: fine
      "stale"     -> CNAME target is NXDOMAIN, but on a service whose names
                     can't be claimed again: old record, not a takeover risk
      "lead"      -> CNAME target is NXDOMAIN (dangling)
    "lead" / "stale" hold the full record for that status, else None.
    """
    try:
        target = get_cname(host)
    except NoSuchHost:
        return {"status": "no_such_host", "cname": None, "lead": None, "stale": None}
    if target is None:
        return {"status": "no_cname", "cname": None, "lead": None, "stale": None}
    if name_exists(target):
        return {"status": "cname_ok", "cname": target, "lead": None, "stale": None}

    if domain and in_domain(target, domain):
        stale = {"host": host, "cname": target, "service": "same domain",
                 "reason": f"only the owner of {domain} can create names under it",
                 "collected_at": now_utc()}
        return {"status": "stale", "cname": target, "lead": None, "stale": stale}

    unclaimable = match_not_claimable(target)
    if unclaimable:
        stale = {"host": host, "cname": target, "service": unclaimable,
                 "reason": "names on this service include a random ID and can't be claimed again",
                 "collected_at": now_utc()}
        return {"status": "stale", "cname": target, "lead": None, "stale": stale}
    service = match_service(target)
    lead = {
        "host": host,
        "cname": target,
        "service": service,              # None = not a known service
        "claimable": service is not None,
        "collected_at": now_utc(),
    }
    return {"status": "lead", "cname": target, "lead": lead, "stale": None}

def check_host(host: str) -> dict | None:
    """Check one hostname. Returns a lead if its CNAME dangles, else None."""
    return inspect_host(host)["lead"]

def _safe_check(host: str, domain: str | None = None):
    """check_host() that never crashes: returns (host, lead, error)."""
    try:
        return host, inspect_host(host, domain), None
    except DNSLookupError as e:
        return host, None, str(e)

def check_hosts(hosts: list[str], workers: int = 16, domain: str | None = None) -> dict:
    """Run the takeover check on every hostname.

    domain: the domain being scanned (e.g. 'wolt.com'), if known.

    Returns {"leads": [...], "stale": [...], "results": {host: {"status", "cname"}},
             "checked": count, "errors": {host: reason}}.
    """
    leads, stale, errors, results = [], [], {}, {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, info, err in pool.map(lambda h: _safe_check(h, domain), hosts):
            if err:
                errors[host] = err
                results[host] = {"status": "error", "cname": None}
            else:
                results[host] = {"status": info["status"], "cname": info["cname"]}
                if info["lead"]:
                    leads.append(info["lead"])
                if info["stale"]:
                    stale.append(info["stale"])
    return {"leads": leads, "stale": stale, "results": results, "checked": len(hosts), "errors": errors}


if __name__ == "__main__":
    import sys

    report = check_hosts(sys.argv[1:])
    print(f"checked {report['checked']} host(s)")
    for lead in report["leads"]:
        service = lead["service"] or "unknown service"
        print(f"  LEAD   {lead['host']}  ->  {lead['cname']}  ({service})")
    for host, err in report["errors"].items():
        print(f"  ERROR  {host}: {err}")
