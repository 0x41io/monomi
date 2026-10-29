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


def _resolvers():
    """System DNS first, then public DNS (WSL's relay can time out)."""
    system = dns.resolver.Resolver()
    public = dns.resolver.Resolver(configure=False)
    public.nameservers = FALLBACK_NAMESERVERS
    return (system, public)


def get_cname(name: str) -> str | None:
    """Where a hostname's CNAME points, e.g. 'myapp.herokuapp.com'.

    None means DNS answered and there's no CNAME (a normal A-record host).
    Raises DNSLookupError if no DNS server would answer.
    """
    for resolver in _resolvers():
        try:
            answers = resolver.resolve(name, "CNAME", lifetime=5)
            # str() gives 'myapp.herokuapp.com.' -- drop the trailing dot
            return str(answers[0].target).rstrip(".").lower()
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
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


def match_service(target: str) -> str | None:
    """Which takeover-prone service a CNAME target belongs to, if any.

    'myapp.azurewebsites.net' -> 'Azure App Service'
    'www.example.com'         -> None
    """
    for ending, service in TAKEOVER_SERVICES:
        if target.endswith(ending):
            return service
    return None

def inspect_host(host: str) -> dict:
    """Check one hostname and report what was found, clean or not.

    Returns {"status": ..., "cname": ..., "lead": ...}:
      "no_cname"  -> plain A-record host, nothing can dangle
      "cname_ok"  -> CNAME points at a name that exists: fine
      "lead"      -> CNAME target is NXDOMAIN (dangling)
    "lead" holds the full lead dict when status is "lead", else None.
    """
    target = get_cname(host)
    if target is None:
        return {"status": "no_cname", "cname": None, "lead": None}
    if name_exists(target):
        return {"status": "cname_ok", "cname": target, "lead": None}

    service = match_service(target)
    lead = {
        "host": host,
        "cname": target,
        "service": service,              # None = not a known service
        "claimable": service is not None,
        "collected_at": now_utc(),
    }
    return {"status": "lead", "cname": target, "lead": lead}


def check_host(host: str) -> dict | None:
    """Check one hostname. Returns a lead if its CNAME dangles, else None."""
    return inspect_host(host)["lead"]

def _safe_check(host: str):
    """check_host() that never crashes: returns (host, lead, error)."""
    try:
        return host, inspect_host(host), None
    except DNSLookupError as e:
        return host, None, str(e)


def check_hosts(hosts: list[str], workers: int = 16) -> dict:
    """Run the takeover check on every hostname.

    Returns {"leads": [...], "results": {host: {"status", "cname"}},
             "checked": count, "errors": {host: reason}}.
    """
    leads, errors, results = [], {}, {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, info, err in pool.map(_safe_check, hosts):
            if err:
                errors[host] = err
                results[host] = {"status": "error", "cname": None}
            else:
                results[host] = {"status": info["status"], "cname": info["cname"]}
                if info["lead"]:
                    leads.append(info["lead"])
    return {"leads": leads, "results": results, "checked": len(hosts), "errors": errors}
if __name__ == "__main__":
    import sys

    report = check_hosts(sys.argv[1:])
    print(f"checked {report['checked']} host(s)")
    for lead in report["leads"]:
        service = lead["service"] or "unknown service"
        print(f"  LEAD   {lead['host']}  ->  {lead['cname']}  ({service})")
    for host, err in report["errors"].items():
        print(f"  ERROR  {host}: {err}")
