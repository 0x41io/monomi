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
import re


from common import now_utc
from dnscheck import ConflictingAnswers, DNSLookupError, NoSuchHost, ServerFailure, check_exists, get_cname

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
    (".elb.amazonaws.com.cn", "AWS Elastic Load Balancing"),
    (".cloudfront.net", "AWS CloudFront"),
]

# Newer AWS load balancers (NLBs) put the region AFTER "elb", so they
# don't end in ".elb.amazonaws.com":
# 'app-nlb-1a2b3c.elb.us-east-1.amazonaws.com' ('.amazonaws.com.cn' in China)
AWS_NLB = re.compile(r"\.elb\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$")


def match_not_claimable(target: str) -> str | None:
    """Which never-claimable service a CNAME target belongs to, if any.

    'internal-lb-1234.us-east-1.elb.amazonaws.com' -> 'AWS Elastic Load Balancing'
    """
    for ending, service in NOT_CLAIMABLE:
        if target.endswith(ending):
            return service
    if AWS_NLB.search(target):
        return "AWS Elastic Load Balancing"
    return None


# Big cloud providers' own domains. A dangling CNAME under one of these
# can't be taken over by BUYING the domain (the provider owns it). Whether
# the name itself can be claimed again depends on the service, so a hit
# here is "check it", not a lead and not stale. Known services above win.
PROVIDER_DOMAINS = [
    (".amazonaws.com", "AWS"),
    (".amazonaws.com.cn", "AWS"),
    (".windows.net", "Microsoft Azure"),
    (".azure.com", "Microsoft Azure"),
    (".azure.net", "Microsoft Azure"),
    (".azurefd.net", "Microsoft Azure"),
    (".googleusercontent.com", "Google Cloud"),
    (".googleapis.com", "Google Cloud"),
    (".appspot.com", "Google Cloud"),
    (".run.app", "Google Cloud"),
    (".cloudflare.net", "Cloudflare"),
    (".fastly.net", "Fastly"),
    (".akamaiedge.net", "Akamai"),
    (".edgekey.net", "Akamai"),
]


def match_provider(target: str) -> str | None:
    """Which big cloud provider's own domain a CNAME target is under, if any."""
    for ending, provider in PROVIDER_DOMAINS:
        if target.endswith(ending):
            return provider
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
    "lead" / "stale" hold the full record for that status, else None. Each
    record has "nxdomain_confirmed_by": the DNS-over-HTTPS providers that
    agreed the CNAME target doesn't exist (empty = system DNS alone).
    """
    try:
        target = get_cname(host)
    except NoSuchHost:
        return {"status": "no_such_host", "cname": None, "lead": None, "stale": None}
    if target is None:
        return {"status": "no_cname", "cname": None, "lead": None, "stale": None}
    exists, confirmed_by = check_exists(target)
    if exists:
        return {"status": "cname_ok", "cname": target, "lead": None, "stale": None}

    if domain and in_domain(target, domain):
        stale = {"host": host, "cname": target, "service": "same domain",
                 "reason": f"only the owner of {domain} can create names under it",
                 "nxdomain_confirmed_by": confirmed_by, "collected_at": now_utc()}
        return {"status": "stale", "cname": target, "lead": None, "stale": stale}

    unclaimable = match_not_claimable(target)
    if unclaimable:
        stale = {"host": host, "cname": target, "service": unclaimable,
                 "reason": "names on this service include a random ID and can't be claimed again",
                 "nxdomain_confirmed_by": confirmed_by, "collected_at": now_utc()}
        return {"status": "stale", "cname": target, "lead": None, "stale": stale}
    service = match_service(target)
    lead = {
        "host": host,
        "cname": target,
        "service": service,              # None = not a known service
        "claimable": service is not None,
        "nxdomain_confirmed_by": confirmed_by,
        "collected_at": now_utc(),
    }
    return {"status": "lead", "cname": target, "lead": lead, "stale": None}


def check_host(host: str) -> dict | None:
    """Check one hostname. Returns a lead if its CNAME dangles, else None."""
    return inspect_host(host)["lead"]


def _safe_check(host: str, domain: str | None = None):
    """inspect_host() that never crashes: returns (host, info, error, status).

    On a DNS problem, info is None, error is the reason, and status says
    which kind: "conflicting" (system DNS and DNS-over-HTTPS disagree),
    "servfail" (DNS servers answered SERVFAIL, even after a retry)
    or "error" (no DNS server answered).
    """
    try:
        return host, inspect_host(host, domain), None, None
    except ConflictingAnswers as e:
        return host, None, str(e), "conflicting"
    except ServerFailure as e:
        return host, None, str(e), "servfail"
    except DNSLookupError as e:
        return host, None, str(e), "error"


def check_hosts(hosts: list[str], workers: int = 16, domain: str | None = None) -> dict:
    """Run the takeover check on every hostname.

    domain: the domain being scanned (e.g. 'wolt.com'), if known.

    Returns {"leads": [...], "stale": [...], "results": {host: {"status", "cname"}},
             "checked": count, "errors": {host: reason}}.
    """
    leads, stale, errors, results = [], [], {}, {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, info, err, err_status in pool.map(lambda h: _safe_check(h, domain), hosts):
            if err:
                errors[host] = err
                results[host] = {"status": err_status, "cname": None}
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
