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
import ipaddress
import re


from monomi.common import now_utc
from monomi.dnscheck import (ConflictingAnswers, DNSLookupError, NoSuchHost, ServerFailure,
                             check_exists, find_zone_cut, get_cname, nameserver_ips)

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

# AWS API Gateway names carry an ID AWS generates, so a deleted one can't be
# registered again, like a load balancer's:
# 'd-ab12cd34ef.execute-api.us-east-1.amazonaws.com' (a custom domain's target)
# 'a1b2c3d4e5.execute-api.us-east-1.amazonaws.com'   (an API's own name)
AWS_API_GATEWAY = re.compile(r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$")

# Amazon OpenSearch Service (formerly Elasticsearch) domain endpoints: the
# customer picks the domain name, AWS appends a long ID it generates (26
# characters in AWS's public example, 28 in its VPC one), so a deleted
# domain's endpoint can't be created again (v1.29.1, from PlayStation:
# search-ml-model-manager-index-th5s4iiqi35qtzwbozief2ydrq.us-west-2.es.amazonaws.com)
# 'search-movies-o36agaraperqwzp7s7vv6xfzwa.us-east-1.es.amazonaws.com' (AWS's example)
# 'vpc-endpoint-h2dsd34efgyghrtguk5gt6j2foh4.us-east-1.es.amazonaws.com' (a VPC domain)
AWS_OPENSEARCH = re.compile(r"(^|\.)(search|vpc)-[a-z][a-z0-9-]*-[a-z0-9]{20,32}"
                            r"\.[a-z0-9-]+\.es\.amazonaws\.com(\.cn)?$")


def match_not_claimable(target: str) -> str | None:
    """Which never-claimable service a CNAME target belongs to, if any.

    'internal-lb-1234.us-east-1.elb.amazonaws.com' -> 'AWS Elastic Load Balancing'
    """
    for ending, service in NOT_CLAIMABLE:
        if target.endswith(ending):
            return service
    if AWS_NLB.search(target):
        return "AWS Elastic Load Balancing"
    if AWS_API_GATEWAY.search(target):
        return "AWS API Gateway"
    if AWS_OPENSEARCH.search(target):
        return "AWS OpenSearch Service"
    return None


# Top-level domains only one company can register under: ICANN "brand" TLDs
# (IANA root zone database, type "brand"). A dangling CNAME into one is stale:
# nobody but that company could ever create the name. (v1.28, from the
# PlayStation run: six *.internal.aws CNAMEs graded "confirm by hand")
BRAND_TLDS = {
    "aws": "Amazon", "amazon": "Amazon",
    "google": "Google", "goog": "Google",
    "microsoft": "Microsoft", "azure": "Microsoft",
    "apple": "Apple", "sony": "Sony", "ibm": "IBM", "bmw": "BMW",
}

# TLDs that never exist on the public internet: reserved for private networks
# (RFC 6762 .local, RFC 6761 .localhost, ICANN's .internal in 2024) or ones
# ICANN won't delegate (.corp, .home, .mail). A name under one only works
# inside someone's own network, so nobody outside can claim it.
# .test / .example / .invalid are left out on purpose: they're for docs and
# tests (Monomi's planted scans use them for "unknown service" leads) and
# never turn up in a real target's DNS.
PRIVATE_TLDS = {"internal", "local", "localhost", "corp", "home", "mail"}


def match_closed_namespace(target: str) -> tuple[str, str] | None:
    """(service, reason) when nobody on the public internet can ever create
    the CNAME target, else None. Looks only at the name, never the network.

    'poseidon.internal.aws'  -> ('Amazon brand TLD', '.aws is a brand TLD ...')
    'preview.direct.q1-pqa'  -> ('internal name', ...): no real TLD has a
                                digit or hyphen, except IDNs (xn--...)
    """
    name = target.rstrip(".").lower()
    tld = name.rsplit(".", 1)[-1]
    if tld in BRAND_TLDS:
        company = BRAND_TLDS[tld]
        return (f"{company} brand TLD",
                f".{tld} is a brand TLD: only {company} can register names under it")
    if tld in PRIVATE_TLDS:
        return ("private name", f".{tld} is reserved for private networks and never "
                "registered on the public internet")
    if "." not in name or (not tld.startswith("xn--") and (any(c.isdigit() for c in tld) or "-" in tld)):
        return ("internal name", f"'{tld}' isn't a real top-level domain, so the name can only "
                "exist inside a private network")
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


# Managed DNS services that hand out nameservers from a large pool. A lame
# delegation to one of them means the zone was deleted there, but getting the
# exact same nameserver set assigned again is impractical, so it's graded
# "theoretical". Each entry: (IPv4 network of its nameservers, name).
# Unrecognized nameservers are graded "investigate": they might be
# re-registerable, and only a look at the exact NS names can tell.
# Route 53's nameserver ranges, from AWS's published list (ip-ranges.json,
# "service": "ROUTE53", list of 2026-11-26). AWS documents these IPs as static.
# v1.17 knew only 205.251.192.0/21, and no IPv6 range at all (v1.28.1).
ROUTE53_RANGES = [
    "1.179.52.0/22", "1.179.56.0/22", "18.196.222.0/24", "18.196.223.0/24", "205.251.192.0/21",
    "205.251.200.0/23", "3.4.24.0/23", "3.4.26.0/23", "3.4.32.0/20", "34.217.142.0/24",
    "34.217.143.0/24", "51.0.136.0/23", "51.0.138.0/23", "51.0.140.0/23", "51.0.142.0/23",
    "52.46.180.0/22", "52.46.184.0/22", "52.61.226.0/23", "52.82.176.0/22", "52.82.180.0/22",
    "52.95.110.0/24", "54.222.32.0/22", "54.222.36.0/22", "63.246.114.0/23", "64.91.192.0/19",
    "96.127.116.0/23",
    "2001:3fc6:8::/47", "2001:3fc6:a::/47", "2001:3fc6:c::/47", "2001:3fc6:e::/47",
    "2600:9000:5300::/45", "2600:9000:7000::/36", "2600:9000:de0::/43", "2600:9000:f530::/46",
    "2600:9000:fc0::/43", "2600:9000:ff8::/46", "2600:f0f0:400::/44", "2600:f0f2:7000::/44",
    "2600:f0f3:f000::/44", "2600:f0fb:f000::/44",
]
POOLED_DNS = [(ipaddress.ip_network(net), "AWS Route 53") for net in ROUTE53_RANGES]


def grade_delegation(ns_ips: list[str]) -> tuple[str, str | None]:
    """How claimable a lame delegation is, from the nameservers that refused it.

    Returns (grade, provider): ("theoretical", "AWS Route 53") when every
    refusing nameserver is on a pooled managed DNS service, otherwise
    ("investigate", None). No IPs at all is "investigate" too: nothing
    shows they're on a pooled service.
    """
    providers = set()
    for ip in ns_ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "investigate", None
        name = next((n for net, n in POOLED_DNS if addr in net), None)
        if name is None:
            return "investigate", None
        providers.add(name)
    if len(providers) == 1:
        return "theoretical", providers.pop()
    return "investigate", None


def delegation_view(d: dict) -> tuple[list[str], str, str | None]:
    """(ns_ips, grade, provider) for a saved ns_delegations record, worked out
    again from what the resolver said. Scans saved before v1.28.1 dropped IPv6
    nameservers and knew one Route 53 range, so their grade can be wrong;
    the same record always gives the same answer."""
    ips = list(d.get("ns_ips") or []) or nameserver_ips(d.get("detail") or "")
    grade, provider = grade_delegation(ips)
    return ips, grade, provider


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
    closed = match_closed_namespace(target)
    if closed:
        stale = {"host": host, "cname": target, "service": closed[0], "reason": closed[1],
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
    """inspect_host() that never crashes: returns (host, info, error, status, lame).

    On a DNS problem, info is None, error is the reason, and status says
    which kind: "conflicting" (system DNS and DNS-over-HTTPS disagree),
    "servfail" (DNS servers answered SERVFAIL, even after a retry)
    or "error" (no DNS server answered). lame is set only on a SERVFAIL the
    resolver blamed on a broken delegation: {"detail", "ns_ips"} (a
    dangling_ns candidate), else None.
    """
    try:
        return host, inspect_host(host, domain), None, None, None
    except ConflictingAnswers as e:
        return host, None, str(e), "conflicting", None
    except ServerFailure as e:
        lame = {"detail": e.detail, "ns_ips": list(e.ns_ips)} if e.lame else None
        return host, None, str(e), "servfail", lame
    except DNSLookupError as e:
        return host, None, str(e), "error", None


def check_hosts(hosts: list[str], workers: int = 16, domain: str | None = None,
                domains: dict | None = None) -> dict:
    """Run the takeover check on every hostname.

    domain: the domain being scanned (e.g. 'wolt.com'), if known.
    domains: host -> the domain to judge "same domain" by, for hosts that
    aren't under `domain` (--extra-hosts, v1.19); the rest use `domain`.

    Returns {"leads": [...], "stale": [...], "results": {host: {"status", "cname"}},
             "checked": count, "errors": {host: reason},
             "ns_delegations": [...]}. ns_delegations holds one record per
    broken (lame) delegation found, grouped by the delegated zone cut:
    {"cut", "hosts", "ns_ips", "detail", "collected_at", "grade", "provider"},
    a dangling_ns candidate (see grade_delegation for the grade).
    """
    leads, stale, errors, results = [], [], {}, {}
    cuts = {}   # zone cut -> delegation record (grouping many hosts into one)
    walked = {}  # name -> lame info or None, shared by every zone-cut walk this run

    def _record_lame(host, lame):
        """Attach a lame host to its delegation record, finding the zone cut once."""
        for cut, rec in cuts.items():
            if host == cut or host.endswith("." + cut):
                rec["hosts"].append(host)
                return
        # one network walk per new cut; the host itself is already known lame
        found = find_zone_cut(host, known=lame, cache=walked)
        cut = found[0] if found else host
        at_cut = found[1] if found else lame
        cuts[cut] = {"cut": cut, "hosts": [host],
                     "ns_ips": list(at_cut.get("ns_ips") or lame["ns_ips"]),
                     "detail": at_cut.get("detail") or lame["detail"],
                     "collected_at": now_utc()}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        def check(h):
            return _safe_check(h, (domains or {}).get(h, domain))
        for host, info, err, err_status, lame in pool.map(check, hosts):
            if err:
                errors[host] = err
                results[host] = {"status": err_status, "cname": None}
                if lame:
                    _record_lame(host, lame)
            else:
                results[host] = {"status": info["status"], "cname": info["cname"]}
                if info["lead"]:
                    leads.append(info["lead"])
                if info["stale"]:
                    stale.append(info["stale"])

    for rec in cuts.values():
        rec["hosts"] = sorted(set(rec["hosts"]))
        rec["grade"], rec["provider"] = grade_delegation(rec["ns_ips"])
    ns_delegations = sorted(cuts.values(), key=lambda r: r["cut"])
    return {"leads": leads, "stale": stale, "results": results, "checked": len(hosts),
            "errors": errors, "ns_delegations": ns_delegations}


if __name__ == "__main__":
    import sys

    report = check_hosts(sys.argv[1:])
    print(f"checked {report['checked']} host(s)")
    for lead in report["leads"]:
        service = lead["service"] or "unknown service"
        print(f"  LEAD   {lead['host']}  ->  {lead['cname']}  ({service})")
    for host, err in report["errors"].items():
        print(f"  ERROR  {host}: {err}")
