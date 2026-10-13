"""Load a SpiderFoot CSV export into Monomi's data structures."""

import csv
from collections import Counter

# Event types that describe a single host (Source column = the hostname or IP)
HOST_DETAIL_TYPES = {
    "WEBSERVER_BANNER": "banners",
    "BGP_AS_MEMBER": "asns",
    "GEOINFO": "countries",
    "PROVIDER_HOSTING": "hosting",
}

# Event types that may be security issues, passed to the AI as findings
FINDING_TYPES = {
    "MALICIOUS_IPADDR",
    "MALICIOUS_EMAILADDR",
    "MALICIOUS_INTERNET_NAME",
    "CLOUD_STORAGE_BUCKET",
    "VULNERABILITY_CVE_CRITICAL",
    "VULNERABILITY_CVE_HIGH",
}

# Short context about the domain as a whole
CONTEXT_TYPES = {
    "DOMAIN_REGISTRAR": "registrar",
    "PROVIDER_MAIL": "mail_providers",
    "PROVIDER_DNS": "dns_providers",
}




def _belongs_to(name, target):
    """True if name is the target domain or one of its subdomains."""
    name = name.lower().rstrip(".")
    return name == target or name.endswith("." + target)


def load_spiderfoot_csv(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))

    # Skip anything SpiderFoot (or the user) marked as a false positive
    rows = [r for r in rows if r.get("F/P", "0") != "1"]

    # 1. Work out the target domain: the one the scan was started on
    target = None
    for r in rows:
        if r["Type"] == "DOMAIN_NAME" and r["Module"] == "SpiderFoot UI":
            target = r["Data"].strip().lower()
            break
    if target is None:
        names = Counter(r["Data"].strip().lower() for r in rows if r["Type"] == "DOMAIN_NAME")
        if not names:
            raise ValueError("Couldn't find a target domain in this SpiderFoot export")
        target = names.most_common(1)[0][0]

    # 2. Hosts: the target's own hostnames
    hosts = {}

    def host(name):
        return hosts.setdefault(name, {
            "ips": set(), "banners": set(), "asns": set(),
            "countries": set(), "hosting": set(),
        })

    for r in rows:
        if r["Type"] == "INTERNET_NAME" and _belongs_to(r["Data"], target):
            host(r["Data"].strip().lower().rstrip("."))    # 3. Link IPs to hosts using the Source column (source host -> resolved IP)
    for r in rows:
        if r["Type"] in ("IP_ADDRESS", "IPV6_ADDRESS"):
            src = r["Source"].strip().lower().rstrip(".")
            if _belongs_to(src, target):
                host(src)["ips"].add(r["Data"].strip())

    # Reverse lookup so details reported against an IP land on its hosts
    ip_to_hosts = {}
    for name, h in hosts.items():
        for ip in h["ips"]:
            ip_to_hosts.setdefault(ip, []).append(name)

    # 4. Per-host details (banner, ASN, country, hosting provider)
    for r in rows:
        field = HOST_DETAIL_TYPES.get(r["Type"])
        if not field:
            continue
        src = r["Source"].strip().lower().rstrip(".")
        value = r["Data"].strip()
        if src in hosts:
            hosts[src][field].add(value)
        for name in ip_to_hosts.get(src, []):
            hosts[name][field].add(value)    # 5. Findings, third-party services, domain context
    findings, third_party = [], set()
    context = {v: set() for v in CONTEXT_TYPES.values()}
    for r in rows:
        t = r["Type"]
        if t in FINDING_TYPES:
            findings.append({
                "type": t,
                "module": r["Module"],
                "source": r["Source"].strip(),
                "data": r["Data"].strip(),
            })
        elif t == "AFFILIATE_INTERNET_NAME":
            third_party.add(r["Data"].strip().lower().rstrip("."))
        elif t in CONTEXT_TYPES:
            context[CONTEXT_TYPES[t]].add(r["Data"].strip())

    # 6. Count what we ignored, so the user can see nothing vanished silently
    used = {"INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME",
            "AFFILIATE_INTERNET_NAME"} | set(HOST_DETAIL_TYPES) | FINDING_TYPES | set(CONTEXT_TYPES)
    skipped = Counter(r["Type"] for r in rows if r["Type"] not in used)

    return {
        "target": target,
        "hosts": hosts,
        "findings": findings,
        "third_party": sorted(third_party),
        "context": {k: sorted(v) for k, v in context.items()},
        "skipped": skipped,
    }


if __name__ == "__main__":
    # Quick test: python3 -m importers.spiderfoot samples/SpiderFoot.csv
    import sys
    from pprint import pprint
    data = load_spiderfoot_csv(sys.argv[1])
    print("Target:", data["target"])
    print(f"Hosts ({len(data['hosts'])}):")
    for name, h in sorted(data["hosts"].items()):
        print(" ", name, sorted(h["ips"]), sorted(h["banners"]), sorted(h["asns"]))
    print("Findings:")
    pprint(data["findings"])
    print("Third-party:", data["third_party"])
    print("Context:", data["context"])
    print("Skipped:", dict(data["skipped"].most_common()))
