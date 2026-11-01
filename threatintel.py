"""
IP threat-intel: look into a suspicious IP (e.g. one hitting your logs).

Answers "what kind of IP is this?" from public sources only:
- Tor exit list (Tor Project): is it a Tor exit node?
- Network owner (Team Cymru ASN), reverse DNS, Shodan InternetDB.
Passive: we only ask these third-party sources about the IP. The IP itself
never receives any traffic from us.

What this can NOT tell you: where the person behind the IP actually is.
Country data is where the network is registered, and VPNs, Tor and cloud
servers hide the real location.
"""

import ipaddress

import socket
import re
import requests

import aws_ranges
import enrich
import internetdb
from common import USER_AGENT, is_hostname, now_utc

TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"

# Network owners that mostly rent out servers. Traffic from these is usually
# a server (a VPS, a bot, a VPN box), not someone's home internet.
HOSTING_PROVIDERS = {
    "AWS", "Google Cloud", "Google", "Microsoft/Azure", "DigitalOcean", "Hetzner",
    "OVH", "Vultr", "Oracle Cloud", "Akamai/Linode",
}

# Shodan tags that matter for a suspicious IP. Tag -> our label.
SHODAN_TAG_LABELS = {
    "tor": "tor_exit", "vpn": "vpn", "proxy": "proxy",
    "cloud": "hosting", "cdn": "cdn_edge", "scanner": "scanner",
    "c2": "known_bad", "malware": "known_bad", "compromised": "known_bad",
}

# Words in a reverse DNS name that hint at an anonymizer. Matched as whole
# words only, so "tor" matches "tor-exit.example" but NOT "storage.example".
RDNS_HINTS = {"tor": "tor_exit", "vpn": "vpn", "proxy": "proxy"}

# Labels that mean "the real person is hidden behind this IP".
ANONYMIZERS = {"tor_exit", "vpn", "proxy"}


def clean_ip(text: str) -> str | None:
    """'  1.2.3.4 ' -> '1.2.3.4'. None if it isn't a public IP address."""
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None

def reject_reason(text: str) -> str:
    """Why clean_ip() turned this down, in plain words."""
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return "not an IP address"
    if ip.is_loopback:
        return "loopback (this machine)"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified (0.0.0.0 / ::)"
    if ip.is_private:
        return "private (internal network)"
    return "reserved, not a public internet address"

def tor_exit_ips(timeout: int = 20) -> set[str]:
    """Download the Tor Project's current list of exit node IPs.

    The list is plain text, one IP per line. Raises requests.RequestException
    if it can't be fetched.
    """
    resp = requests.get(TOR_EXIT_URL, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    resp.raise_for_status()
    found = set()
    for line in resp.text.splitlines():
        ip = clean_ip(line)
        if ip:
            found.add(ip)
    return found


def reverse_dns(ip: str) -> str | None:
    """1.1.1.1 -> 'one.one.one.one'. None if the IP has no PTR record.

    The PTR record is set by whoever controls the IP, so it can be anything.
    It goes through is_hostname() like every other untrusted name.
    """
    try:
        name = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return None
    return name if is_hostname(name) else None


def investigate(ip: str) -> dict:
    """Collect every fact we can about one public IP.

    Each source can fail on its own: failures go in "errors" and the
    rest still run. Shodan "None" with no error = Shodan has nothing on it.
    """
    result = {"ip": ip, "collected_at": now_utc(), "tor_exit": None,
              "network": None, "rdns": None, "shodan": None, "errors": {}}

    # 1. Tor exit list (asks the Tor Project)
    try:
        result["tor_exit"] = ip in tor_exit_ips()
    except requests.RequestException as e:
        result["errors"]["tor"] = str(e)

    # 2. Network owner + registered country (asks Team Cymru)
    try:
        info = enrich.asn_lookup([ip]).get(ip)
    except RuntimeError as e:
        result["errors"]["asn"] = str(e)
    else:
        if info and info["as_name"] == "AWS":
            # Same trick as --enrich: tell CloudFront edges apart from normal AWS
            try:
                if aws_ranges.in_networks(ip, aws_ranges.cloudfront_networks()):
                    info["as_name"] = "AWS CloudFront"
            except RuntimeError as e:
                result["errors"]["aws"] = str(e)
        result["network"] = info

    # 3. Reverse DNS (asks DNS for the IP's PTR record)
    result["rdns"] = reverse_dns(ip)

    # 4. What Shodan last saw on it (asks Shodan, not the IP)
    try:
        result["shodan"] = internetdb.lookup_one(ip)
    except (requests.RequestException, ValueError) as e:
        result["errors"]["shodan"] = str(e)

    result["labels"] = label(result)
    add_vulns_note(result)
    return result


def add_vulns_note(result: dict) -> None:
    """Explain CVEs seen on a shared CDN edge IP.

    Thousands of sites share one CDN edge IP, and Shodan records whatever
    version banners it saw there, so these CVEs most likely belong to
    another site behind the IP. Needs result["labels"] already set.
    """
    shodan = result["shodan"]
    if not shodan or not shodan["vulns"]:
        return
    if any(l["label"] == "cdn_edge" for l in result["labels"]):
        shodan["vulns_note"] = ("seen on a shared CDN edge IP: these CVEs most "
                                "likely belong to another site behind it, "
                                "not to this IP's owner")


def label(facts: dict) -> list[dict]:
    """Turn investigate() facts into labels, each with its source and reason.

    The same label can appear more than once (e.g. tor_exit from the Tor
    list AND Shodan): more sources agreeing = stronger finding.
    """
    labels = []

    def add(name, source, reason):
        labels.append({"label": name, "source": source, "reason": reason})

    if facts["tor_exit"]:
        add("tor_exit", "Tor exit list", "listed in the Tor Project's current exit node list")

    for tag in (facts["shodan"] or {}).get("tags", []):
        if tag in SHODAN_TAG_LABELS:
            add(SHODAN_TAG_LABELS[tag], "Shodan InternetDB", f"Shodan tagged it '{tag}'")

    if facts["rdns"]:
        words = set(re.split(r"[.-]", facts["rdns"]))
        for word, name in RDNS_HINTS.items():
            if word in words:
                add(name, "reverse DNS", f"its hostname ({facts['rdns']}) contains '{word}'")

    provider = (facts["network"] or {}).get("as_name")
    cpe_edge = internetdb.edge_from_cpes((facts["shodan"] or {}).get("cpes", []))
    if provider in internetdb.SHARED_EDGE:
        add("cdn_edge", "Team Cymru ASN",
            f"{provider} edge server: the real source is behind the CDN")
    elif cpe_edge:
        add("cdn_edge", "Shodan InternetDB",
            f"Shodan identifies the service as {cpe_edge[0]} ({cpe_edge[1]}): "
            "the real source is behind it")
    elif provider in HOSTING_PROVIDERS:
        add("hosting", "Team Cymru ASN",
            f"network belongs to {provider}, a hosting/cloud provider")

    found = {l["label"] for l in labels}
    if facts["tor_exit"] is False and not found & ANONYMIZERS:
        add("no_anonymizer_found", "all sources",
            "no Tor, VPN or proxy signs in any source (doesn't prove there isn't one)")

    return labels

# Readable source names for the error keys investigate() uses
SOURCE_NAMES = {"tor": "Tor exit list", "asn": "Team Cymru ASN",
                "aws": "AWS IP ranges", "shodan": "Shodan InternetDB"}


def build_evidence(results: dict) -> list[dict]:
    """Numbered facts (E1, E2...) for the AI verdict to cite.

    Same format as evidence.build_evidence(), so evidence.check_citations()
    and evidence.evidence_appendix() work on it unchanged.
    """
    evidence = []

    def add(fact, source, when):
        evidence.append({"id": f"E{len(evidence) + 1}", "fact": fact,
                         "sources": [{"name": source, "collected_at": when}]})

    for ip, r in results["ips"].items():
        when = r["collected_at"]
        errors = r["errors"]

        if r["tor_exit"] is True:
            add(f"{ip} is in the Tor Project's current exit node list", "Tor exit list", when)
        elif r["tor_exit"] is False:
            add(f"{ip} is not in the Tor Project's current exit node list", "Tor exit list", when)

        net = r["network"]
        if net:
            add(f"{ip} belongs to {net['asn']} ({net.get('raw_as_name', net['as_name'])}); "
                f"the network is registered in {net['country']} "
                "(where the network is registered, not where its user is)",
                "Team Cymru ASN", when)
        elif "asn" not in errors:
            add(f"No network owner (ASN) was found for {ip}", "Team Cymru ASN", when)

        if r["rdns"]:
            add(f"{ip}'s reverse DNS name is {r['rdns']}", "reverse DNS", when)
        else:
            add(f"{ip} has no reverse DNS name", "reverse DNS", when)

        s = r["shodan"]
        if s:
            ports = ", ".join(str(p) for p in s["ports"]) or "none"
            fact = f"Shodan last saw open ports on {ip}: {ports}"
            if s["tags"]:
                fact += f"; tags: {', '.join(s['tags'])}"
            if s["vulns"]:
                fact += f"; {len(s['vulns'])} CVE(s) matched from version banners"
                if s.get("vulns_note"):
                    fact += (" (seen on a shared CDN edge IP, so these likely "
                             "belong to another site behind it)")
            add(fact, "Shodan InternetDB", when)
        elif "shodan" not in errors:
            add(f"Shodan InternetDB has no record of {ip}", "Shodan InternetDB", when)

        for key in errors:
            name = SOURCE_NAMES.get(key, key)
            add(f"The {name} lookup for {ip} failed, so that part is unknown", name, when)

        for l in r["labels"]:
            add(f"monomi rule: {ip} labeled {l['label']} ({l['reason']})",
                f"monomi rules, from {l['source']}", when)

    return evidence


if __name__ == "__main__":
    import json
    import sys

    ip = clean_ip(sys.argv[1])
    if ip is None:
        sys.exit("not a public IP address")
    print(json.dumps(investigate(ip), indent=2))
