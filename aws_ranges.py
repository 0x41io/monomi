"""
AWS CloudFront detection using Amazon's published IP range list.

Team Cymru labels every Amazon IP the same way (AMAZON-02, ...), whether it's
a CloudFront CDN edge server or a customer's own EC2 server. Amazon publishes
which ranges belong to which service, so we use that list to tell them apart:
an IP inside a "CLOUDFRONT" range is a shared edge server, like Cloudflare.

The list (~1-2 MB) is downloaded from Amazon, never from the target, and
cached for a day in cache/ so repeat scans don't download it again.
"""

import ipaddress
import json
import os
import time

import requests

from collectors import USER_AGENT

URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
CACHE_FILE = os.path.join(CACHE_DIR, "aws-ip-ranges.json")
MAX_AGE = 24 * 60 * 60  # seconds: refresh the cached list once a day

# Only the edge servers people connect to. "CLOUDFRONT_ORIGIN_FACING" is the
# range CloudFront uses to reach origin servers, so it's deliberately left out.
# (Every range is also listed under "AMAZON", so matching is on the exact tag.)
EDGE_SERVICE = "CLOUDFRONT"


def _read_cache():
    with open(CACHE_FILE) as f:
        return json.load(f)


def _download() -> dict:
    try:
        resp = requests.get(URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise RuntimeError(f"couldn't download AWS IP ranges: {e}")
    if not isinstance(data, dict) or "prefixes" not in data:
        raise RuntimeError("AWS IP range list had an unexpected format")

    # Save to a temp file, then swap it in, so a crash mid-write can't leave
    # a half-written cache behind. Caching is a bonus: failure is fine.
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, CACHE_FILE)
    except OSError:
        pass
    return data


def load_ranges() -> dict:
    """Return Amazon's range list: fresh cache, else download, else stale cache."""
    try:
        if time.time() - os.path.getmtime(CACHE_FILE) < MAX_AGE:
            return _read_cache()
    except (OSError, ValueError):
        pass  # no cache yet, or it's unreadable
    try:
        return _download()
    except RuntimeError as download_error:
        try:
            return _read_cache()  # older than a day, but better than nothing
        except (OSError, ValueError):
            raise download_error  # no cache at all: report the download problem


def cloudfront_networks() -> list:
    """All CloudFront edge ranges (IPv4 and IPv6) as ip_network objects."""
    data = load_ranges()
    nets = []
    for p in data.get("prefixes", []):
        if p.get("service") == EDGE_SERVICE:
            nets.append(ipaddress.ip_network(p["ip_prefix"]))
    for p in data.get("ipv6_prefixes", []):
        if p.get("service") == EDGE_SERVICE:
            nets.append(ipaddress.ip_network(p["ipv6_prefix"]))
    return nets


def in_networks(ip: str, nets: list) -> bool:
    """True if ip falls inside any of the networks (IPv4/IPv6 mismatch = no match)."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in nets)
