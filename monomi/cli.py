#!/usr/bin/env python3
"""
0x41 / monomi - passive domain reconnaissance with AI synthesis.

Usage:
    python monomi.py example.com
    python monomi.py example.com --json results.json
    python monomi.py example.com --ports --cves cves.txt
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

from concurrent.futures import ThreadPoolExecutor, wait as wait_for
from monomi.collectors import certspotter, crtsh, crtsh_db, otx, saved
from monomi.common import VERSION, is_hostname, now_utc
from monomi.importers import bbot, spiderfoot, subfinder
from monomi import (activelog, content, doctor, emailauth, enrich, evidence, exposed, fingerprint, gate,
                    history, home, internetdb, mcp_setup, paths, probe, rate, report, research,
                    scope, suggest, takeover, threatintel, ui)
from monomi.ui import fail, good, info, warn

# Reports always go in the monomi folder, wherever the command is run from
REPORTS_DIR = home.data_dir("reports")

# --investigate-ip: at most this many IPs per run, to be polite to the free sources
MAX_INVESTIGATE = 20

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)


def short_path(path: str) -> str:
    """'reports/x.md' when run from the monomi folder, the full path otherwise."""
    rel = os.path.relpath(path)
    return path if rel.startswith("..") else rel


def clean_domain(raw: str) -> str:
    """Accept 'https://www.Example.com/path' and turn it into 'example.com'-style input."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)  # strip scheme
    d = d.split("/")[0].split(":")[0]  # strip path and port
    d = d.rstrip(".")  # "example.com." (fully qualified form) -> "example.com"
    d = re.sub(r"^www\.", "", d)  # www.example.com -> example.com, so we search the whole domain
    if not DOMAIN_RE.match(d):
        raise ValueError(f"'{raw}' doesn't look like a valid domain")

    return d


def cli_rate(text: str) -> float:
    """--rate N for argparse: a bad number is a usage error before anything runs."""
    try:
        return rate.parse(text)
    except rate.RateError as e:
        raise argparse.ArgumentTypeError(str(e))


def build_parser() -> argparse.ArgumentParser:
    """All of monomi's command-line options."""
    parser = argparse.ArgumentParser(description="0x41 / monomi - passive domain recon")
    parser.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    parser.add_argument("--import", dest="import_file", metavar="FILE", help="analyze a SpiderFoot CSV export")
    parser.add_argument("--json", metavar="FILE", help="save raw results to a JSON file")
    parser.add_argument("--export", type=report.parse_formats, metavar="FORMATS",
                        help="save the report as files: all, or any of md,html,csv (e.g. --export html,csv)")
    parser.add_argument("--ai", action="store_true", help="have Claude write a summary report (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--enrich", action="store_true", help="resolve hosts to IPs and look up hosting provider/ASN (sends DNS queries)")
    parser.add_argument("--ports", action="store_true", help="look up open ports and known CVEs in Shodan's InternetDB (passive; turns on --enrich)")
    parser.add_argument("--cves", metavar="FILE", help="save every CVE found by --ports to a file (feed it to kaidoku --file)")
    parser.add_argument("--fingerprint", action="store_true", help="ACTIVE: one homepage request per live host to spot web server/framework (turns on --enrich)")
    parser.add_argument("--exposed-files", action="store_true", help="ACTIVE: look for public API specs (OpenAPI/Swagger) and JS source maps on live hosts (turns on --enrich)")
    parser.add_argument("--probe", action="store_true",
                        help="ACTIVE: follow each live host's homepage through its redirects (every hop "
                             "scope-checked) and read the final page's title (turns on --enrich)")
    parser.add_argument("--content", action="store_true",
                        help=f"ACTIVE: content discovery: about {len(content.PATHS)} paths per live host "
                             "(.git, .env, backups, debug pages, admin panels...); a file counts only when "
                             "its content is the real thing (turns on --enrich)")
    parser.add_argument("--wordlist", metavar="FILE",
                        help="with --content: your own paths too (one per line, SecLists style), "
                             "reported as leads only")
    parser.add_argument("--scope", metavar="FILE",
                        help="ACTIVE checks only reach hosts this scope file allows: one rule per "
                             "line, example.com, *.example.com (subdomains), !host (never); every "
                             "other host is skipped and listed")
    parser.add_argument("--rate", type=cli_rate, metavar="N",
                        help="ACTIVE requests per second, in total (e.g. 1, or 0.5 for one every 2s); "
                             f"default {rate.SCOPED_DEFAULT:g}/s with --scope, no limit without")
    parser.add_argument("--research", metavar="FILE",
                        help="ACTIVE requests also carry the headers in this file, one 'Name: value' "
                             "per line (e.g. X-Intigriti: yourname), as some bug bounty programs require")
    parser.add_argument("--email", action="store_true", help="check SPF/DMARC/DKIM: can someone send email pretending to be this domain? (DNS lookups only)")
    parser.add_argument("--takeover", action="store_true", help="check for dangling CNAMEs / subdomain takeover leads (DNS lookups only)")
    parser.add_argument("--hosts", metavar="FILE", help="also check hostnames you already know (one per line), e.g. ones certificate logs miss")
    parser.add_argument("--extra-hosts", metavar="FILE",
                        help="also check single hosts on OTHER domains (one per line), e.g. "
                             "app.other.com from a program's scope: enrich/ports/takeover only, "
                             "their domains are never searched for subdomains; with --scope, "
                             "each one must be in scope")
    parser.add_argument("--subfinder", metavar="FILE",
                        help="also check the hostnames in a subfinder output file (plain, -oJ or -oI); "
                             "Monomi never runs subfinder itself")
    parser.add_argument("--bbot", metavar="FILE",
                        help="also check the in-scope hostnames in a BBOT output.json (v1.29); "
                             "Monomi never runs BBOT itself")
    parser.add_argument("--investigate-ip", nargs="+", metavar="IP",
                        help="look into suspicious IP(s): Tor/VPN/hosting signs, network owner, Shodan (asks public sources, never the IP)")
    parser.add_argument("--no-color", action="store_true", help="plain output (also respects NO_COLOR)")
    return parser


def load_import(path: str) -> dict | None:
    """Read a SpiderFoot CSV export. On failure, say why and return None."""
    try:
        return spiderfoot.load_spiderfoot_csv(path)
    except (OSError, ValueError, KeyError) as e:
        fail(f"Couldn't read SpiderFoot export {path}: {e}")
        return None


def import_matches(sf: dict, domain: str, path: str) -> bool:
    """True if the export is a scan of the domain asked for. Otherwise, explain and return False."""
    # Compare cleaned forms, so "www.example.com" in the export matches "example.com"
    try:
        sf_domain = clean_domain(sf["target"])
    except ValueError:
        sf_domain = sf["target"]
    if sf_domain == domain:
        return True
    # The export's hosts were filtered for its own target, so mixing the two
    # would produce a report about one domain filled with another's data.
    fail(f"This export is a scan of {sf['target']}, but you asked for {domain}.")
    info(f"Run it without a domain to analyze {sf['target']}: python monomi.py --import {path}")
    return False


MAX_HOSTS_FILE = 500
HOSTS_FILE = "hosts file"


def read_hosts_file(path: str, domain: str) -> tuple[list[str], list[str]]:
    """Hostnames from a file, one per line ("#" starts a comment).

    Returns (hosts to check, lines that were skipped, each with the reason).
    Only the target domain and its subdomains are kept, so a file can't
    point monomi at anything outside the scan.
    """
    hosts, skipped = set(), []
    with open(path) as f:
        for line in f:
            name = line.split("#")[0].strip().lower().rstrip(".")
            if not name:
                continue
            if not is_hostname(name):
                skipped.append(f"{name[:60]}: not a hostname")
            elif name != domain and not name.endswith("." + domain):
                skipped.append(f"{name[:60]}: not part of {domain}")
            else:
                hosts.add(name)
    hosts = sorted(hosts)
    if len(hosts) > MAX_HOSTS_FILE:
        skipped.append(f"{len(hosts) - MAX_HOSTS_FILE} more hostnames: over the {MAX_HOSTS_FILE} limit")
    return hosts[:MAX_HOSTS_FILE], skipped


def add_hosts_file(results: dict, path: str, domain: str) -> bool:
    """--hosts: add the file's hostnames as their own source. False if unreadable."""
    try:
        hosts, skipped = read_hosts_file(path, domain)
    except OSError as e:
        fail(f"Can't read the hosts file: {e}")
        return False
    results["sources"][HOSTS_FILE] = {"source": HOSTS_FILE, "file": path,
                                      "subdomains": hosts, "collected_at": now_utc()}
    good(f"{HOSTS_FILE}: {len(hosts)} hostnames from {short_path(path)}")
    for line in skipped[:10]:
        warn(f"Skipped {ui.safe(line)}")
    if len(skipped) > 10:
        warn(f"...and {len(skipped) - 10} more skipped lines")
    return True


EXTRA_HOSTS = "extra hosts"


def read_extra_hosts(path: str, domain: str, active_scope) -> tuple[list[str], list[dict]]:
    """--extra-hosts FILE: single hosts on other domains ("#" starts a comment).

    Returns (hosts to check, refused lines, each {"host", "reason"}). With
    --scope every host must match it (fail closed, as for active checks),
    so a program's single-host assets can be checked without sweeping
    their domains. Hosts under the scanned domain belong in --hosts."""
    names, refused = [], []
    with open(path) as f:
        for line in f:
            name = line.split("#")[0].strip().lower().rstrip(".")
            if not name:
                continue
            if not is_hostname(name):
                refused.append({"host": name[:60], "reason": "not a hostname"})
            elif name == domain or name.endswith("." + domain):
                refused.append({"host": name, "reason": f"part of {domain}: use --hosts for it"})
            elif name not in names:
                names.append(name)
    if active_scope is not scope.UNSCOPED_CLI:
        inside, outside = scope.split(active_scope, names)
        refused += [{"host": o["host"], "reason": f"out of scope ({o['reason']})"} for o in outside]
        names = inside
    names = sorted(names)
    if len(names) > MAX_HOSTS_FILE:
        refused.append({"host": f"{len(names) - MAX_HOSTS_FILE} more",
                        "reason": f"over the {MAX_HOSTS_FILE} limit"})
    return names[:MAX_HOSTS_FILE], refused


def add_extra_hosts(results: dict, path: str, domain: str, active_scope) -> bool:
    """--extra-hosts: add the file's hosts as their own source (never sent to
    CT logs, OTX or subfinder, and left out of change history). False if unreadable."""
    try:
        hosts, refused = read_extra_hosts(path, domain, active_scope)
    except OSError as e:
        fail(f"Can't read the extra hosts file: {e}")
        return False
    results["sources"][EXTRA_HOSTS] = {"source": EXTRA_HOSTS, "file": path,
                                       "subdomains": hosts, "collected_at": now_utc()}
    results["extra_hosts"] = {"file": path, "hosts": hosts, "refused": refused}
    good(f"{EXTRA_HOSTS}: {len(hosts)} single host(s) on other domains from {short_path(path)} "
         "(checked on their own, no subdomain search)")
    for r in refused[:10]:
        warn(f"Skipped {ui.safe(r['host'])}: {ui.safe(r['reason'])}")
    if len(refused) > 10:
        warn(f"...and {len(refused) - 10} more skipped lines")
    return True


def extra_set(results: dict) -> set[str]:
    return set(results.get("extra_hosts", {}).get("hosts", []))


def add_subfinder(results: dict, path: str, domain: str) -> bool:
    """--subfinder: add the output file's hostnames as their own source. False if unreadable."""
    try:
        loaded = subfinder.load(path, domain)
    except (OSError, ValueError) as e:
        fail(f"Can't read the subfinder file: {e}")
        return False
    r = subfinder.to_source(loaded, path)
    results["sources"]["subfinder"] = r
    good(f"subfinder: {r['subdomain_count']} hostnames from {short_path(path)} "
         f"(written {r['collected_at']})")
    for line in r["skipped"]:
        warn(f"Skipped {line}")
    return True


def add_bbot(results: dict, path: str, domain: str) -> bool:
    """--bbot: add the in-scope hostnames from a BBOT output.json as their own
    source, and name everything else it held. False if unreadable."""
    try:
        loaded = bbot.load(path, domain)
    except (OSError, ValueError) as e:
        fail(f"Can't read the BBOT file: {e}")
        return False
    r = bbot.to_source(loaded, path)
    results["sources"]["bbot"] = r
    good(f"BBOT: {r['subdomain_count']} in-scope hostnames from {short_path(path)} "
         f"(written {r['collected_at']})")
    for line in r["skipped"]:
        warn(f"Skipped {line}")
    if r["not_used"]:
        shown = ", ".join(f"{ui.safe(t)}: {n}" for t, n in r["not_used"].items())
        info(f"Not used (other BBOT event types; Monomi checks these itself): {shown}")
    return True


def add_import(results: dict, sf: dict, path: str) -> None:
    """Put the SpiderFoot export's hosts, findings and context into results."""
    hosts = sorted(sf["hosts"])
    results["sources"]["spiderfoot"] = {"source": "spiderfoot", "file": path, "subdomains": hosts}
    results["spiderfoot"] = {
        # sets -> sorted lists, so the data can be saved as JSON and sent to the AI
        "hosts": {h: {k: sorted(v) for k, v in d.items()} for h, d in sf["hosts"].items()},
        "findings": sf["findings"],
        "third_party": sf["third_party"],
        "context": sf["context"],
        "skipped": dict(sf["skipped"].most_common()),
    }
    good(f"SpiderFoot export: {len(hosts)} hostnames, {len(sf['findings'])} possible findings, "
         f"{len(sf['third_party'])} third-party services")
    if sf["skipped"]:
        info(f"Skipped {sum(sf['skipped'].values())} rows of noise/raw data "
             f"(mostly {', '.join(t for t, _ in sf['skipped'].most_common(2))})")


# Sources that keep every certificate ever logged (expired ones too)
FULL_HISTORY_SOURCES = ("crt.sh", "crt.sh database")
# Start of the error message when crt.sh is behind the CT logs (not broken)
CRTSH_BEHIND = "no certificates for this domain yet"

# Job name in collect_ct() -> the "source" name its result is stored under
SOURCE_NAMES = {"crt.sh": "crt.sh", "crt.sh database": "crt.sh database", "Cert Spotter": "certspotter",
                "AlienVault OTX": "otx"}
DISPLAY_NAMES = {key: name for name, key in SOURCE_NAMES.items()}  # "certspotter" -> "Cert Spotter"
# What history tracks, one list each: crt.sh's website and database hold the
# same data, so they're one entry. Imports (hosts file, SpiderFoot, subfinder, BBOT)
# aren't here: they're only there on runs that pass the file, so they'd make
# hosts look new or gone.
HISTORY_SOURCES = {"crt.sh": ("crt.sh", "crt.sh database"), "certspotter": ("certspotter",),
                   "otx": ("otx",)}
HISTORY_LABELS = {"crt.sh": "crt.sh", "certspotter": "Cert Spotter", "otx": "AlienVault OTX"}


def seen(r: dict) -> int:
    """How many raw records a source looked at: certificates for CT logs,
    passive DNS records for OTX."""
    return r.get("certificates_seen", r.get("records_seen", 0))


def seen_line(name: str, r: dict) -> str:
    """"Cert Spotter: 130 certificates -> 29 hostnames", or records for OTX."""
    what = "certificates" if "certificates_seen" in r else "passive DNS records"
    return f"{name}: {seen(r)} {what} -> {r['subdomain_count']} hostnames"


def collect_ct(results: dict, domain: str, crtsh_budget: float = crtsh.DEFAULT_BUDGET,
               crtsh_light: bool = False, total_budget: float | None = None) -> None:
    """Query every subdomain source at the same time and merge whatever succeeds:
    the Certificate Transparency logs and AlienVault OTX's passive DNS."""
    jobs = {
        "crt.sh": lambda: crtsh.collect(domain, budget=crtsh_budget, light=crtsh_light),
        "crt.sh database": lambda: crtsh_db.collect(domain, budget=min(crtsh_budget, crtsh_db.DEFAULT_BUDGET)),
        "Cert Spotter": lambda: certspotter.collect(domain),
        "AlienVault OTX": lambda: otx.collect(domain),
    }
    info("Querying certificate transparency logs and passive DNS "
         "(crt.sh, crt.sh database, Cert Spotter, AlienVault OTX, in parallel)...")
    pool = ThreadPoolExecutor(max_workers=len(jobs))
    futures = {name: pool.submit(job) for name, job in jobs.items()}
    # Wait for every source, but never longer than total_budget (None = no limit)
    wait_for(futures.values(), timeout=total_budget)
    # Don't block on a source that's still running; its result is dropped
    pool.shutdown(wait=False, cancel_futures=True)

    for name, future in futures.items():
        if not future.done():
            results["errors"][name] = f"still running after the {total_budget:.0f}s total budget, skipped"
            warn(f"{name} skipped: took longer than {total_budget:.0f}s")
            continue
        try:
            r = future.result()
            results["sources"][r["source"]] = r
            good(seen_line(name, r))
            if r.get("partial"):
                warn(f"{name} {r['partial']}, so its list may be incomplete")
        except RuntimeError as e:
            results["errors"][name] = str(e)
            warn(f"{name} unavailable: {e}")
    flag_silent_crtsh_failure(results)
    use_saved_copies(results, domain)


def use_saved_copies(results: dict, domain: str) -> None:
    """Save each source that worked, and fill in for each one that failed from its saved copy.

    The crt.sh website and database hold the same data, so a saved crt.sh
    copy is only used when both failed, and then only the newer of the two.
    The error stays in results["errors"], so the scan still counts as
    incomplete and isn't saved to history as a baseline.
    """
    for name, source in SOURCE_NAMES.items():
        r = results["sources"].get(source)
        # An empty result is no use as a fallback, and a cut-short one would
        # replace a complete saved copy with part of a list
        if r and seen(r) > 0 and not r.get("partial"):
            try:
                saved.save(domain, r)
            except (OSError, ValueError) as e:
                warn(f"Couldn't save {name}'s result for later: {e}")

    copies = {}
    for name, source in SOURCE_NAMES.items():
        copy = saved.load(domain, source) if name in results["errors"] else None
        if copy:
            copies[name] = copy
    crtsh_copies = [name for name in FULL_HISTORY_SOURCES if name in copies]
    if any(name in results["sources"] for name in FULL_HISTORY_SOURCES):
        for name in crtsh_copies:
            del copies[name]  # the other crt.sh source worked, so nothing is missing
    elif len(crtsh_copies) == 2:
        older = min(crtsh_copies, key=lambda name: copies[name]["collected_at"])
        del copies[older]

    for name, copy in copies.items():
        results["sources"][copy["source"]] = copy
        results["errors"][name] += f"; using the saved copy from {copy['collected_at']}"
        warn(f"{name}: using the saved copy from {copy['collected_at']} "
             f"({copy['subdomain_count']} hostnames, may be out of date)")


def flag_silent_crtsh_failure(results: dict) -> None:
    """Catch a crt.sh source failing without an error.

    crt.sh (website and database) keeps every certificate ever logged, so it
    should always see at least as many as any other source. If one of them saw
    0 while another source saw some, it broke silently (crt.sh sometimes answers
    with an empty reply when it's overloaded). Treat that as a failure, so
    change detection won't save an incomplete baseline and the AI report won't
    say crt.sh found nothing.

    One exception to "broke": if the crt.sh database itself answered with 0
    rows, crt.sh really has nothing yet (it can fall days behind the CT logs,
    e.g. for a new domain). It's still a gap, but the message says "behind".
    """
    db = results["sources"].get("crt.sh database")
    behind = db is not None and db["certificates_seen"] == 0  # a real 0 from crt.sh's own database
    for name in FULL_HISTORY_SOURCES:
        r = results["sources"].get(name)
        if not r or r["certificates_seen"] > 0:
            continue  # didn't run, failed loudly, or found something: nothing to flag
        # Only other CT logs: passive DNS (OTX) says nothing about what crt.sh should have
        others = {other: o["certificates_seen"] for other, o in results["sources"].items()
                  if other != name and "certificates_seen" in o}
        best = max(others, key=others.get, default=None)
        if best is None or others[best] == 0:
            continue  # nobody found anything: a genuine empty result
        del results["sources"][name]
        shown = DISPLAY_NAMES.get(best, best)
        if behind:
            results["errors"][name] = (
                f"{CRTSH_BEHIND}: the crt.sh database answered with 0 "
                f"while {shown} found {others[best]}; crt.sh may not have indexed them"
            )
            warn(f"{name} has none of the certificates {shown} found, so crt.sh is probably behind "
                 f"on the CT logs. Treating it as unavailable.")
        else:
            results["errors"][name] = (
                f"returned no certificates while {shown} found {others[best]}; "
                f"{name} likely failed silently (empty reply)"
            )
            warn(f"{name} returned nothing but {shown} found certificates, so it probably failed silently. Treating it as unavailable.")


def run_enrich(results: dict, ports_on: bool) -> dict:
    """--enrich: resolve every host, look up who hosts it, and print the table."""
    all_subs = results["subdomains"]
    info("Resolving hosts and looking up hosting providers...")
    data = enrich.enrich(all_subs)
    data["collected_at"] = now_utc()
    for h in extra_set(results) & set(data["hosts"]):
        data["hosts"][h]["extra"] = True   # labeled in the table and in --json
    results["enrichment"] = data
    if data["asn_error"]:
        warn(f"{data['asn_error']} (showing IPs without provider info)")
        if ports_on:
            # Without provider names we can't tell CDN edge IPs apart, so their
            # ports and CVEs would be counted as the target's own.
            warn("CDN edge filtering is OFF for this run: ports/CVEs below may belong to "
                 "Cloudflare/Fastly/etc., not the target. Re-run later for accurate numbers.")
    if data.get("cdn_error"):
        warn(f"CloudFront detection skipped: {data['cdn_error']}. CloudFront edge IPs will show as plain AWS"
             + (" and their ports/CVEs may be counted as the target's." if ports_on else "."))
    print()
    ui.host_table(data["hosts"])
    print()
    total = len(data["hosts"])   # hosts set aside under a wildcard aren't counted
    good(
        f"{data['resolved']}/{total} hosts resolve to "
        f"{data['unique_ips']} unique IPs. Hosting breakdown:\n"
    )
    ui.provider_bars(data["providers"], total)
    mark_certificates(data, results)
    show_wildcards(data, results["target"])
    if data["private_ip_hosts"]:
        print()
        warn(
            f"{len(data['private_ip_hosts'])} host(s) point to private/internal IPs "
            "in public DNS (leaks internal network layout):"
        )
        for h in data["private_ip_hosts"]:
            print(f"    {ui.paint(h, ui.YELLOW)}  {', '.join(data['hosts'][h]['private_ips'])}")
    return data


# Sources that list names from TLS certificates. A certificate issued for an
# exact name means someone set that name up on purpose.
CERT_SOURCES = ("crt.sh", "crt.sh database", "certspotter")


def certificate_names(results: dict) -> set[str]:
    """Every hostname a certificate source found this scan (saved copies included)."""
    names = set()
    for r in results.get("sources", {}).values():
        if r.get("source") in CERT_SOURCES:
            names.update(r.get("subdomains", []))
    return names


def mark_certificates(data: dict, results: dict) -> None:
    """Add "with_certificate" to each wildcard: the hosts set aside under it
    that a certificate names. DNS can't tell them from made-up names, but a
    certificate for the exact name says someone set them up, so they're named
    on their own line instead of only in --json."""
    certs = certificate_names(results)
    for zone, w in data.get("wildcards", {}).items():
        w["with_certificate"] = sorted(h for h, z in data.get("wildcard_only", {}).items()
                                       if z == zone and h in certs)


def _zone_label(zone: str, target: str) -> str:
    """"*.acc-nocdn" for a zone under the target, the full "*.zone" otherwise."""
    if target and zone.endswith("." + target):
        return "*." + zone[:-len(target) - 1]
    return "*." + zone


def _list(names: list[str], total: int) -> str:
    more = total - len(names)
    return ", ".join(ui.safe(n) for n in names) + (f" and {more} more" if more > 0 else "")


def show_wildcards(data: dict, target: str = "") -> None:
    """Wildcards that hosts were set aside under (v1.18): one block per answer.

    A CDN wildcard shows up in every subzone (each one answers made-up names
    too), so zones are grouped by what they answer: by provider for a public
    wildcard (a CDN rotates its IPs), by IP set for a private one."""
    if data.get("wildcard_error"):
        print()
        warn(f"Wildcard check skipped: {data['wildcard_error']}.")
    groups = {}
    for zone, w in data.get("wildcards", {}).items():
        if not w["hosts"]:
            continue   # every host there has its own record: nothing set aside
        key = ("private", tuple(w["ips"])) if w["private"] else ("public", w["provider"])
        groups.setdefault(key, []).append((zone, w))
    for (kind, _), zones in groups.items():
        zones.sort(key=lambda zw: (-zw[1]["hosts"], zw[0]))
        first = zones[0][1]
        total = sum(w["hosts"] for _, w in zones)
        if kind == "private":
            what = f"private IPs ({', '.join(first['ips'])})"
        elif len(zones) == 1:
            n = len(first["ips"])
            what = f"{first['provider'] or 'unknown provider'} ({n} IP{'' if n == 1 else 's'})"
        else:
            what = first["provider"] or "unknown provider"
        print()
        if len(zones) == 1:
            warn(f"*.{ui.safe(zones[0][0])} is a wildcard -> {what}: {total} host(s) resolve only through it")
        else:
            warn(f"{len(zones)} zones are wildcards -> {what}: {total} host(s) resolve only through them")
            top = [f"{_zone_label(z, target)} ({w['hosts']})" for z, w in zones[:5]]
            print(f"    Biggest: {_list(top, len(zones))} zones" if len(zones) > 5
                  else f"    Zones: {', '.join(top)}")
        examples = [h for _, w in zones for h in w["examples"]][:5]
        print(f"    Set aside (DNS can't tell them apart from made-up names, full list in --json): "
              f"{_list(examples, total)}")
        certified = sorted(h for _, w in zones for h in w.get("with_certificate", []))
        if certified:
            print(f"    {len(certified)} of them have their own certificate, so they're likely real: "
                  f"{_list(certified[:8], len(certified))}")


def run_ports(results: dict, enrichment: dict, cves_file: str | None) -> None:
    """--ports: ask Shodan InternetDB about every IP from --enrich, print what's exposed."""
    print()
    info("Checking Shodan InternetDB for open ports and known CVEs (passive)...")
    exposure = internetdb.lookup(enrichment, target=results.get("target", ""))
    exposure["collected_at"] = now_utc()
    results["exposure"] = exposure
    if exposure["errors"]:
        warn(f"{exposure['errors']} Shodan lookup(s) failed (results may be incomplete).")
    if exposure["skipped"]:
        edges = exposure.get("skipped_edges", 0)
        own_left = exposure["skipped"] - edges
        if own_left:
            warn(f"Only {internetdb.MAX_OWN_IPS} of the target's own servers were checked "
                 f"({own_left} more skipped, and {edges} CDN edge IPs).")
        else:
            info(f"All {exposure.get('checked_own', exposure['checked'])} of the target's own servers were "
                 f"checked; {edges} CDN edge IPs weren't looked up (their open ports belong to the CDN).")
    print()
    if not exposure["ips"]:
        good(f"Shodan has no open ports on record for the {exposure['checked']} IP(s) checked.")
    else:
        ui.exposure_table(exposure)
        print()
        own = [d for d in exposure["ips"].values() if internetdb.is_own(d)]
        n_cves = len(exposure["unique_cves"])
        good(
            f"{len(own)} IP(s) with open ports, "
            f"{len(exposure['risky'])} with risky services, "
            f"{ui.paint(str(n_cves), ui.BOLD, ui.RED if n_cves else ui.GREEN)} unique CVE(s)"
            + (" (matched from software versions; verify before acting)." if n_cves else ".")
        )
        if exposure["risky"]:
            warn("Services that usually shouldn't face the internet:")
            for ip, risky in exposure["risky"]:
                print(f"    {ui.paint(ip, ui.YELLOW)}  {', '.join(risky)}")
    if cves_file:
        if exposure["unique_cves"]:
            with open(cves_file, "w") as f:
                f.write("\n".join(exposure["unique_cves"]) + "\n")
            good(f"Saved {len(exposure['unique_cves'])} CVEs to {cves_file}. Triage them with: python kaidoku.py --file {cves_file}")
        else:
            info(f"No CVEs found, so {cves_file} wasn't written.")


def load_cli_scope(path: str | None):
    """--scope FILE as a Scope (strict: an unusable file stops the scan), or
    scope.UNSCOPED_CLI when no --scope was given. Returns None to stop."""
    if not path:
        return scope.UNSCOPED_CLI
    s = scope.load(path)
    if s.problem():
        fail(f"--scope: {s.problem()}. Nothing was scanned.")
        return None
    for r in s.rejected:
        warn(f"--scope line {r['line']} ignored: {ui.safe(r['text'])} ({r['reason']})")
    info(f"Scope for active checks: {path} ({len(s.inclusions)} in, "
         f"{len(s.exclusions)} excluded, sha256 {s.sha256[:12]}...)")
    return s


def scope_hosts(tool: str, enrichment: dict, active_scope) -> tuple[dict, list[dict]]:
    """Keep only in-scope hosts for an active check, BEFORE any request.
    Out-of-scope hosts are listed, logged as refused, and never contacted."""
    inside, outside = scope.split(active_scope, sorted(enrichment["hosts"]))
    for o in outside:
        activelog.refused(activelog.PATH, "cli", tool, o["reason"], o["host"], active_scope)
    if outside:
        shown = ", ".join(ui.safe(o["host"]) for o in outside[:10])
        more = f" and {len(outside) - 10} more" if len(outside) > 10 else ""
        warn(f"{len(outside)} host(s) out of scope, no active request sent: {shown}{more}")
    return {**enrichment, "hosts": {h: enrichment["hosts"][h] for h in inside}}, outside


def log_cli_request(tool: str, active_scope, active=None):
    """on_request for the fetch layer: every CLI active request goes to scans/active.log too,
    with the --rate and --research file it went out under."""
    active = active or ActiveRun()
    return lambda host, url, rule: activelog.request(
        activelog.PATH, "cli", tool, host, url, rule, active_scope,
        rate=active.limiter.rate, research=active.research)


class ActiveRun:
    """How this run's active requests go out: one --rate limiter shared by every
    active check (so the cap is a total for the whole run) and the --research file."""

    def __init__(self, limiter=rate.UNLIMITED, research_file=None):
        self.limiter = limiter
        self.research = research_file

    def record(self, out: dict) -> None:
        """Put the settings in a check's results, so the saved scan says how it was sent."""
        out["rate"] = self.limiter.rate
        out["research_sha256"] = research.sha_of(self.research)


# The ACTIVE checks: the only flags that send requests to the target itself.
ACTIVE_FLAGS = "--fingerprint, --probe, --exposed-files or --content"


def any_active(args) -> bool:
    """Is any ACTIVE check on? One place, so a new active check can't be
    left out of one of the places that ask."""
    return bool(args.fingerprint or args.probe or args.exposed_files or args.content)


def load_active_run(args, active_scope):
    """--rate and --research as an ActiveRun, checked before anything is scanned
    (a bad research file stops the run). Returns None to stop."""
    research_file = None
    if args.research:
        try:
            research_file = research.load(args.research)
        except research.ResearchError as e:
            fail(f"--research: {e}. Nothing was scanned.")
            return None
    if not any_active(args):
        if args.rate is not None or research_file:
            info(f"--rate/--research without {ACTIVE_FLAGS}: no active "
                 "request is sent, so they change nothing.")
        return ActiveRun(rate.UNLIMITED, research_file)
    scoped = active_scope is not scope.UNSCOPED_CLI
    chosen = rate.choose(args.rate, scoped)
    if args.rate is None and scoped:
        info(f"Active requests: {chosen:g}/s (the default with --scope; set --rate to change it)")
    elif chosen is not None:
        info(f"Active requests: {chosen:g}/s (--rate)")
    if research_file:
        info(f"Research header on active requests: {ui.safe(research_file.summary)} "
             f"(sha256 {research_file.sha256[:12]}...)")
    return ActiveRun(rate.Limiter(chosen), research_file)


def run_fingerprint(results: dict, enrichment: dict, active_scope, active=None) -> None:
    """--fingerprint: one homepage request per live host, then show what tech it gives away (ACTIVE)."""
    print()
    info("Fingerprinting web servers (active: one homepage request per live host)...")
    allowed, out_of_scope = scope_hosts("--fingerprint", enrichment, active_scope)
    active = active or ActiveRun()
    fp = fingerprint.fingerprint_all(allowed, scope=active_scope,
                                     on_request=log_cli_request("--fingerprint", active_scope, active),
                                     limiter=active.limiter, research=active.research)
    active.record(fp)
    fp["out_of_scope"] = out_of_scope
    fp["collected_at"] = now_utc()
    results["fingerprint"] = fp
    if fp["skipped"]:
        warn(f"Only the first {fingerprint.MAX_HOSTS} hosts were checked ({fp['skipped']} skipped).")
    print()
    for host, r in fp["hosts"].items():
        techs = []
        for t in r["techs"]:
            name = ui.safe(t["tech"])  # headers come from the target: clean them first
            techs.append(ui.paint(name, ui.YELLOW) if t["version"] else name)
        line = ", ".join(techs) or "no clues"
        if "https_error" in r:
            line += f"  (plain HTTP only: HTTPS failed, {r['https_error']})"
        if "location" in r["headers"]:
            line += f"  -> {ui.safe(r['headers']['location'])}"
        print(f"    {host}  [{r['status']}]  {line}")
    print()
    versions = sum(1 for r in fp["hosts"].values() for t in r["techs"] if t["version"])
    good(f"{len(fp['hosts'])}/{fp['checked']} hosts answered"
         + (f", {ui.paint(str(versions), ui.BOLD, ui.YELLOW)} leaked a software version (can be matched to CVEs)." if versions else "."))
    plain = sorted(h for h, r in fp["hosts"].items() if "https_error" in r)
    if plain:
        warn(f"{len(plain)} host(s) only answered over plain HTTP (HTTPS failed): {', '.join(plain)}")
    if fp["errors"]:
        info(f"{len(fp['errors'])} host(s) didn't answer (timeouts, TLS errors, refused).")

    # Security headers: count how many real pages are missing each one
    counts = {}
    for r in fp["hosts"].values():
        for issue in r["header_issues"]:
            counts[issue["header"]] = counts.get(issue["header"], 0) + 1
    pages = sum(1 for r in fp["hosts"].values() if 200 <= r["status"] < 300)
    if counts:
        print()
        warn(f"Security headers missing or weak ({pages} hosts served a real page):")
        for header, n in sorted(counts.items(), key=lambda item: item[1], reverse=True):
            print(f"    {header}: {n}/{pages}")
    elif pages:
        good(f"All {pages} hosts that served a page have the checked security headers.")


def no_title_reason(r: dict) -> str:
    """Why a probed page has no title, so "(no title)" is never a mystery:
    the body wasn't read (and what the server said it was), or what it was."""
    if r["redirect_blocked"] or r["hit_redirect_limit"]:
        return "redirect not followed"
    if r["body_kind"] is None:
        return f"{r['content_type'] or 'no content type'}, not read"
    return {"json": "JSON", "empty": "empty page", "html": "none in the page",
            "other": "not HTML"}[r["body_kind"]]


def run_probe(results: dict, enrichment: dict, active_scope, active=None) -> None:
    """--probe: follow each live host's homepage through its redirects and read the
    final page's title (ACTIVE: one request per hop)."""
    print()
    info("Probing live pages (active: the homepage plus one request per redirect, at most "
         f"{probe.MAX_REQUESTS} per host if HTTPS fails and it retries over plain HTTP)...")
    allowed, out_of_scope = scope_hosts("--probe", enrichment, active_scope)
    active = active or ActiveRun()
    pr = probe.probe_all(allowed, scope=active_scope,
                         on_request=log_cli_request("--probe", active_scope, active),
                         limiter=active.limiter, research=active.research)
    active.record(pr)
    pr["out_of_scope"] = out_of_scope
    pr["collected_at"] = now_utc()
    results["probe"] = pr
    if pr["skipped"]:
        warn(f"Only the first {probe.MAX_HOSTS} hosts were checked ({pr['skipped']} skipped).")
    print()
    for host, r in sorted(pr["hosts"].items()):
        # titles, URLs and content types come from the target: clean them first
        title = (ui.safe(r["title"]) if r["title"]
                 else ui.paint(f"(no title: {ui.safe(no_title_reason(r))})", ui.GREY))
        line = f"    {ui.safe(host)}  [{r['status']}]  {title}"
        if r["chain"]:
            line += f"  -> {ui.safe(r['final_url'])} ({len(r['chain'])} redirect(s))"
        print(line)
        notes = []
        if r["redirect_blocked"]:
            why = probe.BLOCK_REASONS[r["redirect_blocked_reason"]]
            notes.append(f"redirect {why}, not followed: {ui.safe(r['redirect_blocked'])}")
        if r["hit_redirect_limit"]:
            notes.append(f"still redirecting after {probe.MAX_REDIRECTS} hops, stopped")
        if r["body_kind"] == "json":
            notes.append(f"body is JSON but labeled {ui.safe(r['content_type'])}")
        if "https_error" in r:
            notes.append(f"plain HTTP only: HTTPS failed, {r['https_error']}")
        for note in notes:
            print(f"        {ui.paint(note, ui.YELLOW)}")
    print()
    redirected = sum(1 for r in pr["hosts"].values() if r["chain"])
    good(f"{len(pr['hosts'])}/{pr['checked']} hosts answered"
         + (f", {redirected} redirected elsewhere." if redirected else ".")
         + f" {pr['requests']} request(s) sent.")
    blocked = sorted(h for h, r in pr["hosts"].items() if r["redirect_blocked"])
    if blocked:
        warn(f"{len(blocked)} host(s) had a redirect Monomi refused to follow: {', '.join(blocked)}")
    if pr["errors"]:
        info(f"{len(pr['errors'])} host(s) didn't answer (timeouts, TLS errors, refused).")


def run_exposed(results: dict, enrichment: dict, active_scope, active=None) -> None:
    """--exposed-files: look for public API specs and JS source maps (ACTIVE)."""
    print()
    info("Checking for exposed API specs and source maps "
         "(active: a few requests per live host)...")
    allowed, out_of_scope = scope_hosts("--exposed-files", enrichment, active_scope)
    active = active or ActiveRun()
    ex = exposed.check_all(allowed, scope=active_scope,
                           on_request=log_cli_request("--exposed-files", active_scope, active),
                           limiter=active.limiter, research=active.research)
    active.record(ex)
    ex["out_of_scope"] = out_of_scope
    results["exposed_files"] = ex
    if ex["skipped"]:
        warn(f"Only the first {exposed.MAX_HOSTS} hosts were checked ({ex['skipped']} skipped).")
    print()
    specs = maps = 0
    for host, f in sorted(ex["hosts"].items()):
        s = f["spec"]
        if s:
            specs += 1
            auth = ", declares auth" if s["declares_auth"] else ""
            # host, url and server names come from the target: clean before printing
            print(f"    {ui.safe(host)}  {ui.paint(s['type'] + ' spec', ui.YELLOW)} "
                  f"at {ui.safe(s['url'])}  ({s['endpoint_count']} endpoints{auth})")
            for srv in s["servers"]:
                print(f"        names server: {ui.safe(srv)}")
        for m in f["source_maps"]:
            maps += 1
            code = ui.paint(" + source code", ui.BOLD, ui.YELLOW) if m["has_source_content"] else ""
            print(f"    {ui.safe(host)}  {ui.paint('source map', ui.YELLOW)} "
                  f"at {ui.safe(m['map_url'])}  ({m['source_count']} files{code})")
    if specs or maps:
        good(f"{specs} API spec(s) and {maps} source map(s) exposed "
             f"across {len(ex['hosts'])} host(s).")
    else:
        good(f"No exposed API specs or source maps on the {ex['checked']} host(s) checked.")
    # What "nothing found" covers on each clean host (v1.23)
    for host, c in sorted(ex.get("coverage", {}).items()):
        if host in ex["hosts"] or not c:
            continue
        sp = c["spec_paths"]
        if c.get("scheme") is None and "scheme" in c:
            print(f"    {ui.safe(host)}  checked: homepage {c['homepage']} over HTTPS"
                  + (" or plain HTTP" if c.get("https_error") else "") + ", so nothing else was sent")
            continue
        over = f" over plain HTTP (HTTPS failed: {c['https_error']})" if c.get("scheme") == "http" else ""
        print(f"    {ui.safe(host)}  checked{over}: {sp['answered']}/{sp['tried']} spec paths answered, "
              f"homepage {c['homepage']}, {c['scripts_and_maps']} script(s) and map(s)")


def run_email(results: dict, domain: str) -> None:
    """--email: can someone send mail pretending to be this domain? (DNS lookups only)"""
    print()
    info("Checking email spoofing protection (SPF, DMARC, DKIM; DNS lookups only)...")
    try:
        report = emailauth.check_email(domain)
    except emailauth.DNSLookupError as e:
        # Not in results["errors"]: that would stop change detection saving a good host list
        results["email"] = {"error": str(e)}
        fail(f"Email check failed: {e}")
        return
    report["collected_at"] = now_utc()
    results["email"] = report

    print()
    for label, key in (("SPF", "spf"), ("DMARC", "dmarc"), ("DKIM", "dkim")):
        r = report[key]
        record = ui.safe(r["record"]) if r["record"] else "none found"
        print(f"    {label:<6} {record}")
        for issue in r["issues"]:
            print(f"           {ui.paint(issue['problem'], ui.YELLOW)}: {ui.safe(issue['detail'])}")

    print()
    v = report["verdict"]
    if v["verdict"] == "protected":
        good(f"Email spoofing: {ui.paint('PROTECTED', ui.BOLD, ui.GREEN)}. {v['summary']}")
    elif v["verdict"] == "partial":
        warn(f"Email spoofing: {ui.paint('PARTIAL', ui.BOLD, ui.YELLOW)}. {ui.safe(v['summary'])}")
    else:
        warn(f"Email spoofing: {ui.paint('SPOOFABLE', ui.BOLD, ui.RED)}. {v['summary']}")
    for note in v["notes"]:
        info(note)


def run_takeover(results: dict) -> None:
    """--takeover: CNAMEs pointing at deleted third-party resources (DNS lookups only)."""
    hosts = results["subdomains"]
    print()
    info(f"Checking {len(hosts)} hosts for dangling CNAMEs / subdomain takeover (DNS lookups only)...")
    # an extra host is judged by its own name: a CNAME under the scanned domain
    # isn't "same domain" for it (that only holds for the target's own hosts)
    own = {h: h for h in extra_set(results)}
    report = takeover.check_hosts(hosts, domain=results["target"], **({"domains": own} if own else {}))
    report["collected_at"] = now_utc()
    results["takeover"] = report

    print()
    for lead in report["leads"]:
        host = ui.safe(lead["host"])
        cname = ui.safe(lead["cname"])
        if lead["claimable"]:
            warn(f"{ui.paint('TAKEOVER LEAD', ui.BOLD, ui.RED)}  {host} -> {cname}  "
                 f"({lead['service']}: target deleted, name may be claimable)")
        else:
            warn(f"{ui.paint('DANGLING CNAME', ui.BOLD, ui.YELLOW)}  {host} -> {cname}  "
                 f"(target no longer exists)")
    for record in report["stale"]:
        host = ui.safe(record["host"])
        cname = ui.safe(record["cname"])
        info(f"{ui.paint('STALE', ui.BOLD, ui.GREY)}  {host} -> {cname}  "
             f"({record['service']}: target deleted, {record['reason']})")
    for d in report.get("ns_delegations", []):
        cut = ui.safe(d["cut"])
        n = len(d["hosts"])
        if d["grade"] == "theoretical":
            info(f"{ui.paint('LAME DELEGATION', ui.BOLD, ui.GREY)}  {cut}  ({n} host(s); nameservers "
                 f"on {d['provider']} refuse it: reclaiming them is impractical)")
        else:
            warn(f"{ui.paint('LAME DELEGATION', ui.BOLD, ui.YELLOW)}  {cut}  ({n} host(s); nameservers "
                 "refuse it and weren't recognized: check whether they can be claimed)")
    # a lame host did get an answer (a broken delegation, listed above), so
    # only the other errors are hosts that couldn't be checked
    lame = sum(len(d["hosts"]) for d in report.get("ns_delegations", []))
    rest = len(report["errors"]) - lame
    if rest:
        warn(f"{rest} host(s) couldn't be checked (DNS didn't answer).")
    if not report["leads"]:
        checked = report["checked"] - rest
        good(f"No takeover leads among {checked} hosts checked.")
    show_wildcard_takeover_note(results)


SEVERITY_COLOR = {"secrets": ui.RED, "source": ui.YELLOW, "info": ui.WHITE}


def run_content(results: dict, enrichment: dict, active_scope, active=None, extra=None) -> None:
    """--content: content discovery on every live in-scope host (ACTIVE)."""
    print()
    per_host = content.max_requests(len(extra or []))
    rate_note = f", at {active.limiter.rate:g}/s" if active and active.limiter.rate else ""
    info(f"Content discovery: {len(content.PATHS) + len(extra or [])} paths per live host, "
         f"at most {per_host} requests each{rate_note}. A file counts only when its content "
         "is the real thing...")
    allowed, out_of_scope = scope_hosts("--content", enrichment, active_scope)
    active = active or ActiveRun()
    cd = content.check_all(allowed, scope=active_scope, extra=extra,
                           on_request=log_cli_request("--content", active_scope, active),
                           limiter=active.limiter, research=active.research)
    active.record(cd)
    cd["out_of_scope"] = out_of_scope
    results["content"] = cd
    if cd["skipped"]:
        warn(f"Only the first {content.MAX_HOSTS} hosts were checked ({cd['skipped']} skipped).")
    print()
    for host, r in sorted(cd["hosts"].items()):
        # hosts, paths and locations come from the target: clean before printing
        if r["scheme"] is None:
            print(f"    {ui.safe(host)}  no answer over HTTPS" +
                  (" or plain HTTP" if r["https_error"] else "") + ", so nothing else was sent")
            continue
        over = f" over plain HTTP (HTTPS failed: {r['https_error']})" if r["scheme"] == "http" else ""
        print(f"    {ui.paint(ui.safe(host), ui.BOLD)}  {r['tried']} paths tried{over}, {r['requests']} requests")
        for f in r["found"]:
            tag = ui.paint(f["severity"], SEVERITY_COLOR[f["severity"]])
            print(f"        {tag}  {ui.safe(f['path'])}: {ui.safe(f['what'])}")
        for lead in r["leads"][:content.LEADS_SHOWN]:
            dropped = ", its query not kept" if lead.get("location_query_dropped") else ""
            extra_bit = (f" -> {ui.safe(lead['location'])} (not followed{dropped})" if lead.get("location")
                         else f" ({ui.safe(lead['auth'])} login)" if lead.get("auth") else "")
            print(f"        {ui.paint('lead', ui.GREY)}  {ui.safe(lead['path'])}: {lead['status']}{extra_bit}")
        if len(r["leads"]) > content.LEADS_SHOWN:
            print(f"        ... and {len(r['leads']) - content.LEADS_SHOWN} more lead(s) in the saved scan")
        if r["untrusted"]:
            print(f"        {ui.paint('skipped', ui.GREY)}  a made-up path passed the "
                  f"{', '.join(r['untrusted'])} check(s), so those weren't trusted here")
        if r["stopped"]:
            warn(f"{ui.safe(host)}: stopped early: {ui.safe(r['stopped'])}")
    if cd["found"]:
        good(f"{cd['found']} exposed file(s) and {cd['leads']} lead(s) across {cd['checked']} host(s).")
    else:
        good(f"No exposed files on the {cd['checked']} host(s) checked"
             + (f"; {cd['leads']} lead(s) to look at." if cd["leads"] else "."))


def show_wildcard_takeover_note(results: dict) -> None:
    """Names set aside under a wildcard (v1.18) always resolve, so DNS can
    never show one as dangling: say so, instead of letting them read as clean.
    Only known with --enrich, which runs the wildcard check."""
    under = results.get("enrichment", {}).get("wildcard_only", {})
    if not under:
        return
    zones = sorted(set(under.values()))
    shown = ", ".join("*." + ui.safe(z) for z in zones[:3])
    more = f" and {len(zones) - 3} more" if len(zones) > 3 else ""
    results["takeover"]["under_wildcard"] = len(under)
    info(f"{len(under)} name(s) resolve only through a wildcard ({shown}{more}): "
         "names under a wildcard can't be checked for takeover by DNS alone.")


def show_import_findings(sf: dict) -> None:
    """Print what SpiderFoot flagged (unverified leads)."""
    print()
    warn("SpiderFoot flagged these (unverified; the AI report weighs them):")
    for fnd in sf["findings"]:
        # SpiderFoot data comes from third parties: clean it before it hits the terminal
        first_line = ui.safe((fnd["data"].splitlines() or ["(no data)"])[0])
        print(f"    {ui.paint(ui.safe(fnd['type']), ui.YELLOW)}  {first_line}  ({ui.safe(fnd['module'])})")


def baseline_gaps(results: dict) -> list[str]:
    """Failed sources that leave a real gap in the hostname list.

    The crt.sh website and database hold the same data, so one of them
    failing while the other worked loses nothing.
    """
    # A saved copy doesn't count: it's old data standing in for a failed source
    crtsh_ok = any(name in results["sources"] and not results["sources"][name].get("from_saved")
                   for name in FULL_HISTORY_SOURCES)
    return [name for name in results["errors"]
            if not (name in FULL_HISTORY_SOURCES and crtsh_ok)]


def gap_reason(results: dict, gaps: list[str]) -> str:
    """Why these sources left a gap, in words: which failed, which are only behind."""
    behind = [g for g in gaps if results["errors"][g].startswith(CRTSH_BEHIND)]
    failed = [g for g in gaps if g not in behind]
    parts = []
    if failed:
        parts.append(f"{', '.join(failed)} failed")
    if behind:
        verb = "is" if len(behind) == 1 else "are"
        parts.append(f"{', '.join(behind)} {verb} behind on the CT logs")
    return " and ".join(parts)


def history_input(results: dict) -> tuple[dict, dict, dict]:
    """Sort this scan's sources for history.

    Returns (fresh, partial, notes):
      fresh:   history source -> hosts, when it worked fully
      partial: history source -> hosts, when it was cut short
      notes:   history source -> why it isn't fresh, in words
    A saved copy (from_saved) never counts as working: it's old data
    standing in for a failure.
    """
    fresh, partial, notes = {}, {}, {}
    for name, keys in HISTORY_SOURCES.items():
        worked = [results["sources"][k] for k in keys
                  if k in results["sources"] and not results["sources"][k].get("from_saved")
                  and DISPLAY_NAMES.get(k, k) not in results.get("errors", {})]
        hosts = sorted({h for r in worked for h in r["subdomains"]})
        if any(not r.get("partial") for r in worked):
            fresh[name] = hosts
        elif worked:
            partial[name] = hosts
            notes[name] = f"{HISTORY_LABELS[name]} {worked[0]['partial']}"
        else:
            jobs = [DISPLAY_NAMES.get(k, k) for k in keys if DISPLAY_NAMES.get(k, k) in results.get("errors", {})]
            if jobs:  # (a source that never ran, as in tests, has nothing to say)
                notes[name] = gap_reason(results, jobs)
    return fresh, partial, notes


def show_changes(results: dict) -> None:
    """Compare with the last scan of this domain, then save this one.

    History keeps a list per source. A source that failed or was cut short
    keeps (part of) its last list, so it can't make hosts look gone, and a
    source that's new to this domain starts from what it finds, so it can't
    make hosts look new. So every scan is saved, even an incomplete one.
    """
    domain = results["target"]
    fresh, partial, notes = history_input(results)
    previous = history.load_last(domain)
    entries = history.build(previous, fresh, partial)
    print()
    if not entries:
        warn(f"{'; '.join(notes.values())}: no source worked, so there's nothing to save to history.")
        return
    saved_path = history.save(domain, entries)
    if previous is None:
        info(f"First scan of {domain} - saved as baseline ({short_path(saved_path)})")
        if notes:
            warn(f"Not complete: {'; '.join(notes.values())}. Later scans fill in what "
                 f"{'it' if len(notes) == 1 else 'they'} missed, listed apart from new hosts.")
        return

    changes = history.compare(previous, entries)
    results["changes"] = changes
    info(f"Changes since last scan ({changes['previous_scan']}):")
    if not changes["added"] and not changes["removed"]:
        print("    No changes.")
    for sub in changes["added"]:
        print(f"    {ui.paint('[NEW] ', ui.GREEN)} {sub}")
    for sub in changes["removed"]:
        print(f"    {ui.paint('[GONE]', ui.RED)} {sub}")
    for name, hosts in changes["filled_in"].items():
        info(f"{HISTORY_LABELS.get(name, name)} was cut short last scan, so {len(hosts)} hostname"
             f"{'' if len(hosts) == 1 else 's'} it lists now may not be new:")
        for sub in hosts:
            print(f"    {ui.paint('[FILL]', ui.YELLOW)} {sub}")
    for name, hosts in changes["joined"].items():
        info(f"{HISTORY_LABELS.get(name, name)} joins this domain's history: {len(hosts)} hostname"
             f"{'' if len(hosts) == 1 else 's'} only it found {'is' if len(hosts) == 1 else 'are'} "
             "its starting point, not marked new.")
    if notes:
        one = len(notes) == 1
        warn(f"Not complete: {'; '.join(notes.values())}. Hosts {'that source' if one else 'those sources'} "
             f"saw last time are kept, so none is marked gone because of {'it' if one else 'them'}.")


def show_paths(results: dict) -> None:
    """Attack paths built by code: shown on every scan that ran a check, no AI needed."""
    if not any(k in results for k in ("enrichment", "email", "takeover", "exposure", "fingerprint")):
        return  # discovery only: too little to chain, so "no path found" would mislead
    built = results["paths"]
    print()
    info("Attack paths (worked out by code: how an attack would most likely go, not proof):")
    print()
    leads = built.get("leads", [])
    if not built["paths"] and not leads:
        good("No attack path found: none of the findings chain into a way in.")
        show_set_aside(built)
        return
    if not built["paths"]:
        good(f"No attack path found, {len(leads)} lead{'' if len(leads) == 1 else 's'} to investigate.")
        print()
    colors = {"High": ui.RED, "Medium": ui.YELLOW, "Low": ui.GREY}
    for p in built["paths"]:
        badge = ui.paint(p["severity"].upper(), ui.BOLD, colors[p["severity"]])
        print(f"    {p['id']}  {badge}  {ui.safe(p['title'])}  "
              f"(weakest step: {p['strength']} · {gate.describe(p.get('gate'))})")
        for n, s in enumerate(p["steps"], 1):
            print(f"        {n}. {ui.paint(s['label'], ui.GREY)}: {ui.safe(s['text'])}")
        print(f"        => {ui.safe(p['outcome'])}")
        for note in (p.get("gate") or {}).get("notes", []):
            print(f"        {ui.paint('Note:', ui.GREY)} {ui.safe(note)}")
        print()
    if built["more"]:
        info(f"{built['more']} lower-ranked path(s) not shown.")
    fix = built["fix_first"]
    if fix:
        t = paths.fix_first_parts(fix)
        warn(f"{t['label']} ({t['owners']}): {ui.safe(t['what'])} -> {t['closes']}")
    if leads:
        if fix:
            print()
        info("Leads to investigate (not attack paths: each is missing something that would make it one):")
        print()
    for i, group in enumerate(lead_groups(leads)):
        if i:
            print()  # between leads, not after the last one (the caller adds its own gap)
        if len(group) > 1:
            show_cdn_group(group)
            continue
        p = group[0]
        print(f"    {p['id']}  {ui.paint('LEAD', ui.BOLD, ui.GREY)}  {ui.safe(p['title'])}  "
              f"({gate.describe(p.get('gate'))})")
        for n, s in enumerate(p["steps"], 1):
            print(f"        {n}. {ui.paint(s['label'], ui.GREY)}: {ui.safe(s['text'])}")
        print(f"        Missing: {ui.safe(p['missing'])}")
        for note in (p.get("gate") or {}).get("notes", []):
            print(f"        {ui.paint('Note:', ui.GREY)} {ui.safe(note)}")
    if built.get("more_leads"):
        print()
        cut = built.get("more_leads_hosts", [])
        about = f" About: {', '.join(cut[:10])}" + (f" and {len(cut) - 10} more" if len(cut) > 10 else "")
        info(f"{built['more_leads']} more lead(s) not shown.{ui.safe(about) if cut else ''}")
    show_set_aside(built)


def lead_groups(leads: list[dict]) -> list[list[dict]]:
    """Leads in print order, with go-around-the-CDN leads about the same CDN
    hosts grouped together (v1.18). Each lead keeps its own id and data, so
    Akashi still proves them one origin server at a time; only the terminal
    shows them as one block, placed where the first of them would be."""
    groups, at = [], {}
    for p in leads:
        t = p.get("targets") or {}
        if p.get("rule") == "around_cdn" and t.get("fronted"):
            key = (tuple(t["fronted"]), t.get("cdn"))
            if key in at:
                groups[at[key]].append(p)
                continue
            at[key] = len(groups)
        groups.append([p])
    return groups


def id_span(ids: list[str]) -> str:
    """"L1-L4" for a run of ids, "L1, L3, L6" otherwise."""
    nums = [int(i[1:]) for i in ids]
    if nums == list(range(nums[0], nums[0] + len(nums))):
        return f"{ids[0]}-{ids[-1]}"
    return ", ".join(ids)


def show_cdn_group(group: list[dict]) -> None:
    """Several go-around-the-CDN leads about the same CDN hosts, as one block:
    the CDN hosts once, then one line per origin server with its own lead id."""
    t = group[0]["targets"]
    who = paths._names(t["fronted"])
    n_front = len(t["fronted"])
    cdn = t.get("cdn") or "the CDN"
    print(f"    {id_span([p['id'] for p in group])}  {ui.paint('LEADS', ui.BOLD, ui.GREY)}  "
          f"Check whether {n_front} host{'' if n_front == 1 else 's'} behind {cdn} can be reached "
          f"around it through one of {len(group)} servers  ({gate.describe(group[0].get('gate'))})")
    print(f"        {ui.paint('Observed', ui.GREY)}: {ui.safe(who)} "
          f"{'is' if n_front == 1 else 'are'} behind {cdn}, which filters traffic before it reaches "
          "the real server")
    print(f"        {ui.paint('Observed', ui.GREY)}: these servers answer web requests with no CDN in front:")
    width = max(len(p["id"]) for p in group)
    for p in group:
        pt = p["targets"]
        ip = (pt.get("ips") or ["?"])[0]
        print(f"          {p['id'].ljust(width)}  {ip:<16} <- {ui.safe(paths._names(pt.get('hosts') or []))}")
        for note in (p.get("gate") or {}).get("notes", []):
            print(f"          {' ' * width}  {ui.paint('Note:', ui.GREY)} {ui.safe(note)}")
    print(f"        {ui.paint('Inference', ui.GREY)}: if one of them is also the server behind these hosts, "
          f"an attacker can send requests to it directly and skip {cdn}'s protection")
    print(f"        Missing: nothing shows that any of these servers is the one behind {ui.safe(who)} "
          "(a CDN hides its origin from outside)")


def show_set_aside(built: dict) -> None:
    """What the validation gate set aside: out of scope, or not the target's own,
    and how many out-of-scope hosts the rules left out of their evidence."""
    if built.get("out_of_scope_hosts"):
        print()
        info(ui.safe(paths.out_of_scope_line(built["out_of_scope_hosts"])))
    items = built.get("set_aside", [])
    if not items:
        return
    print()
    info("Set aside (out of scope or not the target's own: neither attack paths nor leads):")
    for why, group in paths.group_by_why(items):
        if len(group) == 1:
            print(f"    - {ui.safe(group[0]['title'])}: {ui.safe(why)}")
            continue
        for p in group:
            print(f"    - {ui.safe(p['title'])}")
        print(f"      (all {len(group)}: {ui.safe(why)})")
    if built.get("more_set_aside"):
        info(f"{built['more_set_aside']} more set aside, not shown.")


def show_next_checks(results: dict, cves_saved: bool = False) -> None:
    """Checks worth running next, with the reason from this scan. Never runs one."""
    checks = suggest.next_checks(results, cves_saved)
    results["next_checks"] = checks  # saved with --json, so a script or agent can read them
    if not checks:
        return
    print()
    info("Next checks worth running (suggestions only: nothing runs unless you add the flag):")
    print()
    width = max(len(c["flag"]) for c in checks)
    for c in checks:
        active = "ACTIVE, sends requests to the target: " if c["active"] else ""
        print(f"    {c['flag']:<{width}}  {active}{ui.safe(c['why'])}")


def write_ai_report(results: dict) -> None:
    """--ai: have Claude write the report, save it to reports/, and show it in the terminal."""
    print()
    info("Asking Claude to analyze the results...")
    try:
        from monomi import analysis  # only loaded with --ai, so plain scans don't need the anthropic package
        summary, model = analysis.summarize(results)
    except Exception as e:  # missing key, network, API errors
        fail(f"AI summary failed: {e}")
        return
    # Kept with the results, so --export and a later --json save include it
    results["ai_report"] = {"text": summary, "model": model}

    domain = results["target"]
    os.makedirs(REPORTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    path = os.path.join(REPORTS_DIR, f"{domain}_{stamp}.md")
    header = (
        f"# mønømi report: {domain}\n\n"
        f"*Generated {datetime.now():%Y-%m-%d %H:%M} · "
        f"sources: {', '.join(results['sources'])} · "
        f"{len(results['subdomains'])} hostnames"
        f"{' · enriched' if 'enrichment' in results else ''}"
        f"{' · Shodan InternetDB' if 'exposure' in results else ''} · model: {model}*\n\n"
    )
    path_list = paths.paths_appendix(results["paths"])
    with open(path, "w") as f:
        # The evidence list also covers facts cited only by the code-built paths
        f.write(header + summary + "\n\n" + evidence.evidence_appendix(summary + path_list, results["evidence"])
                + "\n" + path_list)
    print()
    ui.render_report(summary)
    print()
    good(f"Report saved to {short_path(path)}")
    unknown = evidence.check_citations(summary, results["evidence"])
    if unknown:
        warn(f"The AI cited evidence that doesn't exist: {', '.join(unknown)}. "
             "Treat those findings with caution.")
    else:
        good("Every evidence ID the AI cited exists.")
    missing, made_up = paths.check_paths(summary, results["paths"])
    if missing:
        warn(f"The AI left out attack path(s) or lead(s) {', '.join(missing)}. See the list at the end of the report.")
    if made_up:
        warn(f"The AI named attack path(s) or lead(s) that don't exist: {', '.join(made_up)}. Treat them with caution.")
    if not missing and not made_up:
        good("The report covers every attack path and lead and adds none.")


def export_reports(results: dict, formats: list[str]) -> None:
    """--export: save the report as Markdown, HTML and/or a findings CSV."""
    print()
    for path in report.save(results, formats, datetime.now()):
        good(f"Report saved to {short_path(path)}")


def save_json(results: dict, path: str) -> None:
    """--json: save every result to a file, starting with which Monomi made it
    ("monomi_version"), so other tools can tell what fields to expect."""
    saved = {"monomi_version": VERSION, **{k: v for k, v in results.items() if k != "monomi_version"}}
    with open(path, "w") as f:
        json.dump(saved, f, indent=2)
    print()
    good(f"Saved results to {path}")


def show_investigation(r: dict) -> None:
    """Print one investigate() result: the facts, then the labels."""
    net = r["network"] or {}
    print()
    print(f"    Network   {ui.safe(net.get('as_name', 'unknown'))} ({net.get('asn', '?')}), "
          f"registered in {ui.safe(net.get('country', '?'))}")
    print(f"    rDNS      {ui.safe(r['rdns']) if r['rdns'] else 'none'}")
    shodan = r["shodan"]
    if shodan:
        ports = ", ".join(str(p) for p in shodan["ports"]) or "none"
        cves = f", {len(shodan['vulns'])} CVEs" if shodan["vulns"] else ""
        print(f"    Shodan    open ports {ports}{cves}")
    elif "shodan" not in r["errors"]:
        print("    Shodan    nothing on record")

    print()
    for lb in r["labels"]:
        text = f"{ui.paint(lb['label'].upper(), ui.BOLD, ui.RED)}  {ui.safe(lb['reason'])}  [{lb['source']}]"
        if lb["label"] in threatintel.ANONYMIZERS or lb["label"] == "known_bad":
            warn(text)
        else:
            info(text)
    for source, err in r["errors"].items():
        fail(f"{source} lookup failed: {ui.safe(err)}")


def write_ip_report(results: dict) -> None:
    """--investigate-ip --ai: Claude's verdict, saved to reports/ and shown in the terminal."""
    print()
    info("Asking Claude for a verdict...")
    try:
        from monomi import analysis  # only loaded with --ai
        verdict, model = analysis.ip_verdict(results)
    except Exception as e:  # missing key, network, API errors
        fail(f"AI verdict failed: {e}")
        return

    ips = list(results["ips"])
    name = ips[0].replace(":", "-")  # IPv6 colons aren't allowed in Windows file names
    if len(ips) > 1:
        name += f"_and_{len(ips) - 1}_more"
    os.makedirs(REPORTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    path = os.path.join(REPORTS_DIR, f"ip_{name}_{stamp}.md")
    header = (
        f"# mønømi IP report: {', '.join(ips)}\n\n"
        f"*Generated {datetime.now():%Y-%m-%d %H:%M} · "
        f"sources: Tor exit list, Team Cymru ASN, reverse DNS, Shodan InternetDB · model: {model}*\n\n"
    )
    with open(path, "w") as f:
        f.write(header + verdict + "\n\n" + evidence.evidence_appendix(verdict, results["evidence"]))
    print()
    ui.render_report(verdict)
    print()
    good(f"Report saved to {short_path(path)}")
    unknown = evidence.check_citations(verdict, results["evidence"])
    if unknown:
        warn(f"The AI cited evidence that doesn't exist: {', '.join(unknown)}. "
             "Treat those findings with caution.")
    else:
        good("Every evidence ID the AI cited exists.")


def run_investigate(raw_ips: list[str], json_file: str | None, ai: bool) -> int:
    """--investigate-ip: what kind of IP is this? (asks public sources, never the IP)"""
    ips = []
    for raw in raw_ips:
        ip = threatintel.clean_ip(raw)
        if ip is None:
            fail(f"'{ui.safe(raw)}' can't be investigated: {threatintel.reject_reason(raw)}")
            return 1
        if ip not in ips:
            ips.append(ip)  # skip repeats, keep the order they were typed in
    if len(ips) > MAX_INVESTIGATE:
        fail(f"{len(ips)} IPs is too many for one run (max {MAX_INVESTIGATE})")
        return 1

    results = {"mode": "investigate_ip", "ips": {}}
    for ip in ips:
        print()
        info(f"Investigating {ui.paint(ip, ui.BOLD, ui.WHITE)} (public sources only, nothing is sent to the IP)...")
        r = threatintel.investigate(ip)
        results["ips"][ip] = r
        show_investigation(r)

    results["evidence"] = threatintel.build_evidence(results)
    if ai:
        write_ip_report(results)
    if json_file:
        save_json(results, json_file)
    return 0


def main() -> int:
    # "doctor" is a command, not a domain (a domain always has a dot)
    if sys.argv[1:2] == ["doctor"]:
        return doctor.main(sys.argv[2:])
    # "report FILE": export a saved --json scan again, without scanning
    if sys.argv[1:2] == ["report"]:
        return report.main(sys.argv[2:])
    # "approve RID --scope FILE": a person's typed yes for active checks an agent asked for
    if sys.argv[1:2] == ["approve"]:
        from monomi import approvals
        return approvals.main(sys.argv[2:])
    # "mcp keys": save this terminal's API keys for the MCP server (600 file)
    if sys.argv[1:3] == ["mcp", "keys"]:
        from monomi import keys
        return keys.main(sys.argv[3:])
    # "mcp setup": add Monomi to the Claude app's MCP config
    if sys.argv[1:2] == ["mcp"]:
        return mcp_setup.main(sys.argv[2:])

    parser = build_parser()
    args = parser.parse_args()
    if args.no_color:
        ui.disable()
    print(ui.banner())

    # --investigate-ip is its own mode: IPs in, no domain scan
    if args.investigate_ip:
        if args.domain or args.import_file:
            parser.error("--investigate-ip works on its own: don't pass a domain or --import with it")
        if args.export:
            parser.error("--export works on domain scans, not --investigate-ip")
        return run_investigate(args.investigate_ip, args.json, args.ai)

    # --scope: checked before anything is scanned, so a bad file costs nothing
    if args.scope and not any_active(args):
        info(f"--scope without {ACTIVE_FLAGS}: no active request is sent, "
             "so it only sets aside attack paths through hosts it doesn't allow.")
    active_scope = load_cli_scope(args.scope)
    if active_scope is None:
        return 1
    active = load_active_run(args, active_scope)
    if active is None:
        return 1
    # --wordlist: read and checked before anything is scanned, like --scope
    extra_paths = None
    if args.wordlist:
        if not args.content:
            info("--wordlist without --content: no path is requested, so it changes nothing.")
        else:
            try:
                extra_paths = content.load_wordlist(args.wordlist)
            except content.WordlistError as e:
                fail(f"--wordlist: {e}.")
                return 1

    if args.ports and not args.enrich:
        args.enrich = True  # Shodan lookups need IP addresses, which --enrich provides
    if args.fingerprint and not args.enrich:
        args.enrich = True  # we only fingerprint hosts that resolve, which --enrich tells us
    if args.exposed_files and not args.enrich:
        args.enrich = True  # same: we only check hosts that resolve to a public IP
    if args.probe and not args.enrich:
        args.enrich = True  # same: we only probe hosts that resolve to a public IP
    if args.content and not args.enrich:
        args.enrich = True  # same: content discovery only reaches hosts with a public IP
    if args.cves and not args.ports:
        warn("--cves only works together with --ports; ignoring it.")

    # --import: load the SpiderFoot export first, since it tells us the target domain
    sf = None
    if args.import_file:
        sf = load_import(args.import_file)
        if sf is None:
            return 1
        if not args.domain:
            args.domain = sf["target"]
    if not args.domain:
        parser.error("a domain is required (or use --import FILE)")
    try:
        domain = clean_domain(args.domain)
    except ValueError as e:
        fail(str(e))
        return 1
    if sf and not import_matches(sf, domain, args.import_file):
        return 1

    # 1. Collect hostnames
    results = {"target": domain, "sources": {}, "errors": {}}
    info(f"Target: {ui.paint(domain, ui.BOLD, ui.WHITE)}")
    if sf:
        add_import(results, sf, args.import_file)
    else:
        collect_ct(results, domain)
    if args.hosts and not add_hosts_file(results, args.hosts, domain):
        return 1
    if args.subfinder and not add_subfinder(results, args.subfinder, domain):
        return 1
    if args.bbot and not add_bbot(results, args.bbot, domain):
        return 1
    if args.extra_hosts and not add_extra_hosts(results, args.extra_hosts, domain, active_scope):
        return 1

    if not any(r["subdomains"] for r in results["sources"].values()):
        if sf:
            fail(f"No hostnames for {domain} found in the SpiderFoot export.")
        elif results["errors"]:
            fail("All subdomain sources failed. They're free services - try again in a few minutes.")
        else:
            fail(f"No certificates found for {domain}. Check the spelling, or the domain may not use TLS.")
        return 1

    all_subs = sorted({s for r in results["sources"].values() for s in r["subdomains"]})
    results["subdomains"] = all_subs
    print()
    good(f"{ui.paint(str(len(all_subs)), ui.BOLD, ui.WHITE)} unique hostnames total:\n")

    # 2. Optional enrichment
    if args.enrich:
        data = run_enrich(results, args.ports)
        if args.ports:
            run_ports(results, data, args.cves)
        if args.fingerprint:
            run_fingerprint(results, data, active_scope, active)
        if args.probe:
            run_probe(results, data, active_scope, active)
        if args.exposed_files:
            run_exposed(results, data, active_scope, active)
        if args.content:
            run_content(results, data, active_scope, active, extra_paths)
    else:
        for sub in all_subs:
            print(f"    {sub}")

    # Email spoofing check: DNS lookups on the domain itself, so it doesn't need --enrich
    if args.email:
        run_email(results, domain)

        # Takeover check: DNS lookups on every hostname, so it doesn't need --enrich
    if args.takeover:
        run_takeover(results)

    if sf and sf["findings"]:
        show_import_findings(sf)

    # 3. Change detection (live scans only: an import has no history to compare)
    if not sf:
        show_changes(results)

    # 4. Evidence, AI report, JSON
    results["evidence"] = evidence.build_evidence(results)
    # The validation gate sets aside paths through hosts the --scope file doesn't allow
    gate_scope = None if active_scope is scope.UNSCOPED_CLI else active_scope
    results["paths"] = paths.build_paths(results, results["evidence"], gate_scope)
    show_paths(results)
    show_next_checks(results, cves_saved=bool(args.cves))
    if args.ai:
        write_ai_report(results)
    if args.export:
        export_reports(results, args.export)
    if args.json:
        save_json(results, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
