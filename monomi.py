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
from collectors import certspotter, crtsh, crtsh_db, saved
from common import is_hostname, now_utc
from importers import spiderfoot
import doctor
import emailauth
import enrich
import evidence
import mcp_setup
import paths
import report
import suggest
import fingerprint
import exposed
import history
import internetdb
import takeover
import threatintel
import ui
from ui import fail, good, info, warn

# Reports always go in the monomi folder, wherever the command is run from
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

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
    parser.add_argument("--email", action="store_true", help="check SPF/DMARC/DKIM: can someone send email pretending to be this domain? (DNS lookups only)")           
    parser.add_argument("--takeover", action="store_true", help="check for dangling CNAMEs / subdomain takeover leads (DNS lookups only)")
    parser.add_argument("--hosts", metavar="FILE", help="also check hostnames you already know (one per line), e.g. ones certificate logs miss")
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
SOURCE_NAMES = {"crt.sh": "crt.sh", "crt.sh database": "crt.sh database", "Cert Spotter": "certspotter"}
DISPLAY_NAMES = {key: name for name, key in SOURCE_NAMES.items()}  # "certspotter" -> "Cert Spotter"


def collect_ct(results: dict, domain: str, crtsh_budget: float = crtsh.DEFAULT_BUDGET,
               crtsh_light: bool = False, total_budget: float | None = None) -> None:
    """Query all Certificate Transparency sources at the same time and merge whatever succeeds."""
    jobs = {
        "crt.sh": lambda: crtsh.collect(domain, budget=crtsh_budget, light=crtsh_light),
        "crt.sh database": lambda: crtsh_db.collect(domain, budget=min(crtsh_budget, crtsh_db.DEFAULT_BUDGET)),
        "Cert Spotter": lambda: certspotter.collect(domain),
    }
    info("Querying certificate transparency logs (crt.sh, crt.sh database, Cert Spotter, in parallel)...")
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
            good(f"{name}: {r['certificates_seen']} certificates -> {r['subdomain_count']} hostnames")
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
        if r and r["certificates_seen"] > 0:  # an empty result is no use as a fallback
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
        others = {other: o["certificates_seen"] for other, o in results["sources"].items() if other != name}
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
    good(
        f"{data['resolved']}/{len(all_subs)} hosts resolve to "
        f"{data['unique_ips']} unique IPs. Hosting breakdown:\n"
    )
    ui.provider_bars(data["providers"], len(all_subs))
    if data["private_ip_hosts"]:
        print()
        warn(
            f"{len(data['private_ip_hosts'])} host(s) point to private/internal IPs "
            "in public DNS (leaks internal network layout):"
        )
        for h in data["private_ip_hosts"]:
            print(f"    {ui.paint(h, ui.YELLOW)}  {', '.join(data['hosts'][h]['private_ips'])}")
    return data


def run_ports(results: dict, enrichment: dict, cves_file: str | None) -> None:
    """--ports: ask Shodan InternetDB about every IP from --enrich, print what's exposed."""
    print()
    info("Checking Shodan InternetDB for open ports and known CVEs (passive)...")
    exposure = internetdb.lookup(enrichment)
    exposure["collected_at"] = now_utc()
    results["exposure"] = exposure
    if exposure["errors"]:
        warn(f"{exposure['errors']} Shodan lookup(s) failed (results may be incomplete).")
    if exposure["skipped"]:
        warn(f"Only the first {internetdb.MAX_IPS} IPs were checked ({exposure['skipped']} skipped).")
    print()
    if not exposure["ips"]:
        good(f"Shodan has no open ports on record for the {exposure['checked']} IP(s) checked.")
    else:
        ui.exposure_table(exposure)
        print()
        own = [d for d in exposure["ips"].values() if not d["shared_edge"]]
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


def run_fingerprint(results: dict, enrichment: dict) -> None:
    """--fingerprint: one homepage request per live host, then show what tech it gives away (ACTIVE)."""
    print()
    info("Fingerprinting web servers (active: one homepage request per live host)...")
    fp = fingerprint.fingerprint_all(enrichment)
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


def run_exposed(results: dict, enrichment: dict) -> None:
    """--exposed-files: look for public API specs and JS source maps (ACTIVE)."""
    print()
    info("Checking for exposed API specs and source maps "
         "(active: a few requests per live host)...")
    ex = exposed.check_all(enrichment)
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
    report = takeover.check_hosts(hosts, domain=results["target"])
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
    if report["errors"]:
        warn(f"{len(report['errors'])} host(s) couldn't be checked (DNS didn't answer).")
    if not report["leads"]:
        checked = report["checked"] - len(report["errors"])
        good(f"No takeover leads among {checked} hosts checked.")


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


def show_changes(results: dict) -> None:
    """Compare with the last scan of this domain, then save this one as the new baseline.

    Only saves when every source worked: a partial list would make the next
    full scan report lots of fake [NEW] hosts.
    """
    domain = results["target"]
    # History tracks what certificate logs show; a hosts file would add fake [NEW] hosts
    all_subs = sorted({s for name, r in results["sources"].items() if name != HOSTS_FILE
                       for s in r["subdomains"]})
    previous = history.load_last(domain)

    gaps = baseline_gaps(results)
    if gaps:
        print()
        warn(f"{gap_reason(results, gaps)}, so this scan wasn't saved to history (it would be an incomplete baseline).")
        if previous is not None:
            changes = history.compare(previous, all_subs)
            results["changes"] = changes
            for sub in changes["added"]:
                print(f"    {ui.paint('[NEW] ', ui.GREEN)} {sub}")
            if changes["removed"]:
                info(f"{len(changes['removed'])} host(s) from the last scan are missing, probably due to the missing source.")
        return

    saved_path = history.save(domain, all_subs)
    if previous is None:
        print()
        info(f"First scan of {domain} - saved as baseline ({short_path(saved_path)})")
        return

    changes = history.compare(previous, all_subs)
    results["changes"] = changes
    print()
    info(f"Changes since last scan ({changes['previous_scan']}):")
    if not changes["added"] and not changes["removed"]:
        print("    No changes.")
    for sub in changes["added"]:
        print(f"    {ui.paint('[NEW] ', ui.GREEN)} {sub}")
    for sub in changes["removed"]:
        print(f"    {ui.paint('[GONE]', ui.RED)} {sub}")


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
        return
    if not built["paths"]:
        good(f"No attack path found, {len(leads)} lead{'' if len(leads) == 1 else 's'} to investigate.")
        print()
    colors = {"High": ui.RED, "Medium": ui.YELLOW, "Low": ui.GREY}
    for p in built["paths"]:
        badge = ui.paint(p["severity"].upper(), ui.BOLD, colors[p["severity"]])
        print(f"    {p['id']}  {badge}  {ui.safe(p['title'])}  (weakest step: {p['strength']})")
        for n, s in enumerate(p["steps"], 1):
            print(f"        {n}. {ui.paint(s['label'], ui.GREY)}: {ui.safe(s['text'])}")
        print(f"        => {ui.safe(p['outcome'])}")
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
    for i, p in enumerate(leads):
        if i:
            print()  # between leads, not after the last one (the caller adds its own gap)
        print(f"    {p['id']}  {ui.paint('LEAD', ui.BOLD, ui.GREY)}  {ui.safe(p['title'])}")
        for n, s in enumerate(p["steps"], 1):
            print(f"        {n}. {ui.paint(s['label'], ui.GREY)}: {ui.safe(s['text'])}")
        print(f"        Missing: {ui.safe(p['missing'])}")
    if built.get("more_leads"):
        print()
        info(f"{built['more_leads']} more lead(s) not shown.")


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
        import analysis  # only loaded with --ai, so plain scans don't need the anthropic package
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
    """--json: save every result to a file."""
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
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
    for l in r["labels"]:
        text = f"{ui.paint(l['label'].upper(), ui.BOLD, ui.RED)}  {ui.safe(l['reason'])}  [{l['source']}]"
        if l["label"] in threatintel.ANONYMIZERS or l["label"] == "known_bad":
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
        import analysis  # only loaded with --ai
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
    
    if args.ports and not args.enrich:
        args.enrich = True  # Shodan lookups need IP addresses, which --enrich provides
    if args.fingerprint and not args.enrich:
        args.enrich = True  # we only fingerprint hosts that resolve, which --enrich tells us
    if args.exposed_files and not args.enrich:
        args.enrich = True  # same: we only check hosts that resolve to a public IP
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

    if not any(r["subdomains"] for r in results["sources"].values()):
        if sf:
            fail(f"No hostnames for {domain} found in the SpiderFoot export.")
        elif results["errors"]:
            fail("All certificate sources failed. They're free services - try again in a few minutes.")
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
            run_fingerprint(results, data)
        if args.exposed_files:
            run_exposed(results, data)
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
    results["paths"] = paths.build_paths(results, results["evidence"])
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
