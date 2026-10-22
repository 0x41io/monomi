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

from collectors import certspotter, crtsh
from common import now_utc
from importers import spiderfoot
import enrich
import evidence
import fingerprint
import history
import internetdb
import ui
from ui import fail, good, info, warn

# Reports always go in the monomi folder, wherever the command is run from
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

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
    parser.add_argument("--ai", action="store_true", help="have Claude write a summary report (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--enrich", action="store_true", help="resolve hosts to IPs and look up hosting provider/ASN (sends DNS queries)")
    parser.add_argument("--ports", action="store_true", help="look up open ports and known CVEs in Shodan's InternetDB (passive; turns on --enrich)")
    parser.add_argument("--cves", metavar="FILE", help="save every CVE found by --ports to a file (feed it to kaidoku --file)")
    parser.add_argument("--fingerprint", action="store_true", help="ACTIVE: one homepage request per live host to spot web server/framework (turns on --enrich)")
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


def collect_ct(results: dict, domain: str) -> None:
    """Query both Certificate Transparency sources and merge whatever succeeds."""
    for name, module in [("crt.sh", crtsh), ("Cert Spotter", certspotter)]:
        info(f"Querying certificate transparency logs ({name})...")
        try:
            r = module.collect(domain)
            results["sources"][r["source"]] = r
            good(f"{name}: {r['certificates_seen']} certificates -> {r['subdomain_count']} hostnames")
        except RuntimeError as e:
            results["errors"][name] = str(e)
            warn(f"{name} unavailable: {e}")


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
        good(f"Shodan has no open ports on record for the {exposure['checked']} IPs checked.")
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
        if "location" in r["headers"]:
            line += f"  -> {ui.safe(r['headers']['location'])}"
        print(f"    {host}  [{r['status']}]  {line}")
    print()
    versions = sum(1 for r in fp["hosts"].values() for t in r["techs"] if t["version"])
    good(f"{len(fp['hosts'])}/{fp['checked']} hosts answered on HTTPS"
         + (f", {ui.paint(str(versions), ui.BOLD, ui.YELLOW)} leaked a software version (can be matched to CVEs)." if versions else "."))
    if fp["errors"]:
        info(f"{len(fp['errors'])} host(s) didn't answer on HTTPS (timeouts, TLS errors, refused).")

def show_import_findings(sf: dict) -> None:
    """Print what SpiderFoot flagged (unverified leads)."""
    print()
    warn("SpiderFoot flagged these (unverified; the AI report weighs them):")
    for fnd in sf["findings"]:
        # SpiderFoot data comes from third parties: clean it before it hits the terminal
        first_line = ui.safe((fnd["data"].splitlines() or ["(no data)"])[0])
        print(f"    {ui.paint(ui.safe(fnd['type']), ui.YELLOW)}  {first_line}  ({ui.safe(fnd['module'])})")


def show_changes(results: dict) -> None:
    """Compare with the last scan of this domain, then save this one as the new baseline.

    Only saves when every source worked: a partial list would make the next
    full scan report lots of fake [NEW] hosts.
    """
    domain, all_subs = results["target"], results["subdomains"]
    previous = history.load_last(domain)

    if results["errors"]:
        print()
        warn("A source failed, so this scan wasn't saved to history (it would be an incomplete baseline).")
        if previous is not None:
            changes = history.compare(previous, all_subs)
            results["changes"] = changes
            for sub in changes["added"]:
                print(f"    {ui.paint('[NEW] ', ui.GREEN)} {sub}")
            if changes["removed"]:
                info(f"{len(changes['removed'])} host(s) from the last scan are missing, probably due to the failed source.")
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
    with open(path, "w") as f:
        f.write(header + summary + "\n\n" + evidence.evidence_appendix(summary, results["evidence"]))
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


def save_json(results: dict, path: str) -> None:
    """--json: save every result to a file."""
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print()
    good(f"Saved results to {path}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.no_color:
        ui.disable()
    print(ui.banner())

    if args.ports and not args.enrich:
        args.enrich = True  # Shodan lookups need IP addresses, which --enrich provides
    if args.fingerprint and not args.enrich:
        args.enrich = True  # we only fingerprint hosts that resolve, which --enrich tells us
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
    good(f"{ui.paint(str(len(all_subs)), ui.BOLD, ui.RED)} unique hostnames total:\n")

    # 2. Optional enrichment
    if args.enrich:
        data = run_enrich(results, args.ports)
        if args.ports:
            run_ports(results, data, args.cves)
        if args.fingerprint:
            run_fingerprint(results, data)
    else:
        for sub in all_subs:
            print(f"    {sub}")

    if sf and sf["findings"]:
        show_import_findings(sf)

    # 3. Change detection (live scans only: an import has no history to compare)
    if not sf:
        show_changes(results)

    # 4. Evidence, AI report, JSON
    results["evidence"] = evidence.build_evidence(results)
    if args.ai:
        write_ai_report(results)
    if args.json:
        save_json(results, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
