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
from datetime import datetime, timezone

from collectors import certspotter, crtsh
from importers import spiderfoot
import enrich
import evidence
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


def main() -> int:
    parser = argparse.ArgumentParser(description="0x41 / monomi - passive domain recon")
    parser.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    parser.add_argument("--import", dest="import_file", metavar="FILE", help="analyze a SpiderFoot CSV export")
    parser.add_argument("--json", metavar="FILE", help="save raw results to a JSON file")
    parser.add_argument("--ai", action="store_true", help="have Claude write a summary report (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--enrich", action="store_true", help="resolve hosts to IPs and look up hosting provider/ASN (sends DNS queries)")
    parser.add_argument("--ports", action="store_true", help="look up open ports and known CVEs in Shodan's InternetDB (passive; turns on --enrich)")
    parser.add_argument("--cves", metavar="FILE", help="save every CVE found by --ports to a file (feed it to kaidoku --file)")
    parser.add_argument("--no-color", action="store_true", help="plain output (also respects NO_COLOR)")
    args = parser.parse_args()
    if args.no_color:
        ui.disable()
    print(ui.banner())

    if args.ports and not args.enrich:
        args.enrich = True  # Shodan lookups need IP addresses, which --enrich provides
    if args.cves and not args.ports:
        warn("--cves only works together with --ports; ignoring it.")

    # --import: load the SpiderFoot export first, since it tells us the target domain
    sf = None
    if args.import_file:
        try:
            sf = spiderfoot.load_spiderfoot_csv(args.import_file)
        except (OSError, ValueError, KeyError) as e:
            fail(f"Couldn't read SpiderFoot export {args.import_file}: {e}")
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
    if sf:
        # Compare cleaned forms, so "www.example.com" in the export matches "example.com"
        try:
            sf_domain = clean_domain(sf["target"])
        except ValueError:
            sf_domain = sf["target"]
        if sf_domain != domain:
            # The export's hosts were filtered for its own target, so mixing the two
            # would produce a report about one domain filled with another's data.
            fail(f"This export is a scan of {sf['target']}, but you asked for {domain}.")
            info(f"Run it without a domain to analyze {sf['target']}: python monomi.py --import {args.import_file}")
            return 1
    results = {"target": domain, "sources": {}, "errors": {}}
    info(f"Target: {ui.paint(domain, ui.BOLD, ui.WHITE)}")
    if sf:
        hosts = sorted(sf["hosts"])
        results["sources"]["spiderfoot"] = {"source": "spiderfoot", "file": args.import_file, "subdomains": hosts}
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

    
    # Certificate Transparency: try both sources, merge whatever succeeds
    for name, module in ([] if sf else [("crt.sh", crtsh), ("Cert Spotter", certspotter)]):
        info(f"Querying certificate transparency logs ({name})...")
        try:
            r = module.collect(domain)
            results["sources"][r["source"]] = r
            good(f"{name}: {r['certificates_seen']} certificates -> {r['subdomain_count']} hostnames")
        except RuntimeError as e:
            results["errors"][name] = str(e)
            warn(f"{name} unavailable: {e}")

    if not results["sources"]    or not any(r["subdomains"] for r in results["sources"].values()):
        if sf:
            fail(f"No hostnames for {domain} found in the SpiderFoot export.")   
            return 1 
        if results["errors"]:
            fail("All certificate sources failed. They're free services - try again in a few minutes.")
        else:
            fail(f"No certificates found for {domain}. Check the spelling, or the domain may not use TLS.")
        return 1

    all_subs = sorted({s for r in results["sources"].values() for s in r["subdomains"]})
    results["subdomains"] = all_subs
    print()
    good(f"{ui.paint(str(len(all_subs)), ui.BOLD, ui.RED)} unique hostnames total:\n")

    if args.enrich:
        info("Resolving hosts and looking up hosting providers...")
        data = enrich.enrich(all_subs)
        data["collected_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        results["enrichment"] = data
        if data["asn_error"]:
            warn(f"{data['asn_error']} (showing IPs without provider info)")
            if args.ports:
                # Without provider names we can't tell CDN edge IPs apart, so their
                # ports and CVEs would be counted as the target's own.
                warn("CDN edge filtering is OFF for this run: ports/CVEs below may belong to "
                     "Cloudflare/Fastly/etc., not the target. Re-run later for accurate numbers.")
        if data.get("cdn_error"):
            warn(f"CloudFront detection skipped: {data['cdn_error']}. CloudFront edge IPs will show as plain AWS"
                 + (" and their ports/CVEs may be counted as the target's." if args.ports else "."))
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

        if args.ports:
            print()
            info("Checking Shodan InternetDB for open ports and known CVEs (passive)...")
            exposure = internetdb.lookup(data)
            exposure["collected_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
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
            if args.cves:
                if exposure["unique_cves"]:
                    with open(args.cves, "w") as f:
                        f.write("\n".join(exposure["unique_cves"]) + "\n")
                    good(f"Saved {len(exposure['unique_cves'])} CVEs to {args.cves}. Triage them with: python kaidoku.py --file {args.cves}")
                else:
                    info(f"No CVEs found, so {args.cves} wasn't written.")
    else:
        for sub in all_subs:
            print(f"    {sub}")

    if sf and sf["findings"]:
        print()
        warn("SpiderFoot flagged these (unverified; the AI report weighs them):")
        for fnd in sf["findings"]:
            # SpiderFoot data comes from third parties: clean it before it hits the terminal
            first_line = ui.safe((fnd["data"].splitlines() or ["(no data)"])[0])
            print(f"    {ui.paint(ui.safe(fnd['type']), ui.YELLOW)}  {first_line}  ({ui.safe(fnd['module'])})")

    # Change detection: compare with the last scan of this domain, then save this one
    # Only save a baseline when every source worked; a partial list would make
    # the next full scan report lots of fake [NEW] hosts.
    previous = None if sf else history.load_last(domain)
    complete = not results["errors"]
    saved_path = history.save(domain, all_subs) if (complete and not sf) else None
    if sf:
        pass
    elif not complete:
        print()
        warn("A source failed, so this scan wasn't saved to history (it would be an incomplete baseline).")
        if previous is not None:
            changes = history.compare(previous, all_subs)
            results["changes"] = changes
            for sub in changes["added"]:
                print(f"    {ui.paint('[NEW] ', ui.GREEN)} {sub}")
            if changes["removed"]:
                info(f"{len(changes['removed'])} host(s) from the last scan are missing, probably due to the failed source.")
    elif previous is None:
        print()
        info(f"First scan of {domain} - saved as baseline ({short_path(saved_path)})")
    else:
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
        if results["errors"] and changes["removed"]:
            print(f"    {ui.paint('[!]', ui.YELLOW)} A source failed this run, so GONE hosts may just be missing data.")
    results["evidence"] = evidence.build_evidence(results)
    if args.ai:
        print()
        info("Asking Claude to analyze the results...")
        try:
            import analysis
            summary, model = analysis.summarize(results)
        except Exception as e:  # missing key, network, API errors
            fail(f"AI summary failed: {e}")
        else:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            path = os.path.join(REPORTS_DIR, f"{domain}_{stamp}.md")
            header = (
                f"# mønømi report: {domain}\n\n"
                f"*Generated {datetime.now():%Y-%m-%d %H:%M} · "
                f"sources: {', '.join(results['sources'])} · "
                f"{len(all_subs)} hostnames"
                f"{' · enriched' if 'enrichment' in results else ''}"
                f"{' · Shodan InternetDB' if 'exposure' in results else ''} · model: {model}*\n\n"
            )
            with open(path, "w") as f:
                f.write(header + summary + "\n")
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

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print()
        good(f"Saved results to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
