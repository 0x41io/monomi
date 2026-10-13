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
from importers import spiderfoot
import enrich
import history
import internetdb
import ui
from ui import fail, good, info, warn

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_domain(raw: str) -> str:
    """Accept 'https://www.Example.com/path' and turn it into 'example.com'-style input."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)  # strip scheme
    d = d.split("/")[0].split(":")[0]  # strip path and port
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
    if sf and sf["target"] != domain:
        warn(f"Export was a scan of {sf['target']}, not {domain}; using {domain} as the target.")
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

    if not results["sources"]:
        fail("All certificate sources failed. They're free services - try again in a few minutes.")
        return 1

    all_subs = sorted({s for r in results["sources"].values() for s in r["subdomains"]})
    results["subdomains"] = all_subs
    print()
    good(f"{ui.paint(str(len(all_subs)), ui.BOLD, ui.RED)} unique hostnames total:\n")

    if args.enrich:
        info("Resolving hosts and looking up hosting providers...")
        data = enrich.enrich(all_subs)
        results["enrichment"] = data
        if data["asn_error"]:
            warn(f"{data['asn_error']} (showing IPs without provider info)")
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
                print(f"    {ui.paint(h, ui.YELLOW)}  {data['hosts'][h]['ips'][0]}")

        if args.ports:
            print()
            info("Checking Shodan InternetDB for open ports and known CVEs (passive)...")
            exposure = internetdb.lookup(data)
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
            first_line = fnd["data"].splitlines()[0]
            print(f"    {ui.paint(fnd['type'], ui.YELLOW)}  {first_line}  ({fnd['module']})")

    # Change detection: compare with the last scan of this domain, then save this one
    previous = None if sf else history.load_last(domain)
    saved_path = None if sf else history.save(domain, all_subs)
    if sf:
        pass
    elif previous is None:
        print()
        info(f"First scan of {domain} - saved as baseline ({saved_path})")
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
    if args.ai:
        print()
        info("Asking Claude to analyze the results...")
        try:
            import analysis
            summary, model = analysis.summarize(results)
        except Exception as e:  # missing key, network, API errors
            fail(f"AI summary failed: {e}")
        else:
            os.makedirs("reports", exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            path = os.path.join("reports", f"{domain}_{stamp}.md")
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
            good(f"Report saved to {path}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print()
        good(f"Saved results to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
