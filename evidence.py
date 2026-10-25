"""
Evidence list: numbered, plain facts pulled from the recon data.

The AI report must cite these IDs (E1, E2...) for every claim, so each
finding can be traced back to where and when the data came from.
Built by code, not by the AI, so the evidence itself can't be made up.
"""
import re

from common import now_utc

def build_evidence(results: dict) -> list[dict]:
    """Turn raw recon results into a numbered list of evidence items."""
    evidence = []

    def add(fact, sources):
        evidence.append({
            "id": f"E{len(evidence) + 1}",
            "fact": fact,
            "sources": sources,
        })

    # 1. Which sources found each hostname
    seen_by = {}
    for r in results["sources"].values():
        for host in r["subdomains"]:
            seen_by.setdefault(host, []).append(
                {"name": r["source"], "collected_at": r.get("collected_at")}
            )
    for host in results["subdomains"]:
        names = ", ".join(s["name"] for s in seen_by[host])
        add(f"{host} was found by {names}", seen_by[host])

    # 2. DNS and hosting (from --enrich)
    enr = results.get("enrichment")
    if enr:
        dns_source = [{"name": "DNS + ASN lookup", "collected_at": enr.get("collected_at")}]
        for host in results["subdomains"]:
            h = enr["hosts"].get(host)
            if not h:
                continue
            if h["ips"]:
                where = h["provider"] or "unknown provider"
                if h.get("country"):
                    where += f", {h['country']}"
                add(f"{host} resolves to {', '.join(h['ips'])} ({where})", dns_source)
            else:
                add(f"{host} had no DNS record when checked", dns_source)
        for host in enr["private_ip_hosts"]:
            private = ", ".join(enr["hosts"][host].get("private_ips", []))
            add(f"{host} points to private/internal IP(s) in public DNS: {private}", dns_source)

    # 3. Open ports, risky services and CVEs (from --ports)
    exp = results.get("exposure")
    if exp:
        shodan_source = [{"name": "Shodan InternetDB", "collected_at": exp.get("collected_at")}]
        for ip, d in exp["ips"].items():
            if d["shared_edge"]:
                continue  # CDN edge server: these ports belong to the CDN, not the target
            hosts = ", ".join(d["hosts"][:3])
            if len(d["hosts"]) > 3:
                hosts += f" +{len(d['hosts']) - 3} more"
            ports = ", ".join(str(p) for p in d["ports"])
            fact = f"{ip} ({hosts}) has open ports: {ports}"
            if d["tags"]:
                fact += f"; Shodan tags: {', '.join(d['tags'])}"
            add(fact, shodan_source)
            if d["risky"]:
                add(f"{ip} ({hosts}) runs services that usually shouldn't face the internet: "
                    f"{', '.join(d['risky'])}", shodan_source)
            if d["vulns"]:
                cves = ", ".join(d["vulns"][:15])
                more = f" (+{len(d['vulns']) - 15} more)" if len(d["vulns"]) > 15 else ""
                add(f"Shodan InternetDB lists {len(d['vulns'])} CVE(s) for {ip} ({hosts}), "
                    f"matched from software version banners: {cves}{more}", shodan_source)

    # 4. SpiderFoot findings (from --import)
    sf = results.get("spiderfoot")
    if sf:
        sf_source = [{
            "name": f"SpiderFoot export ({results['sources']['spiderfoot']['file']})",
            "collected_at": None,  # SpiderFoot collected it at its own scan time, which we don't know
            "imported_at": now_utc(),
        }]
        for fnd in sf["findings"]:
            first_line = (fnd["data"].splitlines() or ["(no data)"])[0][:200]
            add(f"SpiderFoot module {fnd['module']} reported {fnd['type']}: {first_line}", sf_source)
    # 5. Web technology seen in HTTP headers (from --fingerprint, ACTIVE)
    fp = results.get("fingerprint")
    if fp:
        for host, r in fp["hosts"].items():
            fp_source = [{"name": "HTTP fingerprint (active, 1 request)", "collected_at": r["collected_at"]}]
            for t in r["techs"]:
                fact = f"{host} (HTTP {r['status']}) shows {t['tech']} in its response ({t['evidence']})"
                if t["version"]:
                    fact += f"; exact version {t['version']} is exposed"
                add(fact, fp_source)

    # 6. Security headers missing or weak (from the same --fingerprint request)
    if fp:
        for host, r in fp["hosts"].items():
            if not r.get("header_issues"):
                continue
            hdr_source = [{"name": "HTTP security headers (same fingerprint request)", "collected_at": r["collected_at"]}]
            problems = "; ".join(f"{i['header']} {i['problem']} ({i['detail']})" for i in r["header_issues"])
            add(f"{host} (HTTP {r['status']}) security headers: {problems}", hdr_source)

    # 7. Email spoofing protection (from --email, DNS lookups only)
    em = results.get("email")
    if em and "error" not in em:
        target = results["target"]
        mail_source = [{"name": "DNS TXT lookups (SPF, DMARC, DKIM)", "collected_at": em["collected_at"]}]
        spf, dmarc, dkim, v = em["spf"], em["dmarc"], em["dkim"], em["verdict"]

        def with_issues(fact, check):
            if check["issues"]:
                fact += "; issues: " + "; ".join(f"{i['problem']} ({i['detail']})" for i in check["issues"])
            return fact

        if spf["record"]:
            add(with_issues(f"{target} SPF record: {spf['record']}", spf), mail_source)
        else:
            add(f"{target} has no SPF record", mail_source)

        if dmarc["record"]:
            add(with_issues(f"_dmarc.{target} DMARC record: {dmarc['record']}", dmarc), mail_source)
        else:
            add(f"{target} has no DMARC record (nothing at _dmarc.{target})", mail_source)

        if dkim["selectors"]:
            add(f"{target} has DKIM keys under selector(s): {', '.join(dkim['selectors'])}", mail_source)
        else:
            add(f"No DKIM key found for {target} under common selector names; "
                "a custom selector can't be ruled out", mail_source)

        fact = f"Email spoofing verdict for {target} (worked out by code from the DMARC policy): {v['verdict']}, {v['summary']}"
        if v["notes"]:
            fact += "; notes: " + "; ".join(v["notes"])
        add(fact, mail_source)
    return evidence


def cited_ids(report: str) -> set[str]:
    """Every evidence ID cited in brackets, e.g. [E1, E2] or a range [E5-E9]."""
    cited = set()
    for group in re.findall(r"\[(E\d+(?:\s*[,-]\s*E\d+)*)\]", report):
        for part in re.split(r"\s*,\s*", group):
            nums = [int(n) for n in re.findall(r"\d+", part)]
            if len(nums) == 2 and 0 <= nums[1] - nums[0] <= 1000:
                cited.update(f"E{n}" for n in range(nums[0], nums[1] + 1))  # a range: E5-E9
            else:
                cited.update(f"E{n}" for n in nums)
    return cited

def check_citations(report: str, evidence: list[dict]) -> list[str]:
    """Return evidence IDs the report cites that don't exist (sorted, no repeats)."""
    known = {e["id"] for e in evidence}
    return sorted(cited_ids(report) - known, key=lambda i: int(i[1:]))


def describe_source(s: dict) -> str:
    """One readable line about where and when a fact came from."""
    if s.get("collected_at"):
        return f"{s['name']}, collected {s['collected_at']}"
    if s.get("imported_at"):
        return f"{s['name']}, imported {s['imported_at']} (original collection time unknown)"
    return f"{s['name']} (collection time unknown)"


def evidence_appendix(report: str, evidence: list[dict]) -> str:
    """Markdown 'Evidence' section listing only the items the report cites."""
    cited = cited_ids(report)
    lines = [
        "## Evidence",
        "",
        "Facts collected by monomi's code, not written by the AI. "
        "Every citation in the report above points to one of these.",
        "",
    ]
    for e in evidence:
        if e["id"] not in cited:
            continue
        sources = "; ".join(describe_source(s) for s in e["sources"])
        lines.append(f"- **{e['id']}**: {e['fact']}")
        lines.append(f"  - Source: {sources}")
    if len(lines) == 4:
        lines.append("*The report cites no evidence.*")
    return "\n".join(lines) + "\n"
