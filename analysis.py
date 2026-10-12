"""
AI synthesis layer: turns raw recon data into a plain-English summary.

This is the 0x41 difference: other tools dump lists, this one explains them.
Requires an Anthropic API key in the ANTHROPIC_API_KEY environment variable.
"""

import json
import os

MAX_HOSTS = 400  # keep requests small and cheap on very large domains

SYSTEM_PROMPT = """You are a security analyst at 0x41, writing an external \
attack-surface summary for an authorized assessment. Your reader is the \
domain owner or the security team they hired. Be clear, practical, and \
defensive in focus.

Write in Markdown with these sections:
1. **Overview**: 2-3 sentences on the size and shape of the public footprint.
2. **How the infrastructure is organized**: group hostnames by apparent \
purpose (production, auth, VPN/remote access, status/monitoring, dev/staging, \
regional clusters, etc.) and note naming patterns.
3. **Worth reviewing**: hostnames whose names suggest they may not need to be \
publicly listed (internal tools, staging, admin, cost/billing, legacy). Explain \
why each matters in one line. Prioritize: High / Medium / Low.
4. **Recommendations**: concrete defensive steps for the owner.
5. **Limitations**: this data comes only from public certificate logs; it \
does not confirm which hosts are live, and names alone don't prove a problem.

If the data includes "enrichment" (DNS + hosting provider per host), also:
- In section 2, describe where things are hosted (providers/ASNs, countries) \
and anything notable, like a sensitive-sounding host sitting on a different \
provider than the rest, or self-hosted ranges next to cloud/CDN.
- In section 3, treat hosts resolving to private/internal IPs as worth \
reviewing (internal addresses published in public DNS reveal network layout), \
and note that CT-listed hosts with no DNS record are likely retired or stale.
- In Limitations, note that DNS reflects one point in time from one resolver.

If the data includes "exposure" (Shodan InternetDB: open ports and CVEs per IP):
- In section 3, treat internet-facing risky services (remote access, file \
sharing, databases, Docker API) as worth reviewing, naming the host and port. \
Mention the CVE count per IP and the most notable CVE IDs, but say they are \
matched from software version banners and must be verified.
- Ignore open ports on IPs marked shared_edge (CDN edge servers such as \
Cloudflare); they belong to the CDN, not the target. Say so once.
- In section 4, suggest triaging the CVE list with kaidoku and closing or \
firewalling services that don't need to be public.
- In Limitations, note that Shodan's data can be days or weeks old.

Formatting rules (the report is rendered in a terminal):
- Start directly with "## 1. Overview". No title line above it.
- Use "## " for the five section headings.
- In section 3, group findings under these exact sub-headings, each on its \
own line: "### High", "### Medium", "### Low". Leave out a level if it has \
no findings.

Do not invent facts beyond the data. Hedge inferences ("suggests", "likely").
Be concise: aim for about 600-900 words total. Summarize large repetitive \
groups (e.g. many regional clusters) in one line instead of listing every host."""


def pick_model(client) -> str:
    """Use $CLAUDE_MODEL if set, otherwise the newest Sonnet the API lists."""
    if os.environ.get("CLAUDE_MODEL"):
        return os.environ["CLAUDE_MODEL"]
    models = [m.id for m in client.models.list(limit=50)]  # newest first
    for mid in models:
        if "sonnet" in mid:
            return mid
    return models[0]


def summarize(results: dict) -> tuple[str, str]:
    """Send recon results to Claude. Returns (markdown_summary, model_used)."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set (see README step for the API key).")

    import anthropic  # imported here so scans without --ai don't need it

    client = anthropic.Anthropic()
    model = pick_model(client)

    hosts = results.get("subdomains", [])
    payload = {
        "target": results["target"],
        "sources_used": list(results.get("sources", {}).keys()),
        "total_hostnames": len(hosts),
        "hostnames": hosts[:MAX_HOSTS],
        "truncated": len(hosts) > MAX_HOSTS,
    }
    enr = results.get("enrichment")
    if enr:
        payload["hostnames"] = [
            {
                "host": h,
                "ips": enr["hosts"][h]["ips"],
                "provider": enr["hosts"][h]["provider"] or "no DNS record",
                "asn": enr["hosts"][h].get("asn"),
                "country": enr["hosts"][h].get("country"),
            }
            for h in hosts[:MAX_HOSTS]
        ]
        payload["enrichment"] = {
            "resolved": enr["resolved"],
            "unique_ips": enr["unique_ips"],
            "providers": enr["providers"],
            "private_ip_hosts": enr["private_ip_hosts"],
        }
    exp = results.get("exposure")
    if exp:
        payload["exposure"] = {
            "ips_checked": exp["checked"],
            "ips": {
                ip: {
                    "hosts": d["hosts"][:10],
                    "provider": d["provider"],
                    "shared_edge": d["shared_edge"],
                    "ports": d["ports"],
                    "risky_services": d["risky"],
                    "cve_count": len(d["vulns"]),
                    "cves": d["vulns"][:15],
                    "tags": d["tags"],
                }
                for ip, d in exp["ips"].items()
            },
            "unique_cves_excluding_cdn": len(exp["unique_cves"]),
        }

    msg = client.messages.create(
        model=model,
        max_tokens=8000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": "Recon data (JSON):\n```json\n" + json.dumps(payload, indent=2) + "\n```",
        }],
    )
    text = "".join(block.text for block in msg.content if block.type == "text")
    if msg.stop_reason == "max_tokens":
        text += "\n\n> **Note:** this report hit the length limit and was cut off."
    return text, model
