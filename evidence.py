"""
Evidence list: numbered, plain facts pulled from the recon data.

The AI report must cite these IDs (E1, E2...) for every claim, so each
finding can be traced back to where and when the data came from.
Built by code, not by the AI, so the evidence itself can't be made up.
"""


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

    return evidence
