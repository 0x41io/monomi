from evidence import build_evidence, check_citations, cited_ids
from history import compare


def test_cited_ids_reads_singles_lists_and_ranges():
    report = "One [E1]. Two [E2, E7]. A range [E10-E12]."
    assert cited_ids(report) == {"E1", "E2", "E7", "E10", "E11", "E12"}


def test_check_citations_finds_made_up_ids():
    evidence = [{"id": "E1"}, {"id": "E2"}]
    assert check_citations("Real [E1], fake [E9] and [E40]", evidence) == ["E9", "E40"]
    assert check_citations("All real [E1, E2]", evidence) == []


def test_history_compare_spots_new_and_gone_hosts():
    previous = {"scanned_at": "2026-10-01T12:00:00", "subdomains": ["a.example.com", "old.example.com"]}
    changes = compare(previous, ["a.example.com", "new.example.com"])
    assert changes["added"] == ["new.example.com"]
    assert changes["removed"] == ["old.example.com"]

def test_evidence_says_why_a_host_has_no_ip():
    hosts = ["old.example.com", "x.example.com"]
    results = {
        "subdomains": hosts,
        "sources": {"crt.sh": {"source": "crt.sh", "subdomains": hosts}},
        "enrichment": {
            "hosts": {
                "old.example.com": {"ips": [], "provider": None, "dns": "gone"},
                "x.example.com": {"ips": [], "provider": None, "dns": "lookup_failed"},
            },
            "private_ip_hosts": [],
        },
    }
    facts = [e["fact"] for e in build_evidence(results)]
    assert any("old.example.com had no DNS record" in f and "NXDOMAIN" in f for f in facts)
    assert any("x.example.com could not be looked up" in f and "unknown" in f for f in facts)
    assert not any("x.example.com had no DNS record" in f for f in facts)

def test_every_dns_status_has_wording():
    # A host_status() word without wording would fall back to a vague
    # "had no IPv4 address" in the report, or show blank in the summary
    import enrich
    import evidence
    for word in ["no_such_host", "dangling_cname", "no_address",
                 "ipv6_only", "conflicting", "lookup_failed"]:
        assert word in evidence.DNS_FACTS, word
        assert word in enrich.DNS_LABELS, word


def owner_results():
    # Hostnames without dots on purpose: the chat app turns dotted names
    # into Markdown links when code is copied. build_evidence() doesn't care.
    hosts = ["app", "old", "nope"]
    return {
        "subdomains": hosts,
        "sources": {"certlog": {"source": "certlog", "subdomains": hosts}},
        "enrichment": {
            "hosts": {
                "app": {"ips": ["198.51.100.7"], "provider": "DigitalOcean"},
                "old": {"ips": [], "provider": None, "dns": "dangling_cname"},
                "nope": {"ips": [], "provider": None, "dns": "no_such_host"},
            },
            "private_ip_hosts": [],
        },
        "exposure": {
            "ips": {
                "198.51.100.7": {"shared_edge": False, "hosts": ["app"], "ports": [22, 80],
                                 "tags": [], "risky": [], "vulns": ["CVE-2024-0001"]},
            },
        },
        "fingerprint": {
            "hosts": {
                "app": {"collected_at": None, "status": 200,
                        "techs": [{"tech": "nginx", "version": "1.24.0", "evidence": "Server header"},
                                  {"tech": "React", "version": None, "evidence": "page script"}],
                        "header_issues": [{"header": "Content-Security-Policy",
                                           "problem": "missing", "detail": "not sent"}]},
            },
        },
        "takeover": {
            "leads": [{"host": "shop", "cname": "gone-shop", "service": "Azure App Service",
                       "claimable": True, "collected_at": None}],
            "stale": [{"host": "lb", "cname": "gone-lb", "service": "AWS ELB",
                       "reason": "random ID", "collected_at": None}],
            "checked": 5, "errors": [], "collected_at": None,
        },
    }


def owners_of(evidence, text):
    """Owners of the one fact that contains text."""
    found = [e["owners"] for e in evidence if text in e["fact"]]
    assert len(found) == 1, f"expected one fact with {text!r}, got {len(found)}"
    return found[0]


def test_owners_follow_the_rules():
    ev = build_evidence(owner_results())
    assert owners_of(ev, "app was found by") == []
    assert owners_of(ev, "app resolves to") == []
    assert owners_of(ev, "old exists in DNS") == ["DNS admin"]
    assert owners_of(ev, "nope does not exist") == []
    assert owners_of(ev, "has open ports") == ["server / infrastructure admin"]
    assert owners_of(ev, "CVE(s)") == ["server / infrastructure admin"]
    assert owners_of(ev, "exact version 1.24.0") == ["server / infrastructure admin"]
    assert owners_of(ev, "shows React") == []
    assert owners_of(ev, "security headers") == ["web app team", "CDN / proxy admin"]
    assert owners_of(ev, "shop has a CNAME") == ["DNS admin", "cloud / service account owner"]
    assert owners_of(ev, "lb has a CNAME") == ["DNS admin"]


def test_every_fact_has_a_list_of_known_owners():
    import evidence
    for e in build_evidence(owner_results()):
        assert isinstance(e["owners"], list), e["id"]
        for owner in e["owners"]:
            assert owner in evidence.OWNERS.values(), owner


def test_appendix_shows_owners():
    from evidence import evidence_appendix
    ev = build_evidence(owner_results())
    lead = next(e for e in ev if "shop has a CNAME" in e["fact"])
    text = evidence_appendix(f"See [{lead['id']}]", ev)
    assert "Owner: DNS admin, cloud / service account owner" in text


def kinds_of(evidence):
    """{kind: [hosts]} for every fact that has a kind."""
    found = {}
    for e in evidence:
        if e["kind"]:
            found.setdefault(e["kind"], []).append(e["host"])
    return found


def test_facts_that_attack_paths_use_have_a_kind():
    results = owner_results()
    results["subdomains"].append("staging")
    results["enrichment"]["hosts"]["staging"] = {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}
    results["exposure"]["ips"]["198.51.100.7"]["risky"] = ["3389 (RDP)"]
    results["takeover"]["leads"].append({"host": "blog", "cname": "gone-blog", "service": "unknown",
                                         "claimable": False, "collected_at": None})
    kinds = kinds_of(build_evidence(results))
    assert kinds["resolves"] == ["app", "staging"]
    assert kinds["risky_name"] == ["staging"]
    assert kinds["risky_service"] == ["198.51.100.7"]
    assert kinds["cves"] == ["198.51.100.7"]
    assert kinds["version_leak"] == ["app"]
    assert kinds["takeover_lead"] == ["shop"]
    assert kinds["dangling_unknown"] == ["blog"]


def test_risky_name_needs_a_live_host():
    # "old" and "nope" have names that could look risky, but no IP: no fact
    results = owner_results()
    results["subdomains"].append("dev")
    results["enrichment"]["hosts"]["dev"] = {"ips": [], "provider": None, "dns": "no_such_host"}
    assert "risky_name" not in kinds_of(build_evidence(results))


def test_email_verdict_kind_names_the_verdict():
    results = owner_results()
    results["target"] = "example"
    results["email"] = {
        "collected_at": None,
        "spf": {"record": None, "issues": []},
        "dmarc": {"record": None, "issues": []},
        "dkim": {"selectors": [], "issues": []},
        "verdict": {"verdict": "spoofable", "summary": "no DMARC", "notes": []},
    }
    assert kinds_of(build_evidence(results))["email_spoofable"] == ["example"]


def test_citations_count_in_brackets_with_other_text():
    # The AI sometimes mixes path IDs or words into a bracket: those
    # citations must still be found, so a made-up ID can't slip past
    report = "Fix it [E26, closes P1]. Lock down [E15, E16, P2]. Fake [E99, P3]. Range [E3-E5, P1]."
    assert cited_ids(report) == {"E26", "E15", "E16", "E99", "E3", "E4", "E5"}
    evidence = [{"id": f"E{n}"} for n in range(1, 30)]
    assert check_citations(report, evidence) == ["E99"]


def test_citations_ignore_lookalikes():
    # CVE IDs and words that merely contain an E and digits aren't citations
    assert cited_ids("[CVE-2024-1234] [see E2E tests] [TE5]") == set()
