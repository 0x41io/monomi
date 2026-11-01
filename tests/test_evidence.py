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
