"""v1.18: what the rest of Monomi does with wildcard results from enrich()."""

import json
import sys
import types

from monomi import analysis, cli, mcp_server
from monomi.evidence import build_evidence

WILD_ZONE = {"ips": ["1.1.1.1", "1.0.0.1"], "canonicals": [], "provider": "Fastly", "private": False,
             "hosts": 7, "examples": ["j1.example.test", "j2.example.test", "j3.example.test",
                                      "j4.example.test", "j5.example.test"]}


def enrichment(**extra):
    """A saved enrichment with one real host and seven set aside under a wildcard."""
    data = {
        "hosts": {"app.example.test": {"ips": ["9.9.9.9"], "canonical": None, "dns": "live",
                                       "provider": "AWS", "providers": ["AWS"], "private_ips": []}},
        "ip_info": {"9.9.9.9": {"provider": "AWS"}},
        "providers": {"AWS": 1}, "resolved": 1, "not_resolving": {}, "unique_ips": 1,
        "private_ip_hosts": [], "asn_error": None, "cdn_error": None,
        "wildcards": {"example.test": WILD_ZONE},
        "wildcard_only": {f"j{i}.example.test": "example.test" for i in range(1, 8)},
        "wildcard_error": None,
    }
    data.update(extra)
    return data


def test_cli_prints_one_line_per_wildcard(capsys):
    cli.show_wildcards(enrichment())
    out = capsys.readouterr().out
    assert "*.example.test is a wildcard -> Fastly (2 IPs): 7 host(s) resolve only through it" in out
    assert "j1.example.test" in out and "and 2 more" in out          # 5 examples + the rest counted
    assert "app.example.test" not in out


def test_cli_names_private_ips_of_an_ingress_wildcard(capsys):
    zone = {**WILD_ZONE, "ips": ["10.54.0.1"], "private": True, "provider": "PRIVATE IP"}
    cli.show_wildcards(enrichment(wildcards={"acc.example.test": zone}))
    assert "*.acc.example.test is a wildcard -> private IPs (10.54.0.1)" in capsys.readouterr().out


def test_cli_quiet_for_a_wildcard_with_nothing_set_aside(capsys):
    cli.show_wildcards(enrichment(wildcards={"example.test": {**WILD_ZONE, "hosts": 0, "examples": []}}))
    assert capsys.readouterr().out == ""


def test_cli_says_when_the_check_was_skipped(capsys):
    cli.show_wildcards(enrichment(wildcards={}, wildcard_error="your DNS resolver answers for names "
                                                               "that don't exist"))
    assert "Wildcard check skipped: your DNS resolver" in capsys.readouterr().out


def test_wildcard_becomes_one_evidence_fact():
    found = ["app.example.test", "j1.example.test"]
    results = {"target": "example.test", "subdomains": found, "enrichment": enrichment(),
               "sources": {"certspotter": {"source": "Cert Spotter", "subdomains": found, "collected_at": None}}}
    facts = [e for e in build_evidence(results) if e["kind"] == "wildcard"]
    assert len(facts) == 1
    assert facts[0]["host"] == "example.test"
    assert "*.example.test is a wildcard" in facts[0]["fact"] and "7 found hostname(s)" in facts[0]["fact"]
    # a set-aside host gets no "resolves to" fact of its own
    assert not any(e["kind"] == "resolves" and e["host"] == "j1.example.test" for e in build_evidence(results))


def test_ai_payload_skips_set_aside_hosts_and_names_the_wildcard(monkeypatch):
    sent = {}

    class Messages:
        def create(self, **kw):
            sent["payload"] = kw["messages"][0]["content"]
            block = types.SimpleNamespace(type="text", text="ok")
            return types.SimpleNamespace(content=[block], stop_reason="end_turn")

    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda: types.SimpleNamespace(messages=Messages())
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(analysis, "pick_model", lambda client: "claude-test")

    results = {"target": "example.test", "sources": {},
               "subdomains": ["app.example.test", "j1.example.test"], "enrichment": enrichment()}
    analysis.summarize(results)          # used to raise KeyError on j1 (not in "hosts")

    payload = json.loads(sent["payload"].split("```json\n", 1)[1].rsplit("\n```", 1)[0])
    assert [h["host"] for h in payload["hostnames"]] == ["app.example.test"]
    assert payload["enrichment"]["wildcards"] == {
        "example.test": {"ips": ["1.1.1.1", "1.0.0.1"], "provider": "Fastly", "hosts_set_aside": 7}}


def test_mcp_enrich_summary_reports_wildcards(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: enrichment())
    result = mcp_server.enrich_hosts(["app.example.test", "j1.example.test"])
    assert result["wildcard_only_count"] == 7
    assert result["wildcards"]["example.test"]["hosts"] == 7
    assert result["wildcards"]["example.test"]["examples"][0] == "j1.example.test"
    assert "canonicals" not in result["wildcards"]["example.test"]   # short form in the summary


# --- grouped wildcard lines and certificate-backed names ---

def zone(n, examples, ips=("1.1.1.1",), provider="AWS CloudFront", private=False, certs=()):
    return {"ips": list(ips), "canonicals": [], "provider": provider, "private": private,
            "hosts": n, "examples": list(examples), "with_certificate": list(certs)}


def test_cdn_wildcard_in_many_subzones_prints_one_block(capsys):
    zones = {"example.test": zone(288, ["a.example.test"]),
             "acc-nocdn.example.test": zone(20, ["b.acc-nocdn.example.test"], ips=("1.0.0.1",)),
             "static.example.test": zone(8, ["c.static.example.test"]),
             "idm.example.test": zone(1, ["keycloak.idm.example.test"], certs=["keycloak.idm.example.test"]),
             "api.example.test": zone(1, ["docs.api.example.test"]),
             "ice.example.test": zone(1, ["x.ice.example.test"])}
    cli.show_wildcards(enrichment(wildcards=zones), "example.test")
    out = capsys.readouterr().out
    assert out.count("is a wildcard") == 0 and out.count("zones are wildcards") == 1
    assert "6 zones are wildcards -> AWS CloudFront: 319 host(s) resolve only through them" in out
    assert "Biggest: *.example.test (288), *.acc-nocdn (20), *.static (8)" in out and "and 1 more zones" in out
    assert "1 of them have their own certificate, so they're likely real: keycloak.idm.example.test" in out


def test_private_wildcards_with_different_ips_stay_apart(capsys):
    zones = {"acc.example.test": zone(3, ["a.acc.example.test"], ips=("10.54.0.1",), private=True),
             "dev.example.test": zone(2, ["a.dev.example.test"], ips=("10.55.0.1",), private=True)}
    cli.show_wildcards(enrichment(wildcards=zones), "example.test")
    out = capsys.readouterr().out
    assert "*.acc.example.test is a wildcard -> private IPs (10.54.0.1)" in out
    assert "*.dev.example.test is a wildcard -> private IPs (10.55.0.1)" in out


def test_certificate_names_come_from_certificate_sources_only():
    results = {"sources": {
        "crt.sh database": {"source": "crt.sh database", "subdomains": ["a.example.test"]},
        "certspotter": {"source": "certspotter", "subdomains": ["b.example.test"]},
        "subfinder": {"source": "subfinder", "subdomains": ["c.example.test"]},
        "otx": {"source": "otx", "subdomains": ["d.example.test"]}}}
    assert cli.certificate_names(results) == {"a.example.test", "b.example.test"}


def test_mark_certificates_lists_set_aside_hosts_a_certificate_names():
    data = enrichment()
    results = {"sources": {"crt.sh": {"source": "crt.sh", "subdomains": ["j2.example.test", "app.example.test"]}}}
    cli.mark_certificates(data, results)
    # app.example.test isn't set aside, so it isn't listed: only wildcard hosts are
    assert data["wildcards"]["example.test"]["with_certificate"] == ["j2.example.test"]
