# Hostnames without dots on purpose: the chat app turns dotted names into
# Markdown links when code is copied. The path rules don't care.
from evidence import build_evidence
from paths import build_paths


def lab_results():
    """Like the 41xlab lab: apex + staging on one server, www behind a CDN."""
    hosts = ["lab", "staging", "www"]
    return {
        "target": "lab",
        "subdomains": hosts,
        "sources": {"certlog": {"source": "certlog", "subdomains": hosts}},
        "enrichment": {
            "hosts": {
                "lab": {"ips": ["198.51.100.7"], "provider": "DigitalOcean"},
                "staging": {"ips": ["198.51.100.7"], "provider": "DigitalOcean"},
                "www": {"ips": ["203.0.113.9"], "provider": "Cloudflare"},
            },
            "private_ip_hosts": [],
        },
        "fingerprint": {
            "hosts": {
                h: {"collected_at": None, "status": 200, "header_issues": [],
                    "techs": [{"tech": "nginx", "version": "1.28.3", "evidence": "Server header"}]}
                for h in ["lab", "staging"]
            },
        },
        "email": {
            "collected_at": None,
            "spf": {"record": None, "issues": []},
            "dmarc": {"record": None, "issues": []},
            "dkim": {"selectors": [], "issues": []},
            "verdict": {"verdict": "spoofable", "summary": "no DMARC", "notes": []},
        },
        "takeover": {"leads": [], "stale": [], "checked": 3, "errors": [], "collected_at": None},
    }


def run(results):
    ev = build_evidence(results)
    return build_paths(results, ev), ev


def test_lab_gives_email_and_side_door_paths():
    out, ev = run(lab_results())
    titles = [p["title"] for p in out["paths"]]
    assert titles == ["Send email as lab", "Use staging as a side door into 198.51.100.7"]
    assert [p["id"] for p in out["paths"]] == ["P1", "P2"]
    side = out["paths"][1]
    assert side["strength"] == "Lead"  # the version step needs checking
    assert [s["label"] for s in side["steps"]] == ["Observed", "Observed", "Inference", "Lead"]
    # No separate "known flaws" path for an IP the side door already covers
    assert not any(t.startswith("Exploit") for t in titles)


def test_every_step_cites_real_evidence():
    out, ev = run(lab_results())
    known = {e["id"] for e in ev}
    for p in out["paths"]:
        for s in p["steps"]:
            assert s["evidence"], (p["title"], s["text"])
            assert set(s["evidence"]) <= known


def test_clean_target_has_no_paths():
    results = lab_results()
    results["subdomains"] = ["lab"]
    results["enrichment"]["hosts"] = {"lab": {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}}
    results["fingerprint"]["hosts"] = {}
    results["email"]["verdict"]["verdict"] = "protected"
    out, _ = run(results)
    assert out == {"paths": [], "fix_first": None, "more": 0}


def test_cdn_ip_is_never_a_side_door():
    results = lab_results()
    results["enrichment"]["hosts"]["staging"] = {"ips": ["203.0.113.9"], "provider": "Cloudflare"}
    out, _ = run(results)
    assert not any("side door" in p["title"] for p in out["paths"])


def test_takeover_path_chains_into_spoofed_email():
    results = lab_results()
    results["takeover"]["leads"] = [{"host": "oldapp", "cname": "gone-app", "service": "Azure App Service",
                                     "claimable": True, "collected_at": None}]
    out, ev = run(results)
    # Both are High; the email path is surer (no Lead step), so it comes first
    assert [p["title"] for p in out["paths"][:2]] == ["Send email as lab", "Take over oldapp"]
    takeover = out["paths"][1]
    assert takeover["strength"] == "Lead"
    assert "linking to oldapp" in takeover["steps"][-1]["text"]
    # Each fix closes one path here, so the tie goes to the first path
    assert out["fix_first"]["closes"] == ["P1"]


def test_exposed_service_ranks_right_after_email():
    results = lab_results()
    results["exposure"] = {"ips": {"198.51.100.20": {"shared_edge": False, "hosts": ["db"], "ports": [5432],
                                                     "tags": [], "risky": ["5432/PostgreSQL"], "vulns": []}}}
    out, ev = run(results)
    titles = [p["title"] for p in out["paths"]]
    assert titles[:2] == ["Send email as lab", "Attack the exposed services on 198.51.100.20"]


def test_one_side_door_per_server_and_its_fix_has_an_owner():
    # staging and dev both sit on the production server: one path, not two
    results = lab_results()
    results["subdomains"].append("dev")
    results["enrichment"]["hosts"]["dev"] = {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}
    results["email"]["verdict"]["verdict"] = "protected"
    out, ev = run(results)
    # Only one side door per IP, so the leaks stay in one path: closes P1
    assert [p["title"] for p in out["paths"]] == ["Use staging as a side door into 198.51.100.7"]
    fix = out["fix_first"]
    assert fix["closes"] == ["P1"]
    assert fix["owners"] == ["server / infrastructure admin"]


def test_paths_are_capped():
    results = lab_results()
    results["takeover"]["leads"] = [{"host": f"app{i}", "cname": f"gone{i}", "service": "Azure App Service",
                                     "claimable": True, "collected_at": None} for i in range(12)]
    out, _ = run(results)
    assert len(out["paths"]) == 10
    assert out["more"] == 4  # 12 takeovers + email + side door = 14


def test_check_paths_finds_left_out_and_made_up_paths():
    from paths import check_paths
    out, _ = run(lab_results())  # P1 and P2
    assert check_paths("### P1: email\n### P2: side door", out) == ([], [])
    assert check_paths("### P1: email only", out) == (["P2"], [])
    assert check_paths("### P1 ### P2 ### P3", out) == ([], ["P3"])
    # Words like HTTP2 or SP1 aren't path IDs
    assert check_paths("P1 P2 over HTTP2, SP1", out) == ([], [])


def test_appendix_lists_paths_and_fix_first():
    from paths import paths_appendix
    out, _ = run(lab_results())
    text = paths_appendix(out)
    assert "**P1: Send email as lab** (High, weakest step: Inference)" in text
    assert "4. Lead: The server shows software versions" in text
    assert "**Fix this first**" in text and "owner: DNS admin, email admin" in text


def test_appendix_says_when_no_path_was_found():
    from paths import paths_appendix
    text = paths_appendix({"paths": [], "fix_first": None, "more": 0})
    assert "No attack path found" in text
    assert "Fix this first" not in text
