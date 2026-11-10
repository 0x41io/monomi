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


def test_one_side_door_per_server_names_every_host_and_has_an_owner():
    # staging and dev both sit on the production server: one path that names both
    results = lab_results()
    results["subdomains"].append("dev")
    results["enrichment"]["hosts"]["dev"] = {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}
    results["email"]["verdict"]["verdict"] = "protected"
    out, ev = run(results)
    # Only one side door per IP, so the leaks stay in one path: closes P1
    assert [p["title"] for p in out["paths"]] == ["Use dev and staging as a side door into 198.51.100.7"]
    side = out["paths"][0]
    assert side["steps"][0]["text"].startswith("dev and staging are live")
    assert len(side["steps"][0]["evidence"]) == 2  # both risky-name facts
    # Two risky hosts = two actions; the version leaks only back a step up
    assert [a["evidence"] for a in side["actions"]] == [[e] for e in side["steps"][0]["evidence"]]
    fix = out["fix_first"]
    assert fix["actions"] == side["actions"]
    assert fix["closes"] == ["P1"]
    assert fix["actions"][0]["owners"] == ["server / infrastructure admin"]
    # The fix says what to do, not why the name matched a rule
    assert [a["what"] for a in fix["actions"]] == [
        "Take dev off the internet or restrict who can reach it",
        "Take staging off the internet or restrict who can reach it"]


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


def test_terminal_shows_paths_without_ai(capsys):
    from monomi import show_paths
    results = lab_results()
    out, ev = run(results)
    results["paths"] = out
    show_paths(results)
    text = capsys.readouterr().out
    assert "P1  HIGH  Send email as lab" in text
    assert "4. Lead: The server shows software versions" in text
    assert "Fix this first (DNS admin, email admin)" in text


def test_terminal_says_no_path_only_when_a_check_ran(capsys):
    from monomi import show_paths
    empty = {"paths": [], "fix_first": None, "more": 0}
    show_paths({"paths": empty})  # discovery only: nothing to chain, say nothing
    assert capsys.readouterr().out == ""
    show_paths({"paths": empty, "email": {}})
    assert "No attack path found" in capsys.readouterr().out


def test_names_reads_like_a_sentence():
    from paths import _names
    assert _names(["a"]) == "a"
    assert _names(["a", "b"]) == "a and b"
    assert _names(["a", "b", "c"]) == "a, b and c"
    assert _names(["a", "b", "c", "d", "e"]) == "a, b, c and 2 more"


def test_dangling_cname_under_cloud_provider_builds_no_path():
    results = lab_results()
    results["takeover"]["leads"] = [{"host": "oldapi", "cname": "gone-api.svc.us-east-1.amazonaws.com",
                                     "service": None, "claimable": False, "collected_at": None}]
    out, ev = run(results)
    fact = next(e for e in ev if e["host"] == "oldapi")
    assert fact["kind"] == "dangling_provider"
    assert "can-i-take-over-xyz" in fact["fact"]
    assert not any("oldapi" in p["title"] for p in out["paths"])


def side_doors(out):
    return [p for p in out["paths"] if "side door" in p["title"]]


def test_private_ip_is_never_a_side_door():
    # Internal addresses in public DNS can't be reached from the internet
    results = lab_results()
    for h in ("lab", "staging"):
        results["enrichment"]["hosts"][h] = {"ips": ["10.1.2.3"], "private_ips": ["10.1.2.3"],
                                             "provider": "PRIVATE IP"}
    out, ev = run(results)
    assert side_doors(out) == []


def test_host_on_several_ips_is_a_load_balancer():
    # Several IPs (one per cloud zone) = a load balancer, not one server: no side door
    results = lab_results()
    three = ["198.51.100.7", "198.51.100.8", "198.51.100.9"]
    for h in ("lab", "staging"):
        results["enrichment"]["hosts"][h]["ips"] = three
    out, ev = run(results)
    assert side_doors(out) == []


def test_many_hosts_on_one_ip_is_a_shared_front_door():
    # 11 more hosts on the same IP = shared load balancer, not one server
    results = lab_results()
    for i in range(11):
        results["subdomains"].append(f"app{i}")
        results["enrichment"]["hosts"][f"app{i}"] = {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}
    out, ev = run(results)
    assert side_doors(out) == []


def test_side_door_wording_follows_the_category():
    # An admin host is a way in through its login page, not "non-production"
    results = lab_results()
    results["subdomains"] = ["lab", "admin", "www"]
    results["sources"]["certlog"]["subdomains"] = results["subdomains"]
    hosts = results["enrichment"]["hosts"]
    hosts["admin"] = hosts.pop("staging")
    out, ev = run(results)
    door = side_doors(out)[0]
    assert door["steps"][0]["text"] == "admin is live and named like a login or remote-access host"
    assert door["steps"][2]["text"].startswith("Login and remote-access pages are where attackers try")


def test_vercel_ip_is_never_a_side_door():
    # The Yuga Labs case: Vercel's IP labeled AWS, and no --ports run to
    # mark it shared_edge. Two hosts on it are two Vercel sites, not one server.
    results = lab_results()
    for h in ("lab", "staging"):
        results["enrichment"]["hosts"][h] = {"ips": ["216.150.1.1"], "provider": "AWS"}
    out, ev = run(results)
    assert side_doors(out) == []


# ---------- fix groups (v1.10) ----------

def three_side_doors():
    """Three test hosts on the production server, email protected: one path."""
    results = lab_results()
    for h in ("dev", "uat"):
        results["subdomains"].append(h)
        results["enrichment"]["hosts"][h] = {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}
    results["email"]["verdict"]["verdict"] = "protected"
    return results


def test_one_host_never_closes_a_three_host_side_door():
    # The bug from the field: "fix one host, closes P1" on a three-host path
    out, ev = run(three_side_doors())
    assert len(out["paths"]) == 1
    fix = out["fix_first"]
    assert len(fix["actions"]) == 3
    assert [a["evidence"] for a in fix["actions"]] == [[e] for e in out["paths"][0]["steps"][0]["evidence"]]
    assert fix["closes"] == ["P1"]  # all three together
    assert fix["partial"] == [] and fix["still_required_actions"] == []


def test_a_fix_that_closes_alone_beats_a_group():
    # Email (one action, closes P1) wins over the side door's two actions
    results = lab_results()
    results["subdomains"].append("dev")
    results["enrichment"]["hosts"]["dev"] = {"ips": ["198.51.100.7"], "provider": "DigitalOcean"}
    out, ev = run(results)
    assert [len(p["actions"]) for p in out["paths"]] == [1, 2]
    fix = out["fix_first"]
    assert len(fix["actions"]) == 1 and fix["closes"] == ["P1"]


def test_known_flaws_are_one_upgrade_action():
    results = lab_results()
    results["enrichment"]["hosts"].pop("staging")  # no side door, so rule D builds the path
    results["subdomains"].remove("staging")
    results["email"]["verdict"]["verdict"] = "protected"
    out, ev = run(results)
    (path,) = out["paths"]
    assert path["title"] == "Exploit known flaws on 198.51.100.7"
    (action,) = path["actions"]
    assert action["what"] == "Upgrade or patch the server software on 198.51.100.7"
    assert action["evidence"] == path["steps"][0]["evidence"]


def test_partial_is_recorded_when_an_action_is_in_two_paths():
    from paths import _fix_first
    a = {"what": "fix a", "evidence": ["E1"], "owners": ["DNS admin"]}
    b = {"what": "fix b", "evidence": ["E2"], "owners": ["app owner"]}
    built = [{"id": "P1", "actions": [a, b]}, {"id": "P2", "actions": [a]}]
    fix = _fix_first(built)
    assert fix["actions"] == [a] and fix["closes"] == ["P2"]
    assert fix["partial"] == [{"path": "P1", "of": 2}]
    assert fix["still_required_actions"] == [b]


def test_fix_first_wording_never_says_one_of_several_closes():
    from paths import fix_first_parts, paths_appendix
    out, ev = run(three_side_doors())
    t = fix_first_parts(out["fix_first"])
    assert t["label"] == "Fix these 3 first"
    assert t["closes"] == "together they close P1"
    assert len(t["ids"]) == 3 and t["owners"] == "server / infrastructure admin"
    text = paths_appendix(out)
    assert "**Fix these 3 first**" in text and "together they close P1" in text
    assert "Fix this first" not in text


def test_terminal_shows_a_group_fix(capsys):
    from monomi import show_paths
    results = three_side_doors()
    out, ev = run(results)
    results["paths"] = out
    show_paths(results)
    text = capsys.readouterr().out
    assert "Fix these 3 first (server / infrastructure admin): Take dev off the internet" in text
    assert "matched rule word" not in text.split("Fix these 3 first")[1]
    assert "-> together they close P1" in text


def test_old_saved_paths_get_actions():
    from paths import upgrade_saved
    out, ev = run(three_side_doors())
    path = out["paths"][0]
    leaks = path["steps"][-1]["evidence"]
    # What v1.9 saved: a flat "fix" list (names + leaks) and a one-fact fix_first
    old = {"paths": [dict(path, fix=[e for a in path["actions"] for e in a["evidence"]] + leaks)],
           "fix_first": {"evidence": "E1", "fact": "x", "owners": [], "closes": ["P1"]}, "more": 0}
    del old["paths"][0]["actions"]
    new = upgrade_saved(old, ev)
    assert new["paths"][0]["actions"] == path["actions"]  # leaks dropped
    assert "fix" not in new["paths"][0]
    assert new["fix_first"] == out["fix_first"]
    assert upgrade_saved(out, ev) is out  # already new: left alone
