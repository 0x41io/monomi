"""Tests for ui.py: what the terminal says about Shodan results."""

from monomi.ui import exposure_table


def edge_ip():
    return {"hosts": ["www"], "ports": [80, 443, 8443], "vulns": [], "risky": [],
            "shared_edge": True}


def test_own_ip_with_no_shodan_data_is_called_checked(capsys):
    # The 41xlab case: the Droplet was checked, Shodan just has nothing on it yet
    exposure = {"ips": {"104.21.9.101": edge_ip()},
                "nothing_seen": {"64.227.89.72": {"hosts": ["lab"], "shared_edge": False}}}
    exposure_table(exposure)
    text = capsys.readouterr().out
    assert "Shodan has nothing on record for the target's own 1 IP(s)" in text
    assert "none of the target's own servers are visible" not in text


def test_only_cdn_ips_still_says_nothing_visible(capsys):
    exposure = {"ips": {"104.21.9.101": edge_ip()}, "nothing_seen": {}}
    exposure_table(exposure)
    assert "none of the target's own servers are visible" in capsys.readouterr().out


def test_someone_elses_server_is_one_line_never_a_row(capsys):
    # v1.23.1: Google's front end with CVEs isn't listed as the target's server
    google = {"hosts": ["ecom"], "ports": [80, 443], "vulns": ["CVE-2021-41184", "CVE-2016-7103"],
              "risky": [], "shared_edge": False, "not_own": "third-party hosting (Google front end)"}
    own = {"hosts": ["app"], "ports": [443, 8080], "vulns": [], "risky": [], "shared_edge": False}
    exposure_table({"ips": {"216.239.32.21": google, "9.9.9.9": own}, "nothing_seen": {}})
    text = capsys.readouterr().out
    assert "1 IP(s) are someone else's server (third-party hosting (Google front end)), with 2 CVE(s) " \
           "that belong to that service, not the target: not shown." in text
    assert "216.239.32.21" not in text and "9.9.9.9" in text
