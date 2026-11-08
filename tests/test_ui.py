"""Tests for ui.py: what the terminal says about Shodan results."""

from ui import exposure_table


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
