"""Tests for categorize.py: rule-based hostname categories."""

import pytest

from monomi.categorize import categorize, categorize_all

DOMAIN = "example.com"


@pytest.mark.parametrize("label, expected", [
    # Exact matches
    ("api", "app-api"),
    ("www", "content"),
    ("mta-sts", "email"),
    # Rule word followed by a number or hyphen still matches
    ("go2", "marketing"),
    ("go-eu", "marketing"),
    ("url824", "marketing"),
    # Rule word glued to other letters does NOT match
    ("gov", "uncategorized"),
    ("information", "uncategorized"),
    ("devices", "uncategorized"),
    ("gslink", "uncategorized"),
    # Riskier category wins, on either side of the hyphen
    ("dev-api", "non-production"),
    ("api-dev", "non-production"),
    # New words and categories (v1.6.2, from the MercadoLibre field run)
    ("is-opensearch-stg", "non-production"),
    ("auth-testing", "non-production"),
    ("sdl-kibana", "internal-tools"),
    ("puppetboard-open", "internal-tools"),
    ("tableau-old", "legacy"),
    ("oldies", "uncategorized"),
    ("prd", "uncategorized"),
    # New categories (v1.7, from the adminml.com and Amazon VRP field runs)
    ("scada", "iot-ot"),
    ("forklift-cam2", "iot-ot"),
    ("cameras", "iot-ot"),
    ("camp", "uncategorized"),
    ("plc-dev", "non-production"),
    ("seller", "partner-portal"),
    ("vendor-portal", "partner-portal"),
    ("brandregistry", "partner-portal"),
    ("partnership", "uncategorized"),
    # Management consoles and extranet/intranet (v1.22, from the Marionnaud field run)
    ("cp-unifi", "management"),
    ("mdm", "management"),
    ("mdm2", "management"),
    ("vcenter-eu", "management"),
    ("ilo", "management"),
    ("ilo4", "management"),
    ("pilot", "uncategorized"),
    ("milo", "uncategorized"),
    ("ilona", "uncategorized"),
    ("unified", "uncategorized"),
    ("extranet", "access"),
    ("intranet", "access"),
    ("extranets", "uncategorized"),
])
def test_label_categories(label, expected):
    result = categorize(f"{label}.{DOMAIN}", DOMAIN)
    assert result["category"] == expected


def test_apex():
    result = categorize("example.com", DOMAIN)
    assert result == {"category": "apex", "reason": "the domain itself"}


def test_case_and_trailing_dot_ignored():
    result = categorize("API.Example.com.", DOMAIN)
    assert result["category"] == "app-api"


def test_deeper_label_is_checked():
    result = categorize("eu.dev.example.com", DOMAIN)
    assert result["category"] == "non-production"


def test_reason_names_matched_part():
    result = categorize("api-dev.example.com", DOMAIN)
    assert result["reason"] == "part 'dev' of label 'api-dev' matched rule word 'dev'"


def test_categorize_all_one_entry_per_hostname():
    hosts = ["example.com", "www.example.com", "gslink.example.com"]
    result = categorize_all(hosts, DOMAIN)
    assert set(result) == set(hosts)
    assert result["gslink.example.com"]["category"] == "uncategorized"


def test_management_reason_names_the_matched_part():
    result = categorize("cp-unifi.example.com", DOMAIN)
    assert result == {"category": "management",
                      "reason": "part 'unifi' of label 'cp-unifi' matched rule word 'unifi'"}


def test_management_ranks_right_after_access():
    # A name that is both a login and a console counts as access; anything
    # riskier (non-production) still wins over management.
    assert categorize("admin-unifi.example.com", DOMAIN)["category"] == "access"
    assert categorize("extranet-citrix.example.com", DOMAIN)["category"] == "access"
    assert categorize("mdm-dev.example.com", DOMAIN)["category"] == "non-production"
    # ...and management wins over the categories after it
    assert categorize("api.mdm.example.com", DOMAIN)["category"] == "management"
    assert categorize("ilo-jenkins.example.com", DOMAIN)["category"] == "management"


def test_management_order_in_rules():
    from monomi.categorize import RULES
    names = [name for name, _ in RULES]
    assert names.index("management") == names.index("access") + 1


def test_short_non_production_words_v1_23():
    # From the Superdrug and Exoscale runs
    for host in ["www-tst", "etst", "euat", "pre-appcms", "pre", "pp-portal", "pp2"]:
        assert categorize(f"{host}.shop.test", "shop.test")["category"] == "non-production", host
    # Matched like every word: whole label, or the word then a number or hyphen
    for host in ["press", "prem", "ppportal", "tstore", "euatlas"]:
        assert categorize(f"{host}.shop.test", "shop.test")["category"] != "non-production", host
