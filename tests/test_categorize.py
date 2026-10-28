"""Tests for categorize.py: rule-based hostname categories."""

import pytest

from categorize import categorize, categorize_all

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
