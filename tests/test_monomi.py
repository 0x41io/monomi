import pytest

from monomi import clean_domain


def test_clean_domain_strips_url_parts():
    assert clean_domain("https://WWW.Example.com/login?x=1") == "example.com"
    assert clean_domain("example.com:8443") == "example.com"
    assert clean_domain("example.com.") == "example.com"


def test_clean_domain_keeps_real_subdomains():
    assert clean_domain("shop.example.co.uk") == "shop.example.co.uk"


def test_clean_domain_rejects_bad_input():
    with pytest.raises(ValueError):
        clean_domain("not a domain")
    with pytest.raises(ValueError):
        clean_domain("localhost")
