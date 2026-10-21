from common import is_hostname, subdomains_in


def test_is_hostname_accepts_normal_names():
    assert is_hostname("example.com")
    assert is_hostname("api-v2.staging.example.com")


def test_is_hostname_rejects_junk():
    assert not is_hostname("not a hostname")    # spaces
    assert not is_hostname("admin@example.com")  # email address
    assert not is_hostname("evil\x1b[31m.com")   # terminal escape code
    assert not is_hostname("")


def test_subdomains_in_cleans_and_filters():
    names = ["*.Example.com", "foo.example.com", "foo.example.com", "x.other.com", "bad name"]
    assert subdomains_in(names, "example.com") == ["example.com", "foo.example.com"]


def test_subdomains_in_ignores_lookalike_domains():
    # "notexample.com" ends with "example.com" but is a different domain
    assert subdomains_in(["notexample.com", "a.example.com"], "example.com") == ["a.example.com"]
