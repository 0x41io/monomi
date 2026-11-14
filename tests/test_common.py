from monomi.common import is_hostname, subdomains_in


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


def test_parse_version_compares_as_numbers():
    from monomi.common import parse_version
    assert parse_version("1.15.0") == (1, 15, 0)
    # As text "1.15.0" < "1.9.0"; as numbers it's newer, which is what counts
    assert "1.15.0" < "1.9.0"
    assert parse_version("1.15.0") > parse_version("1.9.0")
    assert parse_version("1.14.1") < parse_version("1.15.0") < parse_version("2.0.0")


def test_parse_version_only_accepts_x_y_z():
    from monomi.common import parse_version
    for bad in ["1.15", "v1.15.0", "1.15.0rc1", " 1.15.0", "1.15.0\n", "", "1.15.x", None, 1150, (1, 15, 0)]:
        assert parse_version(bad) is None, bad


def test_scan_version():
    from monomi.common import scan_version
    assert scan_version({"monomi_version": "1.15.0", "target": "lab"}) == (1, 15, 0)
    assert scan_version({"target": "lab"}) is None  # saved before v1.15.0
    assert scan_version({"monomi_version": "garbled"}) is None
