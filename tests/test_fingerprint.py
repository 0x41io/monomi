from fingerprint import detect


def techs(headers):
    """Run detect() on fake headers and return just the tech names."""
    return [t["tech"] for t in detect({"headers": headers})]


def test_detect_reads_naming_headers_and_versions():
    found = detect({"headers": {"server": "Apache/2.4.41 (Ubuntu)"}})
    assert found[0]["tech"] == "Apache/2.4.41 (Ubuntu)"
    assert found[0]["version"] == "2.4.41"
    assert found[0]["evidence"] == "server: Apache/2.4.41 (Ubuntu)"


def test_detect_no_version_when_none_leaked():
    found = detect({"headers": {"x-powered-by": "Next.js"}})
    assert found[0]["version"] is None


def test_detect_skips_repeats():
    # server + cf-ray both say Cloudflare; PHP/7.4.3 + PHPSESSID both say PHP
    headers = {"server": "cloudflare", "cf-ray": "abc", "x-powered-by": "PHP/7.4.3", "set-cookie": "PHPSESSID=1"}
    assert techs(headers) == ["cloudflare", "PHP/7.4.3"]


def test_detect_spots_cookies():
    assert techs({"set-cookie": "wordpress_test_cookie=1; path=/"}) == ["WordPress"]


def test_detect_nothing_to_find():
    assert techs({"content-type": "text/html", "date": "Thu, 22 Oct 2026"}) == []
