from headers import check_headers, hsts_max_age


def problems(status, headers):
    """Run check_headers() on fake data and return {header: problem}."""
    issues = check_headers({"status": status, "headers": headers})
    return {i["header"]: i["problem"] for i in issues}


# A page with every protection set correctly
GOOD = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def test_good_page_has_no_issues():
    assert problems(200, GOOD) == {}


def test_bare_page_misses_all_five():
    assert problems(200, {}) == {
        "Strict-Transport-Security": "missing",
        "Content-Security-Policy": "missing",
        "X-Frame-Options": "missing",
        "X-Content-Type-Options": "missing",
        "Referrer-Policy": "missing",
    }


def test_redirects_are_not_judged():
    assert problems(301, {}) == {}


def test_short_hsts_is_weak():
    headers = dict(GOOD)
    headers["strict-transport-security"] = "max-age=300"
    assert problems(200, headers) == {"Strict-Transport-Security": "weak"}


def test_csp_frame_ancestors_counts_as_clickjacking_protection():
    headers = dict(GOOD)
    headers["content-security-policy"] = "frame-ancestors 'none'"
    del headers["x-frame-options"]
    assert problems(200, headers) == {}


def test_hsts_max_age_parsing():
    assert hsts_max_age("max-age=31536000; includeSubDomains") == 31536000
    assert hsts_max_age('max-age="600"') == 600
    assert hsts_max_age("max-age=abc") is None
    assert hsts_max_age("includeSubDomains") is None
