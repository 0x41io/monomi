"""
Security headers check: which browser protections is a site missing?

Reads the headers --fingerprint already fetched, so it makes ZERO extra
requests. Only looks at real pages (HTTP 2xx): a redirect isn't the page
people actually see, so its headers don't tell us much.
"""

# HSTS should last at least 180 days to really protect returning visitors.
MIN_HSTS_AGE = 15552000  # 180 days in seconds

def hsts_max_age(value: str):
    """'max-age=31536000; includeSubDomains' -> 31536000 (None if missing/broken)."""
    for part in value.split(";"):
        name, _, number = part.strip().partition("=")
        if name.lower() == "max-age":
            try:
                return int(number.strip().strip('"'))
            except ValueError:
                return None
    return None

def check_headers(result: dict) -> list[dict]:
    """Turn fetch_headers() output into a list of header problems.

    Each item: {"header", "problem", "detail"}. Empty list = nothing to flag,
    or the response wasn't a real page (not 2xx) so we didn't judge it.
    """
    if not 200 <= result["status"] < 300:
        return []

    headers = result["headers"]
    issues = []

    def flag(header, problem, detail):
        issues.append({"header": header, "problem": problem, "detail": detail})

    # 1. HSTS: tells browsers "always use HTTPS here"
    hsts = headers.get("strict-transport-security")
    if hsts is None:
        flag("Strict-Transport-Security", "missing",
             "browsers aren't told to always use HTTPS")
    else:
        age = hsts_max_age(hsts)
        if age is None or age < MIN_HSTS_AGE:
            flag("Strict-Transport-Security", "weak",
                 f"max-age is under 180 days ({hsts})")

    # 2. CSP: limits which scripts can run (main defense against XSS)
    csp = headers.get("content-security-policy", "")
    if not csp:
        flag("Content-Security-Policy", "missing",
             "no limit on which scripts can run (XSS defense)")

    # 3. Clickjacking: X-Frame-Options, OR CSP frame-ancestors (the modern way)
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        flag("X-Frame-Options", "missing",
             "page can be framed by other sites (clickjacking); no CSP frame-ancestors either")

    # 4. Stops browsers guessing file types
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        flag("X-Content-Type-Options", "missing",
             "not set to nosniff, so browsers may guess content types")

    # 5. Controls how much of the URL leaks to other sites
    if "referrer-policy" not in headers:
        flag("Referrer-Policy", "missing",
             "full URLs may leak to other sites in the Referer header")

    return issues

if __name__ == "__main__":
    import sys
    from fingerprint import fetch_headers

    result = fetch_headers(sys.argv[1])
    print(f"{result['url']}  ->  HTTP {result['status']}")
    if not 200 <= result["status"] < 300:
        print("  not a real page (redirect or error), so headers weren't judged")
    else:
        issues = check_headers(result)
        if not issues:
            print("  all checked security headers look fine")
        for i in issues:
            print(f"  {i['header']}: {i['problem']}  ({i['detail']})")
