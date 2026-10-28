"""Rule-based hostname categories for Monomi.

Tags each hostname with a category based on the words in its name.
Pure code: no network calls, no AI. The same input always gives the
same output, so a category is a fact with a stated reason, not a guess.
"""

# Each rule is (category, words to look for).
# ORDER MATTERS: the first rule that matches wins. Riskier categories
# come first, so "dev-api.example.com" counts as non-production.
RULES = [
    ("non-production", ["dev", "staging", "stage", "test", "uat", "qa", "sandbox", "preview"]),
    ("access", ["admin", "vpn", "sso", "login", "auth", "portal", "remote"]),
    ("app-api", ["api", "graphql", "ws", "websockets", "app"]),
    ("email", ["mta-sts", "mail", "smtp", "imap", "autodiscover", "webmail", "mx"]),
    ("marketing", ["go", "info", "links", "click", "url", "email", "events", "lp"]),
    ("content", ["www", "docs", "blog", "support", "help", "status", "cdn", "static", "design"]),
]


def _label_matches(label, word):
    """True if a label is the word, or the word followed by a number or hyphen.

    "dev" matches "dev", "dev2" and "dev-eu", but NOT "devices".
    """
    if label == word:
        return True
    if label.startswith(word):
        rest = label[len(word):]
        return rest[0].isdigit() or rest[0] == "-"
    return False

def _find_match(label, word):
    """Return the part of the label that matched the word, or None.

    Checks the whole label first, so rule words with a hyphen
    (like "mta-sts") still match. If the whole label doesn't match,
    checks each hyphen-separated piece: "api-dev" -> "api", "dev".
    """
    if _label_matches(label, word):
        return label
    if "-" in label:
        for part in label.split("-"):
            if part and _label_matches(part, word):
                return part
    return None


def categorize(hostname, domain):
    """Return {"category": ..., "reason": ...} for one hostname."""
    hostname = hostname.lower().rstrip(".")
    domain = domain.lower().rstrip(".")

    if hostname == domain:
        return {"category": "apex", "reason": "the domain itself"}

    # Cut the base domain off: "mta-sts.managed.hackerone.com" -> "mta-sts.managed"
    if hostname.endswith("." + domain):
        sub = hostname[: -len(domain) - 1]
    else:
        sub = hostname

    labels = sub.split(".")

    for category, words in RULES:
        for label in labels:
            for word in words:
                matched = _find_match(label, word)
                if matched == label:
                    return {
                        "category": category,
                        "reason": f"label '{label}' matched rule word '{word}'",
                    }
                if matched:
                    return {
                        "category": category,
                        "reason": f"part '{matched}' of label '{label}' matched rule word '{word}'",
                    }
    return {"category": "uncategorized", "reason": "no rule matched"}


def categorize_all(hostnames, domain):
    """Categorize a list of hostnames. Returns {hostname: result}."""
    return {h: categorize(h, domain) for h in hostnames}
