"""Scope file for ACTIVE checks: which hosts Monomi may send requests to.

Pure logic: reads a file you give it and answers "is this host in scope?".
No network, no DNS. The MCP server and the CLI use it to refuse active
requests to anything the person running Monomi didn't approve.

File format (one rule per line, so a bug bounty program's scope list can
be pasted in):

    # comments and blank lines are ignored
    example.com          exactly this host
    *.example.com        any subdomain (a.example.com, a.b.example.com),
                         NOT example.com itself: list it separately
    !blog.example.com    exclusion: never in scope, even if a rule above
                         matches. Exclusions always win.

Rules are case-insensitive; one trailing dot and a port (":443") are
dropped. Lines that aren't a hostname rule are rejected with the reason
(they don't count, and setup/doctor show them). IP addresses and CIDR
ranges aren't supported yet: scope is by hostname only, and the IP a
host resolves to isn't checked.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

# One DNS label: letters, digits, hyphens (not at either end), underscores,
# 1-63 characters. Same rule as mcp_server.LABEL_RE.
LABEL_RE = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")

PORT_RE = re.compile(r":\d{1,5}$")

# Suffixes that many unrelated owners share, so a rule for one of them
# would put thousands of other people's sites in scope. Not the full
# Public Suffix List (that's a later release): the common multi-part
# country suffixes plus the big hosting platforms. A rule is rejected only
# if its domain IS one of these: example.co.uk is fine, *.co.uk isn't.
SHARED_SUFFIXES = frozenset({
    # country suffixes with a second level
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "go.kr",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx", "gob.mx",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "com.tw", "com.sg", "com.my", "com.ph", "co.id", "co.th",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "co.za", "org.za", "gov.za",
    "com.ar", "com.co", "com.pe", "com.tr", "com.ua", "com.pl", "com.ru",
    "co.il", "org.il", "gov.il",
    # hosting platforms: every customer gets a subdomain of these
    "github.io", "githubusercontent.com", "gitlab.io",
    "vercel.app", "now.sh", "netlify.app", "netlify.com", "pages.dev", "workers.dev",
    "herokuapp.com", "herokudns.com", "fly.dev", "onrender.com", "railway.app",
    "cloudfront.net", "amazonaws.com", "elasticbeanstalk.com", "awsapps.com",
    "azurewebsites.net", "cloudapp.net", "azureedge.net", "azurefd.net",
    "blob.core.windows.net", "trafficmanager.net",
    "appspot.com", "web.app", "firebaseapp.com", "run.app", "cloudfunctions.net",
    "storage.googleapis.com", "googleusercontent.com",
    "fastly.net", "global.ssl.fastly.net", "akamaized.net", "edgekey.net",
    "edgesuite.net", "cdn.cloudflare.net",
    "shopify.com", "myshopify.com", "wixsite.com", "squarespace.com",
    "wordpress.com", "blogspot.com", "webflow.io", "framer.app", "framer.website",
    "ngrok.io", "ngrok-free.app", "repl.co", "glitch.me", "surge.sh",
    "readthedocs.io", "statuspage.io", "zendesk.com", "freshdesk.com",
})


class _Unscoped:
    """Marker the CLI passes when it runs active checks without --scope.

    The fetch layer's scope argument has no default on purpose: a caller
    that forgets it crashes (and the tests catch it) instead of silently
    skipping the check. Passing this marker says "a person ran the CLI
    without a scope file" out loud."""

    def __repr__(self):
        return "UNSCOPED_CLI"


UNSCOPED_CLI = _Unscoped()


class OutOfScope(requests.RequestException):
    """Raised by the fetch layer instead of sending a request to a host the
    scope doesn't allow. It's a kind of requests error on purpose: every
    place that already handles "this host didn't answer" handles this too,
    so it can never crash a scan halfway, and no request is ever sent."""


@dataclass(frozen=True)
class Rule:
    """One accepted line of the scope file."""
    text: str        # the rule as written in the file (after cleanup), e.g. "!*.dev.example.com"
    domain: str      # the name part, e.g. "dev.example.com"
    wildcard: bool   # True for "*.domain" (subdomains only)
    exclude: bool    # True for "!rule"

    def matches(self, host: str) -> bool:
        if self.wildcard:
            return host.endswith("." + self.domain)
        return host == self.domain


@dataclass(frozen=True)
class Match:
    """The answer to "is this host in scope?"."""
    host: str
    allowed: bool
    rule: str | None  # the rule that allowed it (None if refused)
    reason: str       # "allowed by *.example.com", "excluded by !blog.example.com", ...


@dataclass
class Scope:
    """A parsed scope file. Build one with load() or from_bytes()."""
    path: str | None
    sha256: str
    rules: list[Rule] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)  # {"line": n, "text": ..., "reason": ...}
    error: str | None = None  # set if the file couldn't be read or decoded

    @property
    def inclusions(self) -> list[Rule]:
        return [r for r in self.rules if not r.exclude]

    @property
    def exclusions(self) -> list[Rule]:
        return [r for r in self.rules if r.exclude]

    def problem(self) -> str | None:
        """Why this scope can't be used for active checks, or None if it can."""
        if self.error:
            return self.error
        if not self.inclusions:
            if self.exclusions:
                return "the scope file has only exclusions, so nothing is in scope"
            return "the scope file has no valid rules"
        return None

    def match(self, host: str) -> Match:
        """Is this host in scope? Exclusions are checked first and always win."""
        h = normalize_host(host)
        if h is None:
            return Match(host, False, None, "not a valid hostname")
        if self.problem():
            return Match(h, False, None, f"no usable scope: {self.problem()}")
        for rule in self.exclusions:
            if rule.matches(h):
                return Match(h, False, None, f"excluded by {rule.text}")
        for rule in self.inclusions:
            if rule.matches(h):
                return Match(h, True, rule.text, f"allowed by {rule.text}")
        return Match(h, False, None, "no rule matches")


def normalize_host(host) -> str | None:
    """Lowercase a hostname and drop one trailing dot. None if it isn't a
    valid ASCII hostname (so it can never be in scope)."""
    if not isinstance(host, str) or not host.isascii():
        return None
    h = host.strip().lower()
    if h.endswith("."):
        h = h[:-1]
    if _name_problem(h):
        return None
    return h


def _name_problem(name: str) -> str | None:
    """Why `name` (lowercased, no wildcard) isn't a hostname, or None."""
    if not name:
        return "empty"
    if len(name) > 253:
        return "too long to be a hostname (253 characters max)"
    if not all(LABEL_RE.fullmatch(label) for label in name.split(".")):
        return "not a valid hostname (only letters, digits, hyphens and dots)"
    return None


def parse_rule(raw: str) -> tuple[Rule | None, str | None]:
    """Parse one line (comments already removed). Returns (rule, None) or
    (None, reason it was rejected)."""
    text = raw.strip()
    if not text.isascii():
        return None, "contains non-ASCII characters (internationalized names aren't supported)"
    text = text.lower()

    exclude = text.startswith("!")
    if exclude:
        text = text[1:].strip()
        if not text:
            return None, "a lone '!' has nothing to exclude"
        if text.startswith("!"):
            return None, "more than one '!'"

    # Checked before the URL and port rules: a CIDR has a "/" and IPv6 has ":"
    try:
        ipaddress.ip_network(text, strict=False)
        return None, "IP addresses and ranges aren't supported yet (scope is by hostname)"
    except ValueError:
        pass

    if "://" in text or "/" in text:
        return None, "looks like a URL: write just the hostname, without https:// or a path"

    text = PORT_RE.sub("", text)   # "example.com:443" -> "example.com"
    if text.endswith("."):         # one trailing dot only
        text = text[:-1]

    if text == "*":
        return None, "a bare '*' would allow every host"
    wildcard = text.startswith("*.")
    domain = text[2:] if wildcard else text
    if "*" in domain:
        return None, "'*' is only allowed as the first label ('*.example.com')"

    problem = _name_problem(domain)
    if problem:
        return None, problem
    if "." not in domain:
        return None, f"'{domain}' is a single label (a whole top-level domain or a local name)"
    if domain in SHARED_SUFFIXES:
        return None, f"'{domain}' is shared by many unrelated owners: name your own domain under it"

    shown = ("!" if exclude else "") + ("*." if wildcard else "") + domain
    return Rule(shown, domain, wildcard, exclude), None


def parse(text: str) -> tuple[list[Rule], list[dict]]:
    """Parse the whole file. Returns (rules, rejected lines with reasons)."""
    rules, rejected = [], []
    for n, line in enumerate(text.splitlines(), start=1):
        body = line.split("#", 1)[0]   # "#" starts a comment, also mid-line
        if not body.strip():
            continue
        rule, reason = parse_rule(body)
        if rule:
            rules.append(rule)
        else:
            rejected.append({"line": n, "text": line.strip()[:120], "reason": reason})
    return rules, rejected


def from_bytes(data: bytes, path: str | None = None) -> Scope:
    """Hash the exact bytes, then parse those same bytes. Setup shows and
    approves this Scope, and the server checks this hash, so what you saw
    is exactly what's enforced."""
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8-sig")  # -sig: Windows Notepad may add a BOM
    except UnicodeDecodeError:
        return Scope(path, digest, error="the scope file isn't UTF-8 text")
    rules, rejected = parse(text)
    return Scope(path, digest, rules, rejected)


def check_url(scope, url: str) -> str | None:
    """The last check before an ACTIVE request goes out: is this URL's host
    in scope? Returns the rule that allowed it (None for UNSCOPED_CLI) or
    raises OutOfScope.

    The host is read from the URL itself, never from a separate argument:
    this check exists to catch bugs, so it doesn't trust the caller's label.
    `scope` must be a Scope or UNSCOPED_CLI; anything else (None, a typo,
    a forgotten argument passed through) is a TypeError, never a pass."""
    if scope is UNSCOPED_CLI:
        return None
    if not isinstance(scope, Scope):
        raise TypeError(f"scope must be a Scope or scope.UNSCOPED_CLI, not {scope!r}")
    try:
        host = urlparse(url).hostname
    except ValueError:
        host = None
    m = scope.match(host)
    if not m.allowed:
        raise OutOfScope(f"{host or url}: out of scope ({m.reason})")
    return m.rule


def split(scope, hosts) -> tuple[list[str], list[dict]]:
    """Sort hosts into (in scope, out of scope with the reason), before any
    DNS lookup. With UNSCOPED_CLI every host is in."""
    if scope is UNSCOPED_CLI:
        return list(hosts), []
    if not isinstance(scope, Scope):
        raise TypeError(f"scope must be a Scope or scope.UNSCOPED_CLI, not {scope!r}")
    inside, outside = [], []
    for host in hosts:
        m = scope.match(host)
        if m.allowed:
            inside.append(host)
        else:
            outside.append({"host": host, "reason": m.reason})
    return inside, outside


NO_SCOPE = ("no scope file is approved, so active checks refuse every host. "
            "The person running Monomi sets one with "
            "`python monomi.py mcp setup --scope FILE` (and types yes)")


def check_pinned(path: str | None, sha256: str | None) -> tuple[Scope | None, str | None]:
    """Load the approved scope file and check it's exactly what was approved.

    Returns (scope, None) when it can be used, or (scope or None, why not).
    The MCP server calls this once at startup and doctor calls it to report,
    so both always give the same answer."""
    if not path:
        return None, NO_SCOPE
    if not sha256:
        return None, ("the scope file has no approved hash; run "
                      "`python monomi.py mcp setup --scope FILE` again")
    s = load(path)
    if s.problem():
        return s, s.problem()
    if s.sha256 != sha256.lower():
        return s, ("the scope file changed since it was approved, so active checks "
                   "refuse until you approve it again: "
                   f"`python monomi.py mcp setup --scope {path}` (and type yes)")
    return s, None


def load(path: str) -> Scope:
    """Read the scope file once and parse it. Never raises: a missing or
    unreadable file gives a Scope whose problem() says why."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return Scope(path, "", error=f"the scope file is missing: {path}")
    except OSError as e:
        return Scope(path, "", error=f"the scope file can't be read: {e.strerror or e}")
    return from_bytes(data, path)
