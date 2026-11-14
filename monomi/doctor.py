"""
monomi doctor: is Monomi set up right, and can it reach what it needs?

    python monomi.py doctor

Every check returns one or more results, each with a status:
  ok    works
  warn  a feature is weaker or off, but scans still work
  fail  something is broken: fix it before relying on Monomi
Warnings and failures come with a one-line fix.
Exit code 1 if anything failed, so scripts can check it.
"""

import argparse
import importlib.metadata
import json
import os
import platform
import re
import socket
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests

from monomi import activelog, aws_ranges, dnscheck, internetdb, mcp_setup, scope, threatintel, ui
from monomi.collectors import certspotter, crtsh, crtsh_db, otx, pacing, saved
from monomi.common import USER_AGENT

OK, WARN, FAIL = "ok", "warn", "fail"
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIREMENTS = os.path.join(HERE, "requirements.txt")
MIN_PYTHON = (3, 10)
# Built from pieces so chat apps don't turn it into a link when pasting
CONSOLE = "console.anthropic" + ".com"

# A name that always exists, for DNS and Cert Spotter checks
EXAMPLE = "example" + ".com"
TIMEOUT = 10  # seconds per network check
HEADERS = {"User-Agent": USER_AGENT}

# Packages Monomi can run without: {package: what's missing without it}
OPTIONAL = {"anthropic": "--ai is off"}
PIP_FIX = "pip install -r requirements.txt"


def result(group, name, status, detail, fix=None):
    return {"group": group, "name": name, "status": status,
            "detail": detail, "fix": fix}


def version_tuple(text):
    """'2.34.2' -> (2, 34, 2).

    Stops at the first part that isn't a number: '1.0rc1' -> (1, 0).
    """
    nums = re.match(r"\d+(?:\.\d+)*", text)
    if not nums:
        return ()
    return tuple(int(n) for n in nums.group().split("."))


def read_requirements(path=None):
    """[(package, minimum version or None)] from requirements.txt.

    'psycopg[binary]>=3.2' -> ('psycopg', '3.2').
    Comments and blank lines are skipped.
    """
    reqs = []
    pattern = r"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(?:>=\s*([0-9.]+))?"
    with open(path or REQUIREMENTS, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            m = re.match(pattern, line)
            if m:
                reqs.append((m.group(1), m.group(2)))
    return reqs


def installed_version(package):
    """The installed version of a package, or None if it isn't installed."""
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


# ---------- 1. Setup (local only) ----------

def check_python():
    v = sys.version_info
    text = f"Python {v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) < MIN_PYTHON:
        need = ".".join(map(str, MIN_PYTHON))
        return [result("Setup", "python", FAIL, f"{text} is too old",
                       f"install Python {need} or newer")]
    return [result("Setup", "python", OK, text)]


def check_packages():
    try:
        reqs = read_requirements()
    except OSError:
        return [result("Setup", "packages", WARN,
                       "requirements.txt not found, packages not checked",
                       "run doctor from a full copy of the Monomi repo")]

    missing, old, optional_off, good = [], [], [], []
    for name, minimum in reqs:
        have = installed_version(name)
        if have is None:
            (optional_off if name in OPTIONAL else missing).append(name)
        elif minimum and version_tuple(have) < version_tuple(minimum):
            old.append(f"{name} {have} (needs {minimum})")
        else:
            good.append(name)

    out = []
    if missing or old:
        problems = []
        if missing:
            problems.append(f"missing: {', '.join(missing)}")
        if old:
            problems.append(f"too old: {', '.join(old)}")
        out.append(result("Setup", "packages", FAIL,
                          "; ".join(problems), PIP_FIX))
    else:
        out.append(result("Setup", "packages", OK,
                          "packages: " + ", ".join(good)))
    for name in optional_off:
        out.append(result("Setup", name, WARN,
                          f"{name} not installed, so {OPTIONAL[name]}",
                          PIP_FIX))
    return out


def folders():
    """Folders Monomi writes to: {name shown: path}."""
    return {"scans/": saved.SCANS_DIR,
            "reports/": os.path.join(HERE, "reports"),
            "cache/": aws_ranges.CACHE_DIR}


def check_folders():
    """Each folder can be created and written to.

    Writes a temporary file, which is deleted right away.
    """
    bad = []
    for name, path in folders().items():
        try:
            os.makedirs(path, exist_ok=True)
            with tempfile.TemporaryFile(dir=path):
                pass
        except OSError as e:
            bad.append(f"{name} ({e.strerror or e})")
    if bad:
        return [result("Setup", "folders", FAIL,
                       f"can't write to {', '.join(bad)}",
                       "check the Monomi folder's permissions")]
    return [result("Setup", "folders", OK,
                   f"{', '.join(folders())} writable")]


# ---------- 2. Claude API (for --ai) ----------

API = "Claude API"


def describe_key(key):
    """Safe description of an API key: only its first 7 characters."""
    return f"{key[:7]}…, {len(key)} chars"


def check_api_key():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return [result(API, "api key", WARN,
                       "ANTHROPIC_API_KEY not set, so --ai is off "
                       "(scans work without it)",
                       "see 'API key' in the README")]
    if key != key.strip() or key[0] in "\"'":
        return [result(API, "api key", FAIL,
                       "ANTHROPIC_API_KEY has spaces or quotes around it "
                       f"({describe_key(key)})",
                       "set it again in ~/.bashrc without quotes or spaces, "
                       "then open a new terminal")]
    if key.startswith("sk-ant-"):
        first = result(API, "api key", OK,
                       f"ANTHROPIC_API_KEY set ({describe_key(key)})")
    else:
        first = result(API, "api key", WARN,
                       "ANTHROPIC_API_KEY doesn't start with sk-ant- "
                       f"({describe_key(key)})",
                       f"copy the key again from {CONSOLE}")
    return [first] + check_api_access()


def check_api_access():
    """One free call (listing models uses no tokens) proves the key works."""
    if installed_version("anthropic") is None:
        return []  # check_packages already says --ai is off
    import anthropic
    from monomi.analysis import pick_model

    def bad(status, detail, fix):
        return [result(API, "key accepted", status, detail, fix)]

    try:
        client = anthropic.Anthropic(timeout=10, max_retries=0)
        models = [m.id for m in client.models.list(limit=50)]
        model = pick_model(client)
    except anthropic.AuthenticationError:
        return bad(FAIL, "the API rejected the key (expired or revoked?)",
                   f"make a new key at {CONSOLE}, put it in ~/.bashrc")
    except anthropic.PermissionDeniedError:
        return bad(FAIL, "the key isn't allowed to list models",
                   f"check the key's permissions at {CONSOLE}")
    except anthropic.APIConnectionError:
        return bad(WARN, "couldn't reach the Claude API, "
                   "so the key wasn't checked",
                   "check your internet connection")
    except anthropic.APIStatusError as e:
        return bad(WARN, f"the Claude API answered HTTP {e.status_code}, "
                   "so the key wasn't checked",
                   "try again in a few minutes")

    chosen = os.environ.get("CLAUDE_MODEL")
    if chosen and model not in models:
        return bad(WARN, f"key accepted, but $CLAUDE_MODEL={model} "
                   "isn't in this key's model list",
                   "fix its spelling, or unset it to use the newest Sonnet")
    source = " (from $CLAUDE_MODEL)" if chosen else ""
    return [result(API, "key accepted", OK,
                   f"key accepted · --ai would use {model}{source}")]


# ---------- 3. DNS ----------

def short(e):
    """First line of an error, at most 80 characters (DNS errors can be long)."""
    text = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
    return text[:80]


def net_error(e, timeout=TIMEOUT):
    """A requests error in plain words, instead of its long internal text."""
    if isinstance(e, requests.Timeout):
        return f"timed out after {timeout}s"
    if isinstance(e, requests.ConnectionError):
        return "couldn't connect"
    if isinstance(e, requests.HTTPError) and e.response is not None:
        return f"HTTP {e.response.status_code}"
    return short(e)


def db_error(e):
    """The reason from a psycopg error, without the address in front of it.

    'connection to server at "x", port 5432 failed: sorry, too many
    clients already' -> 'sorry, too many clients already'
    """
    lines = str(e).strip().splitlines()
    first = lines[0] if lines else type(e).__name__
    return short(first.rsplit("failed: ", 1)[-1])


def in_wsl():
    return "microsoft" in platform.uname().release.lower()


def port53_fix():
    fix = ("a VPN's DNS (e.g. NordVPN) can drop lookups: turn it off, "
           f"or set your DNS to {dnscheck.FALLBACK_NAMESERVERS[0]}")
    if in_wsl():
        fix += "; in WSL, also run ipconfig /flushdns in an admin PowerShell"
    return fix


def ask_port53(resolver):
    """None if this resolver answered, otherwise the error text."""
    try:
        resolver.resolve(EXAMPLE, "A", lifetime=5)
        return None
    except Exception as e:  # any DNS failure is the answer we're after
        return short(e)


def ask_doh(url):
    try:
        dnscheck._ask_doh(url, EXAMPLE, "A")
        return None
    except dnscheck.DNSLookupError as e:
        return short(e)


def check_dns():
    """Port 53 (system and public DNS) and DNS-over-HTTPS, all at once.

    Scans use system DNS first and DNS-over-HTTPS to double-check, so
    port 53 failing is only a warning while DNS-over-HTTPS still works.
    """
    group = "DNS"
    system, public = dnscheck._resolvers()
    servers = dnscheck.DOH_SERVERS
    with ThreadPoolExecutor(max_workers=2 + len(servers)) as pool:
        sys_job = pool.submit(ask_port53, system)
        pub_job = pool.submit(ask_port53, public)
        doh_jobs = {name: pool.submit(ask_doh, url) for name, url in servers.items()}
        sys_err, pub_err = sys_job.result(), pub_job.result()
        doh_errs = {name: job.result() for name, job in doh_jobs.items()}

    doh_ok = [name for name, err in doh_errs.items() if err is None]
    if sys_err and pub_err and not doh_ok:
        return [result(group, "dns", FAIL,
                       f"DNS lookups failed everywhere (system DNS: {sys_err})",
                       "check your internet connection; " + port53_fix())]

    out = []
    if sys_err:
        out.append(result(group, "system dns", WARN,
                          f"system DNS (port 53) failed: {sys_err}; "
                          "scans fall back to DNS-over-HTTPS", port53_fix()))
    else:
        out.append(result(group, "system dns", OK, "system DNS (port 53) answered"))

    public_names = ", ".join(dnscheck.FALLBACK_NAMESERVERS)
    if pub_err:
        out.append(result(group, "public dns", WARN,
                          f"public DNS on port 53 ({public_names}) failed: {pub_err}",
                          port53_fix()))
    else:
        out.append(result(group, "public dns", OK,
                          f"public DNS on port 53 ({public_names}) answered"))

    failed = [f"{name} failed ({err})" for name, err in doh_errs.items() if err]
    if not failed:
        out.append(result(group, "doh", OK, "DNS-over-HTTPS: " + ", ".join(doh_ok)))
    elif doh_ok:
        out.append(result(group, "doh", WARN,
                          f"DNS-over-HTTPS: {'; '.join(failed)}; "
                          f"{', '.join(doh_ok)} works",
                          "usually a brief outage: scans use the other server"))
    else:
        out.append(result(group, "doh", WARN,
                          f"DNS-over-HTTPS: {'; '.join(failed)}",
                          "scans lose the double-check that catches stale "
                          "DNS answers; check whether port 443 is blocked"))
    return out


# ---------- 4. Sources ----------

SRC = "Sources"


def at_time(timestamp):
    """A time.time() value as local 'HH:MM'."""
    return datetime.fromtimestamp(timestamp).strftime("%H:%M")


def check_crtsh_website():
    name = pacing.CRTSH.label  # kept out of the code so chat apps don't link it
    try:
        pacing.CRTSH.acquire(max_wait=0)  # counts as 1 of its 5 requests a minute
    except pacing.Paced as e:
        return result(SRC, "crtsh", WARN, f"{name} website not checked: {e}")
    fix = "it's often overloaded; scans still use the other sources"
    try:
        resp = requests.get(crtsh.CRTSH_URL, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException as e:
        return result(SRC, "crtsh", WARN, f"{name} website: {net_error(e)}", fix)
    if resp.status_code != 200:
        return result(SRC, "crtsh", WARN,
                      f"{name} website: HTTP {resp.status_code}", fix)
    return result(SRC, "crtsh", OK, f"{name} website reachable")


def check_crtsh_database():
    name = pacing.CRTSH.label
    db = crtsh_db.DB
    try:
        ipv4 = socket.gethostbyname(db["host"])  # IPv4 only, like crtsh_db.py
    except OSError:
        return result(SRC, "crtsh database", WARN,
                      f"{name} database: couldn't look up its address",
                      "check your DNS (see the DNS lines above)")
    try:
        with crtsh_db.psycopg.connect(**db, hostaddr=ipv4, connect_timeout=TIMEOUT,
                                      autocommit=True) as conn:
            conn.execute("SELECT 1")
    except (OSError, crtsh_db.psycopg.Error) as e:
        return result(SRC, "crtsh database", WARN, f"{name} database: {db_error(e)}",
                      "it's sometimes down; scans still use the other sources")
    return result(SRC, "crtsh database", OK, f"{name} database reachable")


def check_certspotter():
    pacer = pacing.CERTSPOTTER
    state = pacer.status()
    if state["cooldown_until"]:
        until = at_time(state["cooldown_until"])
        return result(SRC, "certspotter", WARN,
                      f"Cert Spotter cooling down until {until} "
                      "after a rate limit (scans skip it until then)",
                      "wait, or sweep fewer domains per hour")
    try:
        pacer.acquire(max_wait=0)  # one real query from the free hourly quota
    except pacing.Paced as e:
        return result(SRC, "certspotter", WARN, f"Cert Spotter not checked: {e}")
    try:
        params = {"domain": EXAMPLE, "include_subdomains": "false"}
        resp = requests.get(certspotter.API_URL, params=params, headers=HEADERS,
                            timeout=TIMEOUT)
    except requests.RequestException as e:
        return result(SRC, "certspotter", WARN, f"Cert Spotter: {net_error(e)}",
                      "check your internet connection")
    if resp.status_code == 429:
        pacer.cool_down(certspotter.cooldown_seconds(resp))
        return result(SRC, "certspotter", WARN,
                      "Cert Spotter: rate limited (free tier used up for now)",
                      "wait, or sweep fewer domains per hour")
    if resp.status_code != 200:
        return result(SRC, "certspotter", WARN,
                      f"Cert Spotter: HTTP {resp.status_code}",
                      "try again in a few minutes")
    used = pacer.status()
    return result(SRC, "certspotter", OK,
                  f"Cert Spotter reachable · {used['used']} of {used['limit']} "
                  "free queries used this hour")


OTX_CHECK_URL = otx.API_URL.format(domain=EXAMPLE).replace("/passive_dns", "/general")
OTX_TIMEOUT = 20  # OTX is slower than the other sources


def check_otx():
    """AlienVault OTX: reachable, and whether a key is set (keyless works, with lower limits)."""
    keyed = otx.api_key() is not None
    key_note = f"key set in {otx.KEY_VAR}" if keyed else "no key (works, with lower limits)"
    pacer = pacing.OTX
    state = pacer.status()
    if state["cooldown_until"]:
        until = at_time(state["cooldown_until"])
        return result(SRC, "otx", WARN,
                      f"AlienVault OTX cooling down until {until} after a rate limit "
                      f"(scans skip it until then) · {key_note}",
                      "wait" if keyed else f"wait, or set a free key in {otx.KEY_VAR}")
    try:
        pacer.acquire(max_wait=0)
    except pacing.Paced as e:
        return result(SRC, "otx", WARN, f"AlienVault OTX not checked: {e}")
    try:
        # The domain's small "general" section, not its passive DNS: example.com
        # is looked up so often that its passive DNS list takes over 20s to send
        resp = requests.get(OTX_CHECK_URL, headers=otx.headers(), timeout=OTX_TIMEOUT)
    except requests.RequestException as e:
        return result(SRC, "otx", WARN, f"AlienVault OTX: {net_error(e, OTX_TIMEOUT)} · {key_note}",
                      "it's sometimes slow; scans wait longer (30s) and use the other sources meanwhile")
    if resp.status_code == 429:
        pacer.cool_down(otx.cooldown_seconds(resp))
        return result(SRC, "otx", WARN, f"AlienVault OTX: rate limited · {key_note}",
                      "wait" if keyed else f"wait, or set a free key in {otx.KEY_VAR}")
    if resp.status_code in (401, 403):
        if keyed:
            return result(SRC, "otx", WARN, f"AlienVault OTX refused the key in {otx.KEY_VAR}",
                          "copy the key again from otx.alienvault.com (Settings, API Integration)")
        return result(SRC, "otx", WARN, "AlienVault OTX wants an API key",
                      f"set a free key in {otx.KEY_VAR} (otx.alienvault.com)")
    if resp.status_code != 200:
        return result(SRC, "otx", WARN, f"AlienVault OTX: HTTP {resp.status_code}",
                      "try again in a few minutes")
    return result(SRC, "otx", OK, f"AlienVault OTX reachable · {key_note}")


def check_ct_sources():
    """The subdomain sources (three certificate logs and OTX), at the same time.
    Scans need at least one."""
    checks = [check_crtsh_website, check_crtsh_database, check_certspotter, check_otx]
    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        out = list(pool.map(lambda check: check(), checks))
    if not any(r["status"] == OK for r in out):
        out.append(result(SRC, "certificates", FAIL,
                          "no subdomain source answered, so scans can't find "
                          "hostnames right now",
                          "try again in a few minutes (--hosts FILE still works)"))
    return out


def check_shodan():
    ip = ".".join(["1"] * 4)  # any public IP Shodan knows
    try:
        resp = requests.get(internetdb.API_URL.format(ip=ip), headers=HEADERS,
                            timeout=TIMEOUT)
    except requests.RequestException as e:
        return [result(SRC, "shodan", WARN, f"Shodan InternetDB: {net_error(e)}",
                       "--ports won't find anything until it's reachable")]
    if resp.status_code not in (200, 404):  # 404 = "nothing on this IP", still up
        return [result(SRC, "shodan", WARN,
                       f"Shodan InternetDB: HTTP {resp.status_code}",
                       "--ports won't find anything until it's reachable")]
    return [result(SRC, "shodan", OK, "Shodan InternetDB reachable")]


def check_aws_ranges():
    """AWS's IP list (used to spot CloudFront edge IPs), cached for a day."""
    try:
        age = time.time() - os.path.getmtime(aws_ranges.CACHE_FILE)
    except OSError:
        age = None
    if age is not None and age < aws_ranges.MAX_AGE:
        return [result(SRC, "aws", OK, f"AWS IP ranges (cached {age / 3600:.0f}h ago)")]
    try:
        aws_ranges._download()
    except RuntimeError as e:
        # _download wraps the network error; show that one in plain words
        cause = e.__context__
        network = isinstance(cause, requests.RequestException)
        why = net_error(cause) if network else short(e)
        fix = "CloudFront edge IPs may be counted as the target's own servers"
        if age is not None:
            days = age / 86400
            return [result(SRC, "aws", WARN,
                           f"AWS IP ranges: download failed ({why}); "
                           f"using a {days:.0f}-day-old copy", fix)]
        return [result(SRC, "aws", WARN,
                       f"AWS IP ranges: download failed ({why})", fix)]
    return [result(SRC, "aws", OK, "AWS IP ranges (just downloaded)")]


def check_tor_list():
    try:
        resp = requests.get(threatintel.TOR_EXIT_URL, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        return [result(SRC, "tor", WARN, f"Tor exit list: {net_error(e)}",
                       "only --investigate-ip uses it")]
    return [result(SRC, "tor", OK, "Tor exit list reachable (for --investigate-ip)")]


# ---------- 5. MCP (Claude app) ----------

MCP = "MCP"
SETUP_FIX = "python monomi.py mcp setup"
# Worst first: when there are two config copies, the worst one is shown
MCP_STATES = ["unreadable", "broken", "different", "missing", "ok"]


def mcp_state(path, entry):
    """How one config file stands: one of MCP_STATES.
    Whether active tools are on (check_active) and the scope (check_scope)
    are their own checks, so those flags don't make the entry "different"."""
    try:
        config = mcp_setup.load_config(path)
    except mcp_setup.SetupError:
        return "broken"
    except OSError:
        return "unreadable"
    old = config.get("mcpServers", {}).get(mcp_setup.NAME)
    # the same order mcp setup builds it in: the scope pair, then --allow-active
    entry = mcp_setup.with_scope(entry, *mcp_setup.scope_args(old))
    entry = mcp_setup.with_active(entry, mcp_setup.is_active(old))
    status, _ = mcp_setup.change(config, entry)
    return {"new": "missing", "unchanged": "ok", "changing": "different"}[status]


def check_mcp():
    """Is Monomi in the Claude app's config, pointing at this Monomi?

    Read-only: finds the config and builds the entry the same way
    mcp setup does, so the two always agree. Nothing is written.
    """
    try:
        found, _ = mcp_setup.config_paths()
    except mcp_setup.SetupError:
        return [result(MCP, "mcp", WARN, "couldn't find the Claude app config",
                       "python monomi.py mcp setup --print, then add it by hand")]
    if not found:
        return [result(MCP, "mcp", WARN,
                       "Monomi isn't set up in the Claude app", SETUP_FIX)]

    entry = mcp_setup.server_entry()
    states = {path: mcp_state(path, entry) for path in found}
    path, state = min(states.items(), key=lambda kv: MCP_STATES.index(kv[1]))
    where = f" ({path})" if len(found) > 1 else ""
    if state == "ok":
        many = f" ({len(found)} config files)" if len(found) > 1 else ""
        return [result(MCP, "mcp", OK,
                       f"Claude app config points at this Monomi{many}")]
    if state == "unreadable":
        return [result(MCP, "mcp", WARN,
                       f"can't read the Claude app config ({path})",
                       "check that file's permissions")]
    if state == "broken":
        return [result(MCP, "mcp", WARN,
                       f"Claude app config isn't valid JSON ({path})",
                       f"fix or move that file, then run {SETUP_FIX}")]
    if state == "different":
        return [result(MCP, "mcp", WARN,
                       f"Claude app config points at a different Monomi{where}",
                       SETUP_FIX)]
    return [result(MCP, "mcp", WARN,
                   f"Monomi isn't set up in the Claude app{where}", SETUP_FIX)]


def active_configs(found):
    """(config files with active tools ON, readable ones with them off)."""
    on, off = [], []
    for path in found:
        try:
            config = mcp_setup.load_config(path)
        except (mcp_setup.SetupError, OSError):
            continue  # check_mcp already reports broken or unreadable files
        if mcp_setup.is_active(config.get("mcpServers", {}).get(mcp_setup.NAME)):
            on.append(path)
        else:
            off.append(path)
    return on, off


def config_lines(label, paths):
    """One indented line per config file, under a result's detail line."""
    return "".join(f"\n      {label} {path}" for path in paths)


def last_active_request(log=None):
    """(requests in scans/active.log, its last request, refusals) or (0, None, 0).
    Refusals (v1.12) are counted on their own, never as requests."""
    log = log or mcp_setup.ACTIVE_LOG
    try:
        with open(log, encoding="utf-8") as f:
            lines = [line for line in f if line.strip()]
    except OSError:
        return 0, None, 0
    requests_, refusals, last = 0, 0, None
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            entry = {"time": "?", "host": "?", "tool": "? (last line unreadable)"}
        if activelog.is_request(entry):
            requests_ += 1
            last = entry
        else:
            refusals += 1
    return requests_, last, refusals


def check_active():
    """Are ACTIVE MCP tools turned on, and when did one last send a request?

    On is a warning on purpose: it should never go unnoticed. Read-only.
    """
    try:
        found, _ = mcp_setup.config_paths()
    except mcp_setup.SetupError:
        found = []
    out = []
    on, off = active_configs(found)
    if on and off:
        # The app reads only one copy, so we can't tell which setting it uses
        files = config_lines("ON: ", on) + config_lines("off:", off)
        out.append(result(MCP, "active", WARN,
                          "ACTIVE tools: the config files disagree, and the Claude app reads "
                          f"only one of them, so the setting is unclear{files}",
                          "python monomi.py mcp setup --allow-active or --no-active, "
                          "to make them match"))
    elif on:
        where = config_lines("in", on) if len(found) > 1 else ""
        out.append(result(MCP, "active", WARN,
                          "ACTIVE tools are ON: fingerprint_hosts and check_exposed_files can "
                          "send requests to hosts in the approved scope "
                          f"(after a Claude app restart){where}",
                          "python monomi.py mcp setup --no-active, to turn them off"))
    else:
        out.append(result(MCP, "active", OK, "ACTIVE tools are off (fingerprint_hosts and check_exposed_files refuse)"))
    count, last, refusals = last_active_request()
    refused = f", {plural(refusals, 'refusal')}" if refusals else ""
    if last:
        out.append(result(MCP, "active_log", OK,
                          f"last active request {last.get('time')}: {last.get('tool')} -> "
                          f"{last.get('host')} ({plural(count, 'request')}{refused} "
                          "in scans/active.log)"))
    elif refusals:
        out.append(result(MCP, "active_log", OK,
                          f"no active requests sent yet ({plural(refusals, 'refusal')} "
                          "in scans/active.log)"))
    return out


def scope_pairs(found):
    """{config file: (scope path, approved sha256)} for readable files with a Monomi entry."""
    pairs = {}
    for path in found:
        try:
            config = mcp_setup.load_config(path)
        except (mcp_setup.SetupError, OSError):
            continue  # check_mcp already reports broken or unreadable files
        entry = config.get("mcpServers", {}).get(mcp_setup.NAME)
        if entry is not None:
            pairs[path] = mcp_setup.scope_args(entry)
    return pairs


def rejected_lines(s):
    """The scope file's rejected lines, one per line under a result's detail."""
    if not s or not s.rejected:
        return ""
    return "".join(f"\n      rejected line {r['line']}: {ui.safe(r['text'])} ({r['reason']})"
                   for r in s.rejected)


def check_scope():
    """Which scope file is approved for ACTIVE tools, and does it still match?

    Uses scope.check_pinned, the same check the MCP server makes at startup,
    so doctor and the server always agree. Read-only."""
    fix = "python monomi.py mcp setup --scope FILE (and type yes)"
    try:
        found, _ = mcp_setup.config_paths()
    except mcp_setup.SetupError:
        found = []
    pairs = scope_pairs(found)
    on, _ = active_configs(found)
    if len(set(pairs.values())) > 1:
        files = "".join(f"\n      {mcp_setup.describe_scope(*pair)} in {path}"
                        for path, pair in pairs.items())
        return [result(MCP, "scope", WARN,
                       "scope: the config files disagree, and the Claude app reads only "
                       f"one of them{files}", f"{fix}, to make them match")]
    path, sha256 = next(iter(pairs.values()), (None, None))
    if not path:
        if on:
            return [result(MCP, "scope", WARN,
                           "ACTIVE tools are ON but no scope file is approved, so every "
                           "active check refuses", fix)]
        return [result(MCP, "scope", OK,
                       "no scope file approved (needed before active tools can run)")]
    s, problem = scope.check_pinned(path, sha256)
    if problem:
        return [result(MCP, "scope", WARN, f"scope file {path}: {problem}{rejected_lines(s)}",
                       fix)]
    return [result(MCP, "scope", OK,
                   f"scope file {path}: {plural(len(s.inclusions), 'rule')} in scope, "
                   f"{plural(len(s.exclusions), 'exclusion')}, sha256 {s.sha256[:12]}... "
                   f"matches the approval{rejected_lines(s)}")]


# ---------- Running and showing the checks ----------

# ---------- 6. Other MCP clients (v1.13): Codex, OpenCode, Hermes ----------

def client_state(client, path):
    """(state, Monomi's entry or None) for one client config file. States:
    ok, different, missing, comments (OpenCode JSONC: can't look inside),
    broken, unreadable. Like mcp_state, the active and scope flags don't make
    the entry "different": they're reported on their own."""
    try:
        doc = client.load(path)
    except mcp_setup.HasComments:
        return "comments", None
    except mcp_setup.SetupError:
        return "broken", None
    except OSError:
        return "unreadable", None
    old = client.entry(doc)
    if old is None:
        return "missing", None
    want = mcp_setup.with_scope(client.base(), *mcp_setup.scope_args(old))
    want = mcp_setup.with_active(want, mcp_setup.is_active(old))
    return ("ok" if old == want else "different"), old


def client_active(label, entry):
    """The active-tools part of a client's line: (status, words)."""
    if not mcp_setup.is_active(entry):
        return OK, "active tools off"
    path, sha256 = mcp_setup.scope_args(entry)
    if not path:
        return WARN, "ACTIVE tools ON but no scope file is approved, so every active check refuses"
    _, problem = scope.check_pinned(path, sha256)
    if problem:
        return WARN, f"ACTIVE tools ON, scope file {path}: {problem}"
    return WARN, (f"ACTIVE tools ON (scope {mcp_setup.describe_scope(path, sha256)}): "
                  f"agents in {label} can send requests to hosts in that scope")


def check_clients():
    """Monomi in every other MCP client that has a config file on this machine.

    A client with no config file is listed once on an OK line, never warned
    about: most people don't use every client. Read-only, like check_mcp.
    """
    out, absent = [], []
    for key, client in mcp_setup.CLIENTS.items():
        if key == "claude":
            continue  # check_mcp, check_active and check_scope cover the Claude app
        fix = f"{SETUP_FIX} --client {key}"
        found, _ = client.paths()
        if not found:
            absent.append(client.label)
        for path in found:
            state, entry = client_state(client, path)
            if state == "ok":
                status, words = client_active(client.label, entry)
                out.append(result(MCP, key, status,
                                  f"{client.label} config points at this Monomi, {words} ({path})",
                                  f"{fix} --no-active, to turn them off" if status == WARN else None))
            elif state == "missing":
                out.append(result(MCP, key, OK,
                                  f"{client.label} is set up on this machine, Monomi isn't in it "
                                  f"({path}); to add it: {fix}"))
            elif state == "comments":
                out.append(result(MCP, key, OK,
                                  f"{client.label} config has comments, so doctor can't check "
                                  f"Monomi's entry in it ({path})"))
            elif state == "different":
                out.append(result(MCP, key, WARN,
                                  f"{client.label} config points at a different Monomi ({path})", fix))
            elif state == "broken":
                out.append(result(MCP, key, WARN,
                                  f"{client.label} config can't be read ({path})",
                                  f"fix or move that file, then run {fix}"))
            else:
                out.append(result(MCP, key, WARN, f"can't open the {client.label} config ({path})",
                                  "check that file's permissions"))
    if absent:
        out.append(result(MCP, "clients", OK, f"no config found for: {', '.join(absent)}"))
    return out


CHECKS = [check_python, check_packages, check_folders, check_api_key,
          check_dns, check_ct_sources, check_shodan, check_aws_ranges,
          check_tor_list, check_mcp, check_active, check_scope, check_clients]


def run_all(checks=None):
    """Run every check at the same time; results keep the order of CHECKS.

    A check that crashes becomes a 'fail' line, so doctor never crashes.
    """
    checks = CHECKS if checks is None else checks

    def safe_run(check):
        try:
            return check()
        except Exception as e:  # doctor must always finish
            name = check.__name__.removeprefix("check_")
            return [result("Other", name, FAIL,
                           f"{name} check crashed: {type(e).__name__}: {e}",
                           "please report this line on GitHub")]

    with ThreadPoolExecutor(max_workers=max(1, len(checks))) as pool:
        return [r for rs in pool.map(safe_run, checks) for r in rs]


def plural(n, word):
    """plural(1, "warning") -> "1 warning", plural(2, ...) -> "2 warnings"."""
    return f"{n} {word}" + ("" if n == 1 else "s")


MARKS = {OK: ("[+]", ui.GREEN), WARN: ("[!]", ui.YELLOW),
         FAIL: ("[x]", ui.RED)}


def show(results):
    """Print the results grouped, then one summary line."""
    print(ui.paint("monomi doctor", ui.BOLD, ui.WHITE))
    group = None
    for r in results:
        if r["group"] != group:
            group = r["group"]
            print(f"\n{ui.paint(group, ui.BOLD, ui.WHITE)}")
        mark, color = MARKS[r["status"]]
        print(f"  {ui.paint(mark, color)} {r['detail']}")
        if r["fix"]:
            print(f"      {ui.paint('fix:', ui.GREY)} {r['fix']}")

    count = {s: sum(r["status"] == s for r in results) for s in MARKS}
    warnings = plural(count[WARN], "warning")
    problems = plural(count[FAIL], "problem")
    verdict = "fix the problems above first" if count[FAIL] else "ready to scan"
    print(f"\n{count[OK]} ok · {warnings} · {problems}: {verdict}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="monomi.py doctor",
        description="check Monomi's setup and what it can reach")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output (also respects NO_COLOR)")
    args = parser.parse_args(argv)
    if args.no_color:
        ui.disable()
    print(ui.banner())
    results = run_all()
    show(results)
    return 1 if any(r["status"] == FAIL for r in results) else 0
