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
import os
import re
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

import aws_ranges
import ui
from collectors import saved

OK, WARN, FAIL = "ok", "warn", "fail"
HERE = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS = os.path.join(HERE, "requirements.txt")
MIN_PYTHON = (3, 10)
# Built from pieces so chat apps don't turn it into a link when pasting
CONSOLE = "console.anthropic" + ".com"

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
    from analysis import pick_model

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


# ---------- Running and showing the checks ----------

CHECKS = [check_python, check_packages, check_folders, check_api_key]


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
