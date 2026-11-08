"""
Report exports: the scan as Markdown, HTML or a findings CSV.

Everything here is built by code from the evidence and the attack paths, so
an export never needs --ai. If Claude wrote a summary (--ai), it goes at the
top, labeled as written by the AI; the findings, paths and evidence below it
are always code-built.

A "finding" is an evidence item with an owner: evidence.py only gives owners
to facts someone has to act on (which source found a hostname has none).
"""

import csv
import io

import evidence
import paths

SEVERITIES = ("High", "Medium", "Low")
# Cells starting with these can run as formulas in Excel / Sheets
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
# How source keys are shown (the same names the terminal uses)
SOURCE_LABELS = {"certspotter": "Cert Spotter"}
CSV_COLUMNS = ["id", "host", "finding", "owners", "attack_paths",
               "worst_path_severity", "fix_first", "source", "collected_at"]


# ---------- What goes in every format ----------

def host_of(e: dict, results: dict) -> str:
    """The host a finding is about.

    Most facts store it; the rest start with the hostname, so the first
    word counts only if it's a host this scan actually checked.
    """
    if e.get("host"):
        return e["host"]
    first = e["fact"].split(" ", 1)[0]
    known = set(results.get("subdomains", [])) | {results.get("target")}
    return first if first in known else ""


def findings(results: dict) -> list[dict]:
    """Every evidence item with an owner, worst attack path first.

    A finding's severity is the worst attack path it's part of; findings
    in no path get none, since there are no per-finding severity rules.
    """
    built = results["paths"]
    fix = built.get("fix_first") or {}
    in_paths = {}
    for p in built["paths"]:
        cited = {eid for s in p["steps"] for eid in s["evidence"]} | set(p["fix"])
        for eid in cited:
            in_paths.setdefault(eid, []).append(p)

    out = []
    for e in results["evidence"]:
        if not e.get("owners"):
            continue
        ps = in_paths.get(e["id"], [])
        worst = min((p["severity"] for p in ps), key=SEVERITIES.index, default="")
        out.append({
            "id": e["id"],
            "host": host_of(e, results),
            "finding": e["fact"],
            "owners": e["owners"],
            "paths": [p["id"] for p in ps],
            "severity": worst,
            "fix_first": e["id"] == fix.get("evidence"),
            "sources": e["sources"],
        })
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out.sort(key=lambda f: (rank.get(f["severity"], len(SEVERITIES)),
                            not f["fix_first"], int(f["id"][1:])))
    return out


def summary(results: dict) -> dict:
    """The counts at the top of every report."""
    built = results["paths"]
    return {
        "hostnames": len(results.get("subdomains", [])),
        "sources": [SOURCE_LABELS.get(k, k) for k in results.get("sources", {})],
        "problems": dict(results.get("errors", {})),
        "findings": len(findings(results)),
        "paths": {s: sum(p["severity"] == s for p in built["paths"]) for s in SEVERITIES},
        "more_paths": built.get("more", 0),
        "fix_first": built.get("fix_first"),
    }


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def path_counts(s: dict) -> str:
    """'2 attack paths (1 High, 1 Medium)' or 'no attack paths'."""
    total = sum(s["paths"].values())
    if not total:
        return "no attack paths"
    parts = ", ".join(f"{n} {sev}" for sev, n in s["paths"].items() if n)
    return f"{plural(total, 'attack path')} ({parts})"


# ---------- Markdown ----------

def md_cell(text: str) -> str:
    """Safe inside a Markdown table: no line breaks, pipes or raw HTML."""
    text = " ".join(str(text).split())
    return (text.replace("\\", "\\\\").replace("|", "\\|")
            .replace("<", "&lt;").replace(">", "&gt;"))


def to_markdown(results: dict, generated) -> str:
    """The whole report as Markdown. generated: a datetime for the header."""
    target = results["target"]
    s = summary(results)
    found = findings(results)
    ai = results.get("ai_report")

    lines = [f"# mønømi report: {target}", "",
             f"*Generated {generated:%Y-%m-%d %H:%M} · "
             f"sources: {', '.join(s['sources']) or 'none'} · "
             f"{plural(s['hostnames'], 'hostname')}"
             + (f" · AI summary: {ai['model']}" if ai else "") + "*", "",
             "## Summary", "",
             f"- {plural(s['hostnames'], 'hostname')} found",
             f"- {plural(s['findings'], 'finding')} to fix, {path_counts(s)}"]
    if s["more_paths"]:
        lines.append(f"- {s['more_paths']} lower-ranked path(s) left out")
    fix = s["fix_first"]
    if fix:
        lines.append(f"- **Fix this first** ({fix['evidence']}, closes "
                     f"{', '.join(fix['closes'])}): {fix['fact']}")
    for source, why in s["problems"].items():
        lines.append(f"- {source} had a problem: {why}")

    if ai:
        lines += ["", "## AI summary", "",
                  f"*Written by Claude ({ai['model']}). Every claim should cite "
                  "evidence listed below; the findings, attack paths and "
                  "evidence after this section are built by code.*", "",
                  ai["text"].strip()]

    lines += ["", "## Findings", ""]
    if found:
        lines += ["| ID | Host | Finding | Owner | Attack paths |",
                  "|---|---|---|---|---|"]
        for f in found:
            paths_cell = ", ".join(f["paths"]) + (" (fix first)" if f["fix_first"] else "")
            lines.append(f"| {f['id']} | {md_cell(f['host'])} | {md_cell(f['finding'])} | "
                         f"{md_cell(', '.join(f['owners']))} | {paths_cell} |")
    else:
        lines.append("*Nothing to fix was found in this scan.*")

    body = "\n".join(lines) + "\n\n" + paths.paths_appendix(results["paths"])
    # The evidence list covers everything cited above: findings, paths, AI text
    cites = " ".join(f"[{f['id']}]" for f in found) + body
    return body + "\n" + evidence.evidence_appendix(cites, results["evidence"])


# ---------- CSV ----------

def csv_safe(value) -> str:
    """A cell Excel won't run as a formula (CSV injection)."""
    text = str(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def to_csv(results: dict) -> str:
    """One row per finding, for ticketing systems and spreadsheets."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings(results):
        first = f["sources"][0] if f["sources"] else {}
        row = [f["id"], f["host"], f["finding"], "; ".join(f["owners"]),
               "; ".join(f["paths"]), f["severity"], "yes" if f["fix_first"] else "",
               "; ".join(src["name"] for src in f["sources"]),
               first.get("collected_at") or first.get("imported_at") or ""]
        writer.writerow([csv_safe(v) for v in row])
    return out.getvalue()
