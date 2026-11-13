"""
Report exports: the scan as Markdown, HTML or a findings CSV.

Everything here is built by code from the evidence and the attack paths, so
an export never needs --ai. If Claude wrote a summary (--ai), it goes at the
top, labeled as written by the AI; the findings, paths and evidence below it
are always code-built.

A "finding" is an evidence item with an owner: evidence.py only gives owners
to facts someone has to act on (which source found a hostname has none).
"""

import argparse
import csv
import html
import io
import json
import os
import re
from datetime import datetime

import evidence
import gate
import paths
import ui

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

    A finding's severity is the worst attack path or lead it's part of;
    findings in neither get none, since there are no per-finding severity
    rules. Leads (L1...) are listed with the paths but never flagged fix-first.
    """
    built = results["paths"]
    fix = built.get("fix_first") or {"actions": []}
    fix_ids = {eid for a in fix["actions"] for eid in a["evidence"]}
    in_paths = {}
    for p in built["paths"] + built.get("leads", []):
        cited = ({eid for s in p["steps"] for eid in s["evidence"]}
                 | {eid for a in p["actions"] for eid in a["evidence"]})
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
            "fix_first": e["id"] in fix_ids,
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
        "leads": len(built.get("leads", [])),
        "fix_first": built.get("fix_first"),
    }


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def path_counts(s: dict) -> str:
    """'2 attack paths (1 High, 1 Medium), 1 lead to investigate' or 'no attack paths'."""
    total = sum(s["paths"].values())
    leads = f", {plural(s['leads'], 'lead')} to investigate" if s.get("leads") else ""
    if not total:
        return "no attack paths" + leads
    parts = ", ".join(f"{n} {sev}" for sev, n in s["paths"].items() if n)
    return f"{plural(total, 'attack path')} ({parts})" + leads


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
        t = paths.fix_first_parts(fix)
        lines.append(f"- **{t['label']}** ({', '.join(t['ids'])}, {t['closes']}): {t['what']}")
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


# ---------- HTML ----------

# One self-contained page: no scripts, no outside fonts or files, so it
# opens offline and can be emailed. The CSP tag blocks scripts and outside
# requests even if escaping were ever missed somewhere.
CSP = "default-src 'none'; style-src 'unsafe-inline'"
STYLE = """
body { font: 15px/1.5 system-ui, sans-serif; color: #111; background: #fff;
       max-width: 1100px; margin: 2em auto; padding: 0 1em; }
h1 { font-family: ui-monospace, monospace; letter-spacing: .02em; }
h2 { border-bottom: 2px solid #111; padding-bottom: .2em; margin-top: 2em; }
.meta, .note { color: #555; font-size: .9em; }
table { border-collapse: collapse; width: 100%; font-size: .9em; }
th, td { border: 1px solid #111; padding: .35em .5em; text-align: left;
         vertical-align: top; }
th { background: #111; color: #fff; }
.sev { font-weight: bold; padding: 0 .4em; border: 1px solid #111; white-space: nowrap; }
.High { background: #111; color: #fff; }
.Low { color: #555; border-color: #999; }
.fix { border: 2px solid #111; padding: .6em .8em; }
.ai { white-space: pre-wrap; border-left: 4px solid #111; padding-left: 1em; }
ol li { margin: .2em 0; }
code, .id { font-family: ui-monospace, monospace; }
a { color: #111; }
@media print { body { margin: 0; max-width: none; } a { text-decoration: none; } }
"""


def esc(value) -> str:
    """Text from the scan, made safe for HTML (quotes too, for attributes)."""
    return html.escape(str(value), quote=True)


def id_links(ids) -> str:
    """'E8, E9' as links to the evidence list at the bottom."""
    return ", ".join(f'<a class="id" href="#{esc(i)}">{esc(i)}</a>' for i in ids)


def badge(severity: str) -> str:
    return f'<span class="sev {esc(severity)}">{esc(severity)}</span>' if severity else ""


def to_html(results: dict, generated) -> str:
    """The whole report as one HTML page, same content as the Markdown."""
    target = results["target"]
    s = summary(results)
    found = findings(results)
    built = results["paths"]
    ai = results.get("ai_report")
    out = ['<!DOCTYPE html>', '<html lang="en"><head><meta charset="utf-8">',
           f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>mønømi report: {esc(target)}</title>",
           f"<style>{STYLE}</style></head><body>",
           f"<h1>[mønømi] {esc(target)}</h1>",
           f'<p class="meta">Generated {generated:%Y-%m-%d %H:%M} · sources: '
           f"{esc(', '.join(s['sources']) or 'none')} · "
           f"{plural(s['hostnames'], 'hostname')}"
           + (f" · AI summary: {esc(ai['model'])}" if ai else "") + "</p>",
           "<h2>Summary</h2><ul>",
           f"<li>{plural(s['hostnames'], 'hostname')} found</li>",
           f"<li>{plural(s['findings'], 'finding')} to fix, {path_counts(s)}</li>"]
    if s["more_paths"]:
        out.append(f"<li>{s['more_paths']} lower-ranked path(s) left out</li>")
    for source, why in s["problems"].items():
        out.append(f"<li>{esc(source)} had a problem: {esc(why)}</li>")
    out.append("</ul>")
    fix = s["fix_first"]
    if fix:
        t = paths.fix_first_parts(fix)
        out.append(f'<p class="fix"><strong>{esc(t["label"])}</strong> '
                   f"({id_links(t['ids'])}, owner: {esc(t['owners'])}, "
                   f"{esc(t['closes'])}): {esc(t['what'])}</p>")

    if ai:
        out += ["<h2>AI summary</h2>",
                f'<p class="note">Written by Claude ({esc(ai["model"])}). Every claim '
                "should cite evidence listed below; the findings, attack paths and "
                "evidence after this section are built by code.</p>",
                f'<div class="ai">{esc(ai["text"].strip())}</div>']

    out.append("<h2>Findings</h2>")
    if found:
        out.append("<table><tr><th>ID</th><th>Severity</th><th>Host</th><th>Finding</th>"
                   "<th>Owner</th><th>Attack paths</th></tr>")
        for f in found:
            paths_cell = ", ".join(f["paths"]) + (" (fix first)" if f["fix_first"] else "")
            out.append(f"<tr><td>{id_links([f['id']])}</td><td>{badge(f['severity'])}</td>"
                       f"<td>{esc(f['host'])}</td><td>{esc(f['finding'])}</td>"
                       f"<td>{esc(', '.join(f['owners']))}</td><td>{esc(paths_cell)}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p><em>Nothing to fix was found in this scan.</em></p>")

    out += ["<h2>Attack paths (built by code)</h2>",
            '<p class="note">Worked out by monomi\'s code from the evidence below, not by '
            "the AI. A path shows how an attack would most likely go, not proof that it "
            "works.</p>"]
    if not built["paths"]:
        out.append("<p><em>No attack path found in this scan's evidence.</em></p>")
    for p in built["paths"]:
        out.append(f"<h3>{esc(p['id'])}: {esc(p['title'])} {badge(p['severity'])}</h3>"
                   f'<p class="note">weakest step: {esc(p["strength"])} · '
                   f'{esc(gate.describe(p.get("gate")))}</p><ol>')
        for st in p["steps"]:
            out.append(f"<li><strong>{esc(st['label'])}:</strong> {esc(st['text'])} "
                       f"[{id_links(st['evidence'])}]</li>")
        out.append(f"</ol><p>Result: {esc(p['outcome'])}</p>")
        out += [f'<p class="note">Note: {esc(n)}</p>' for n in (p.get("gate") or {}).get("notes", [])]
    leads = built.get("leads", [])
    if leads:
        out += ["<h3>Leads to investigate</h3>",
                '<p class="note">Not attack paths: each is missing something that '
                "would make it one.</p>"]
    for p in leads:
        out.append(f"<h4>{esc(p['id'])}: {esc(p['title'])} {badge(p['severity'])}</h4>"
                   f'<p class="note">weakest step: {esc(p["strength"])} · '
                   f'{esc(gate.describe(p.get("gate")))}</p><ol>')
        for st in p["steps"]:
            out.append(f"<li><strong>{esc(st['label'])}:</strong> {esc(st['text'])} "
                       f"[{id_links(st['evidence'])}]</li>")
        out.append(f"</ol><p>Missing: {esc(p['missing'])}</p>")
        out += [f'<p class="note">Note: {esc(n)}</p>' for n in (p.get("gate") or {}).get("notes", [])]
    if built.get("more_leads"):
        out.append(f"<p>{built['more_leads']} more lead(s) left out</p>")
    set_aside = built.get("set_aside", [])
    if set_aside:
        out += ["<h3>Set aside</h3>",
                '<p class="note">Out of scope or not the target\'s own: neither attack '
                "paths nor leads.</p><ul>"]
        out += [f"<li>{esc(p['title'])}: {esc(p['why'])}</li>" for p in set_aside]
        out.append("</ul>")
    if built.get("more_set_aside"):
        out.append(f"<p>{built['more_set_aside']} more set aside</p>")
    if built.get("out_of_scope_hosts"):
        out.append(f'<p class="note">{esc(paths.out_of_scope_line(built["out_of_scope_hosts"]))}</p>')

    # Same evidence as the Markdown: everything a finding, path or the AI cites
    cites = " ".join(f"[{f['id']}]" for f in found)
    cites += " ".join(f"[{', '.join(st['evidence'])}]"
                      for p in built["paths"] + leads for st in p["steps"])
    if fix:
        cites += f" [{', '.join(paths.fix_first_parts(fix)['ids'])}]"
    if ai:
        cites += ai["text"]
    listed = evidence.cited_ids(cites)
    out += ["<h2>Evidence</h2>",
            '<p class="note">Facts collected by monomi\'s code, not written by the AI. '
            "Every citation above points to one of these.</p><ul>"]
    for e in results["evidence"]:
        if e["id"] not in listed:
            continue
        sources = "; ".join(evidence.describe_source(src) for src in e["sources"])
        owners = (f"<br>Owner: {esc(', '.join(e['owners']))}" if e.get("owners") else "")
        out.append(f'<li id="{esc(e["id"])}"><strong class="id">{esc(e["id"])}</strong>: '
                   f'{esc(e["fact"])}<br><span class="note">Source: {esc(sources)}</span>'
                   f"{owners}</li>")
    out += ["</ul>", "</body></html>"]
    return "\n".join(out) + "\n"


# ---------- Saving (--export and the report command) ----------

# Reports go in the monomi folder, wherever the command is run from
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
# format name: (builder, file ending, encoding). utf-8-sig puts a BOM at the
# start of the CSV, so Excel reads characters like ø correctly
FORMATS = {
    "md": (to_markdown, ".md", "utf-8"),
    "html": (to_html, ".html", "utf-8"),
    "csv": (lambda r, when: to_csv(r), ".csv", "utf-8-sig"),
}


def parse_formats(text: str) -> list[str]:
    """'html,csv' -> ['html', 'csv']; 'all' -> every format.

    Raises argparse.ArgumentTypeError, so argparse shows a clean error.
    """
    if text.strip().lower() == "all":
        return list(FORMATS)
    asked = [f.strip().lower() for f in text.split(",") if f.strip()]
    unknown = [f for f in asked if f not in FORMATS]
    if unknown or not asked:
        raise argparse.ArgumentTypeError(
            f"unknown format {', '.join(unknown) or text!r}: use all, or any of "
            f"{', '.join(FORMATS)} (e.g. html,csv)")
    return list(dict.fromkeys(asked))  # drop repeats, keep the order


def save(results: dict, formats: list[str], generated, folder: str = None) -> list[str]:
    """Write each format to the reports folder. Returns the paths written."""
    folder = folder or REPORTS_DIR
    os.makedirs(folder, exist_ok=True)
    # The target is a checked domain, but a file name gets only safe characters
    name = re.sub(r"[^a-z0-9.-]", "_", str(results["target"]).lower())
    written = []
    for fmt in formats:
        build, ending, encoding = FORMATS[fmt]
        path = os.path.join(folder, f"{name}_{generated:%Y-%m-%d_%H%M%S}_export{ending}")
        # newline="": write line endings exactly as built (no extra \r on Windows)
        with open(path, "w", encoding=encoding, newline="") as f:
            f.write(build(results, generated))
        written.append(path)
    return written


def short_path(path: str) -> str:
    """'reports/x.md' when run from the monomi folder, the full path otherwise."""
    rel = os.path.relpath(path)
    return path if rel.startswith("..") else rel


def load_scan(path: str) -> dict:
    """A saved --json domain scan, ready to export.

    Evidence and attack paths saved with the scan are used as they are, so
    the IDs an AI summary cites still match. Older saves without them get
    them built now. Paths saved before v1.10 keep their IDs and steps and
    get their actions (and a corrected "fix this first") added.
    """
    with open(path, encoding="utf-8-sig") as f:
        results = json.load(f)
    if not isinstance(results, dict) or results.get("mode") == "investigate_ip":
        raise ValueError("only domain scans can be exported, not --investigate-ip results")
    if "target" not in results or "subdomains" not in results:
        raise ValueError("this doesn't look like a Monomi --json scan")
    if "evidence" not in results or "paths" not in results:
        results["evidence"] = evidence.build_evidence(results)
        results["paths"] = paths.build_paths(results, results["evidence"])
    paths.upgrade_saved(results["paths"], results["evidence"])
    return results


def main(argv=None) -> int:
    """python monomi.py report FILE: export a saved --json scan again."""
    parser = argparse.ArgumentParser(
        prog="monomi.py report",
        description="export a saved --json scan as Markdown, HTML or a findings CSV")
    parser.add_argument("file", help="a scan saved with --json")
    parser.add_argument("--format", type=parse_formats, default=list(FORMATS),
                        help="all (default), or any of md,html,csv")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output (also respects NO_COLOR)")
    args = parser.parse_args(argv)
    if args.no_color:
        ui.disable()
    try:
        results = load_scan(args.file)
    except json.JSONDecodeError as e:
        ui.fail(f"can't export {args.file}: it isn't valid JSON ({e})")
        return 1
    except OSError as e:  # missing file, no permission
        ui.fail(f"can't export {args.file}: {e.strerror or e}")
        return 1
    except ValueError as e:  # valid JSON, but not a domain scan
        ui.fail(f"can't export {args.file}: {e}")
        return 1
    for path in save(results, args.format, datetime.now()):
        ui.good(f"Saved {short_path(path)}")
    return 0
