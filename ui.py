"""
Terminal styling for monomi: the colored banner and status markers.

Uses plain ANSI escape codes (no extra dependency). Color turns itself off
when output isn't a terminal (piping to a file) or when NO_COLOR is set.
"""

import os
import re
import shutil
import sys

from common import VERSION

ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def disable() -> None:
    global ENABLED
    ENABLED = False


def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
BOLD = "\033[1m"

WHITE = rgb(240, 240, 240)
SILVER = rgb(120, 120, 128)    # shadow edge on the white letters
RED = rgb(255, 40, 60)
DARK_RED = rgb(110, 0, 18)     # shadow edge on the red letters
GREY = rgb(130, 130, 140)
GREEN = rgb(80, 220, 120)
YELLOW = rgb(255, 200, 60)

# Top-to-bottom red gradient for the "41" (bright at the top, deeper below)
RED_RAMP = [rgb(255, 70, 85), rgb(255, 45, 62), rgb(235, 25, 45),
            rgb(210, 15, 35), rgb(180, 8, 28), rgb(150, 0, 22)]


# Control characters (including ESC, which starts terminal escape codes)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text: str) -> str:
    """Neutralize control characters in untrusted text before printing it.

    Data from other people (web banners, SpiderFoot findings) can contain
    escape codes that recolor, hide or rewrite lines in your terminal.
    """
    return _CONTROL.sub("?", str(text))


def paint(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET if ENABLED else text


LOGO = [
    " ██████╗ ██╗  ██╗██╗  ██╗ ██╗",
    "██╔═████╗╚██╗██╔╝██║  ██║███║",
    "██║██╔██║ ╚███╔╝ ███████║╚██║",
    "████╔╝██║ ██╔██╗ ╚════██║ ██║",
    "╚██████╔╝██╔╝ ██╗     ██║ ██║",
    " ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝",
]
SPLIT = 17  # column where "0x" ends and "41" begins


def _shade(segment: str, face: str, edge: str) -> str:
    """Solid blocks get the face color, box-drawing 'shadow' gets the edge color."""
    out, current = [], None
    for ch in segment:
        color = face if ch == "█" else edge if ch.strip() else None
        if color and color != current:
            out.append(color)
            current = color
        out.append(ch)
    return "".join(out) + RESET


def banner() -> str:
    side = [
        "",
        f"{paint('mønømi', BOLD, RED)}  {paint('v' + VERSION, GREY)}",
        "",
        paint("passive OSINT · AI analysis", GREY),
        paint("by ", GREY) + paint("0x", WHITE) + paint("41", RED),
        "",
    ]
    lines = []
    for i, row in enumerate(LOGO):
        if ENABLED:
            logo = _shade(row[:SPLIT], WHITE, SILVER) + _shade(row[SPLIT:], RED_RAMP[i], DARK_RED)
        else:
            logo = row
        lines.append(f"{logo}   {side[i]}".rstrip())
    return "\n" + "\n".join(lines) + "\n"


# Status markers used throughout the CLI
def info(msg: str) -> None:
    print(f"{paint('[*]', GREY)} {msg}")


def good(msg: str) -> None:
    print(f"{paint('[+]', GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"{paint('[!]', YELLOW)} {msg}")


def fail(msg: str) -> None:
    print(f"{paint('[x]', BOLD, RED)} {msg}")


def _cell(text: str, width: int) -> str:
    text = text if len(text) <= width else text[: width - 1] + "…"
    return text.ljust(width)


def host_table(hosts: dict, indent: str = "    ", show_dead: int = 3) -> None:
    """Print enriched hosts as aligned columns: HOST  IP  PROVIDER  CC.

    Fits the terminal width. Hosts with no DNS record are listed after the
    live ones and collapsed to a few examples so they don't flood the screen.
    """

    live = {h: e for h, e in hosts.items() if e["ips"]}
    dead = [h for h, e in hosts.items() if not e["ips"]]

    cols = shutil.get_terminal_size((110, 24)).columns
    ip_w = 18
    def prov_label(e):
        # "Cloudflare +1" when a host's IPs belong to more than one provider
        extra = len(e.get("providers") or []) - 1
        return (e["provider"] or "") + (f" +{extra}" if extra > 0 else "")

    prov_w = min(max([len(prov_label(e)) for e in live.values()] + [8]), 20)
    room = cols - len(indent) - ip_w - prov_w - 2 - 6 - 1  # gaps + CC column
    host_w = max(20, min(max([len(h) for h in live] + [4]), room))

    def line(h, ip, prov, cc):
        return f"{_cell(h, host_w)}  {ip}  {prov}  {cc}"

    print(indent + paint(line("HOST", "IP".ljust(ip_w), "PROVIDER".ljust(prov_w), "CC"), GREY))
    print(indent + paint("─" * (host_w + ip_w + prov_w + 8), GREY))
    for host, e in live.items():
        ips = e["ips"]
        ip = ips[0] + (f" +{len(ips) - 1}" if len(ips) > 1 else "")
        provider = e["provider"]
        prov = _cell(prov_label(e), prov_w)
        prov = paint(prov, YELLOW, BOLD) if provider == "PRIVATE IP" else paint(prov, WHITE)
        print(indent + line(host, paint(_cell(ip, ip_w), GREY), prov, e.get("country", "-")))

    if dead:
        print()
        shown = dead if len(dead) <= show_dead + 1 else dead[:show_dead]
        print(indent + paint(f"{len(dead)} host(s) in CT logs have no DNS record (likely retired):", GREY))
        for h in shown:
            print(indent + "  " + paint(h, GREY))
        if len(shown) < len(dead):
            print(indent + "  " + paint(f"... and {len(dead) - len(shown)} more (full list with --json)", GREY))


def provider_bars(providers: dict, total: int, width: int = 24, top: int = 8, indent: str = "    ") -> None:
    """Small horizontal bar chart of hosts per provider."""
    items = list(providers.items())
    if len(items) > top:
        rest = sum(n for _, n in items[top:])
        items = items[:top] + [(f"{len(providers) - top} others", rest)]
    name_w = min(max(len(n) for n, _ in items), 26)
    biggest = max(n for _, n in items)
    for name, n in items:
        bar = "█" * max(1, round(n / biggest * width))
        color = GREY if name == "no DNS record" else YELLOW if name == "PRIVATE IP" else RED
        pct = f"{n / total:4.0%}" if total else ""
        print(f"{indent}{_cell(name, name_w)}  {paint(bar.ljust(width), color)}  {n:>3}  {paint(pct, GREY)}")


def exposure_table(exposure: dict, indent: str = "    ") -> None:
    """Print the Shodan InternetDB findings that matter: IP  HOST  PORTS  CVES  NOTE.

    Only IPs with CVEs, risky services or ports beyond 80/443 get a row.
    Plain web servers and shared CDN edge IPs are summarized in one line each
    (their details stay in --json), so the important rows aren't buried.
    """

    web = {80, 443}
    items = exposure["ips"].items()
    edge = [ip for ip, d in items if d["shared_edge"]]
    web_only = {ip for ip, d in items if not d["shared_edge"] and not d["vulns"] and set(d["ports"]) <= web}
    rows = sorted(
        ((ip, d) for ip, d in items if not d["shared_edge"] and ip not in web_only),
        key=lambda kv: (-len(kv[1]["vulns"]), -len(kv[1]["risky"])),
    )

    if rows:
        cols = shutil.get_terminal_size((110, 24)).columns
        ip_w, ports_w, cve_w = 16, 24, 5
        host_w = max(18, min(max(len(d["hosts"][0]) + 4 for _, d in rows), cols - len(indent) - ip_w - ports_w - cve_w - 30))

        head = f"{_cell('IP', ip_w)}  {_cell('HOST', host_w)}  {_cell('PORTS', ports_w)}  {'CVES':>{cve_w}}  NOTE"
        print(indent + paint(head, GREY))
        print(indent + paint("─" * (ip_w + host_w + ports_w + cve_w + 14), GREY))
        for ip, d in rows:
            host = d["hosts"][0] + (f" +{len(d['hosts']) - 1}" if len(d["hosts"]) > 1 else "")
            ports = ", ".join(str(p) for p in d["ports"]) or "-"
            n = len(d["vulns"])
            note = paint("exposed: " + ", ".join(d["risky"]), YELLOW, BOLD) if d["risky"] else ""
            cve_txt = paint(f"{n:>{cve_w}}", RED, BOLD) if n else paint(f"{n:>{cve_w}}", GREY)
            print(indent + f"{paint(_cell(ip, ip_w), GREY)}  {_cell(host, host_w)}  {_cell(ports, ports_w)}  {cve_txt}  {note}".rstrip())
        print()
    elif not web_only and edge:
        print(indent + paint("Every IP with open ports belongs to a CDN, so none of the target's own servers are visible to check.", GREEN))
    else:
        print(indent + paint("Nothing beyond normal web ports (80/443) on the target's own IPs, and no known CVEs.", GREEN))

    if web_only:
        print(indent + paint(f"{len(web_only)} IP(s) only serve web traffic (80/443) with no known CVEs.", GREY))
    if edge:
        print(indent + paint(f"{len(edge)} shared CDN edge IP(s) not shown: their open ports belong to the CDN.", GREY))
    if web_only or edge:
        print(indent + paint("Full details with --json", GREY))


# ---------------------------------------------------------------------------
# AI report rendering
# ---------------------------------------------------------------------------


# Matches priority headers however the model writes them:
#   "### High", "### High priority", "**High**", "**Medium:**", "High priority:"
_PRIORITY = re.compile(
    r"^[ \t]*(?:#{1,6}[ \t]*)?(?:\*\*|__)?[ \t]*(High|Medium|Low)(?![A-Za-z-])(?:[ \t]+priority)?"
    r"[ \t]*:?[ \t]*(?:\*\*|__)?[ \t]*:?[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
_PRIORITY_STYLE = {"high": "bold #ffffff on #c8102e", "medium": "bold #0c0c0c on #ffc83c", "low": "bold #ffffff on #5a5a64"}


def render_report(markdown: str) -> None:
    """Pretty-print the AI's Markdown report in the terminal.

    Uses the 'rich' library when it's installed (headings in 0x41 red, real
    tables, bold text, High/Medium/Low as colored badges). Falls back to the
    raw Markdown when rich is missing or color is off.
    """
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        from rich.text import Text
        from rich.theme import Theme
    except ImportError:
        print(markdown)
        return
    if not ENABLED:
        print(markdown)
        return

    theme = Theme({
        "markdown.h1": "bold #ff283c",
        "markdown.h1.border": "#6e0012",
        "markdown.h2": "bold #ff283c",
        "markdown.h3": "bold #f0f0f0",
        "markdown.h4": "bold #f0f0f0",
        "markdown.strong": "bold #f0f0f0",
        "markdown.em": "italic #b4b4be",
        "markdown.code": "#ff8c96",
        "markdown.item.bullet": "#ff283c",
        "markdown.item.number": "#ff283c",
        "markdown.block_quote": "#ffc83c",
        "markdown.hr": "#6e0012",
        "markdown.link": "#78b4ff",
        "markdown.table.border": "#6e0012",
        "markdown.table.header": "bold #ff283c",
    })
    console = Console(theme=theme, highlight=False)

    # rich centers top-level "# Title" headings; demote them so everything lines up left
    markdown = re.sub(r"^# ", "## ", markdown, flags=re.MULTILINE)

    # Split around High / Medium / Low headings so they can be drawn as badges
    pos = 0
    for m in _PRIORITY.finditer(markdown):
        chunk = markdown[pos:m.start()].strip()
        if chunk:
            console.print(Markdown(chunk, code_theme="monokai"))
        level = m.group(1).lower()
        console.print()
        console.print(Text(f" {level.upper()} ", style=_PRIORITY_STYLE[level]))
        pos = m.end()
    rest = markdown[pos:].strip()
    if rest:
        console.print(Markdown(rest, code_theme="monokai"))
