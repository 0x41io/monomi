"""
monomi mcp setup: add Monomi to the Claude desktop app's MCP config.

    python monomi.py mcp setup          # show the change, ask, then write it
    python monomi.py mcp setup --yes    # write without asking
    python monomi.py mcp setup --print  # only print the entry (for other MCP clients)
    python monomi.py mcp setup --allow-active  # also allow ACTIVE tools (asks you first)
    python monomi.py mcp setup --no-active     # turn ACTIVE tools back off

Without --allow-active or --no-active, setup keeps whatever the config has now.
Turning active tools ON always asks you to type "yes" at a real terminal,
even with --yes: an agent running commands for you can't turn them on.

Safe by design: only the "monomi" entry changes (other servers and settings
stay as they are), the old file is backed up first, a file that isn't valid
JSON is never overwritten, and the new file is swapped in whole.
"""

import argparse
import glob
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime

import ui

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "mcp_server.py")
NAME = "monomi"            # the server's name in the config
CONFIG = "claude_desktop_config.json"
ACTIVE_FLAG = "--allow-active"  # mcp_server.py's flag that allows ACTIVE tools
ACTIVE_LOG = os.path.join(HERE, "scans", "active.log")  # where mcp_server.py logs them
ACTIVE_WARNING = (
    "ACTIVE tools send requests to the target's own servers (today: fingerprint_hosts,\n"
    "one homepage request per host). Any agent connected to Monomi in the Claude app\n"
    "could then call them, so only scan targets you're allowed to test. Every request\n"
    "is written to scans/active.log, and `python monomi.py doctor` shows the setting.")


class SetupError(Exception):
    """Something that stops setup before anything is written."""


# ---------- What to write ----------

def in_wsl():
    return "microsoft" in platform.uname().release.lower()


def server_entry():
    """How the Claude app should start Monomi's MCP server.

    In WSL the app runs on Windows, so it starts Linux through wsl.exe:
    -d picks this Linux (WSL_DISTRO_NAME), -e runs Python directly, no shell.
    """
    if in_wsl():
        distro = os.environ.get("WSL_DISTRO_NAME")
        args = (["-d", distro] if distro else []) + ["-e", sys.executable, SERVER]
        return {"command": "wsl.exe", "args": args}
    return {"command": sys.executable, "args": [SERVER]}


def is_active(entry):
    """Does this config entry start the server with active tools allowed?"""
    return isinstance(entry, dict) and ACTIVE_FLAG in (entry.get("args") or [])


def with_active(entry, on):
    """A copy of the entry with --allow-active added (on) or removed (off)."""
    args = [a for a in entry.get("args", []) if a != ACTIVE_FLAG]
    return {**entry, "args": args + ([ACTIVE_FLAG] if on else [])}


# ---------- Where the config is ----------

def windows_folder(var):
    """A Windows folder (e.g. %APPDATA%) as a path this Python can open, or None."""
    if not in_wsl():
        return os.environ.get(var)
    try:
        # cwd on the Windows drive: cmd.exe complains when started from a Linux folder
        out = subprocess.run(["cmd.exe", "/c", f"echo %{var}%"], cwd="/mnt/c",
                             capture_output=True, text=True, timeout=10).stdout
        win = out.strip().strip('"')  # Windows may wrap the folder in quotes
        if not win or "%" in win:
            return None
        return subprocess.run(["wslpath", "-u", win], capture_output=True,
                              text=True, timeout=10).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def config_paths():
    """(config files that exist, the standard path to create if none do).

    Windows can have two copies: the standard one in %APPDATA%\\Claude, and
    one inside the MSIX package folder that some installs read instead.
    """
    system = platform.system()
    if system == "Darwin":
        home = os.path.expanduser("~/Library/Application Support/Claude")
        return [p for p in [os.path.join(home, CONFIG)] if os.path.exists(p)], \
            os.path.join(home, CONFIG)
    if system == "Linux" and not in_wsl():
        standard = os.path.join(os.path.expanduser("~/.config/Claude"), CONFIG)
        return [p for p in [standard] if os.path.exists(p)], standard

    appdata, local = windows_folder("APPDATA"), windows_folder("LOCALAPPDATA")
    if not appdata:
        raise SetupError("couldn't find your Windows user folder (%APPDATA%); "
                         "run with --print and add the entry by hand")
    standard = os.path.join(appdata, "Claude", CONFIG)
    found = [standard] if os.path.exists(standard) else []
    if local:
        msix = os.path.join(local, "Packages", "Claude_*", "LocalCache",
                            "Roaming", "Claude", CONFIG)
        found += sorted(glob.glob(msix))
    return found, standard


# ---------- Reading, changing and writing ----------

def load_config(path):
    """The config as a dict ({} if the file is missing or empty).

    Raises SetupError if it isn't valid JSON, so it's never overwritten.
    utf-8-sig also reads files that Windows editors saved with a BOM.
    """
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    if not text.strip():
        return {}
    try:
        config = json.loads(text)
    except ValueError as e:
        raise SetupError(f"{path} isn't valid JSON ({e}); fix it or move it "
                         "away, then run setup again. Nothing was changed.")
    servers = config.get("mcpServers", {}) if isinstance(config, dict) else None
    if not isinstance(servers, dict):
        raise SetupError(f"{path} doesn't look like a Claude config "
                         "(expected {\"mcpServers\": {...}}). Nothing was changed.")
    return config


def change(config, entry):
    """'new', 'unchanged' or 'changing', and the old entry (or None)."""
    old = config.get("mcpServers", {}).get(NAME)
    if old is None:
        return "new", None
    return ("unchanged" if old == entry else "changing"), old


def with_entry(config, entry):
    """A copy of the config with Monomi's entry set; everything else kept."""
    new = dict(config)
    new["mcpServers"] = {**config.get("mcpServers", {}), NAME: entry}
    return new


def write_config(path, config):
    """Back up the old file, then swap the new one in whole. Returns the backup path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup = None
    if os.path.exists(path):
        backup = f"{path}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(path, backup)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(config, indent=2) + "\n")
    os.replace(tmp, path)  # all at once: a crash can't leave half a file
    return backup


# ---------- The command ----------

def show_entry(label, entry):
    print(f"  {ui.paint(label, ui.GREY)}")
    for line in json.dumps(entry, indent=2).splitlines():
        print(f"    {line}")


def ask(question):
    try:
        return input(question).strip().lower() in ("y", "yes")
    except EOFError:  # no keyboard (e.g. piped): treat as "no"
        return False


def confirm_active():
    """Turning active tools on needs a person: a real terminal and the word "yes".
    --yes never skips this, and piped input (how agents run commands) is refused."""
    print(f"\n{ui.paint('Turning ACTIVE tools on', ui.BOLD, ui.YELLOW)}")
    print(ACTIVE_WARNING)
    if not sys.stdin.isatty():
        ui.fail("Turning active tools on has to be typed by you at a terminal "
                "(this input isn't one).")
        return False
    try:
        return input('\nType "yes" to allow active tools: ').strip().lower() == "yes"
    except EOFError:
        return False


def setup(yes=False, active=None):
    """active: True = allow ACTIVE tools, False = turn them off, None = keep each config's setting."""
    found, standard = config_paths()
    targets = found or [standard]
    # Read every file first: if any is broken, nothing gets written anywhere
    configs = {path: load_config(path) for path in targets}

    plans, turning_on = {}, False
    for path, cfg in configs.items():
        old = cfg.get("mcpServers", {}).get(NAME)
        on = is_active(old) if active is None else active
        entry = with_active(server_entry(), on)
        plans[path] = (*change(cfg, entry), entry)
        turning_on = turning_on or (on and not is_active(old))

    for path, (status, old, entry) in plans.items():
        print(f"\n{ui.paint(path, ui.BOLD, ui.WHITE)}")
        if not os.path.exists(path):
            print("  no config yet: it will be created")
        print(f"  monomi: {status}")
        print(f"  active tools: {'ON' if is_active(entry) else 'off'}")
        if status == "changing":
            show_entry("now:", old)
        if status != "unchanged":
            show_entry("will be:", entry)

    to_write = [p for p, (status, _, _) in plans.items() if status != "unchanged"]
    if not to_write:
        ui.good("Monomi is already set up in the Claude app. Nothing to change.")
        return 0
    if turning_on:
        if not confirm_active():
            ui.info("Nothing was changed.")
            return 0
    elif not yes and not ask("\nWrite this? [y/N] "):
        ui.info("Nothing was changed.")
        return 0

    for path in to_write:
        backup = write_config(path, with_entry(configs[path], plans[path][2]))
        ui.good(f"Updated {path}")
        if backup:
            ui.info(f"Backup of the old file: {backup}")
    print("\nNext: fully quit the Claude app, not just its window (Windows: "
          "right-click its tray icon > Quit; macOS: Cmd+Q), open it again, "
          "and ask Claude to run Monomi's ping tool. A change to active tools "
          "only takes effect after that restart.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="monomi.py mcp",
        description="set up Monomi's MCP server in the Claude desktop app")
    parser.add_argument("action", choices=["setup"])
    parser.add_argument("--yes", action="store_true", help="write without asking")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="only print the config entry (for other MCP clients)")
    active = parser.add_mutually_exclusive_group()
    active.add_argument("--allow-active", dest="active", action="store_const", const=True,
                        help="also allow ACTIVE tools, which send requests to targets (asks you first)")
    active.add_argument("--no-active", dest="active", action="store_const", const=False,
                        help="turn ACTIVE tools off")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output (also respects NO_COLOR)")
    args = parser.parse_args(argv)
    if args.no_color:
        ui.disable()

    if args.print_only:
        entry = with_active(server_entry(), bool(args.active))
        print(json.dumps({"mcpServers": {NAME: entry}}, indent=2))
        return 0
    try:
        return setup(yes=args.yes, active=args.active)
    except SetupError as e:
        ui.fail(str(e))
        return 1
