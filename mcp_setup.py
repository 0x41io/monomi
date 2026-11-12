"""
monomi mcp setup: add Monomi to the Claude desktop app's MCP config.

    python monomi.py mcp setup          # show the change, ask, then write it
    python monomi.py mcp setup --yes    # write without asking
    python monomi.py mcp setup --print  # only print the entry (for other MCP clients)
    python monomi.py mcp setup --allow-active  # also allow ACTIVE tools (asks you first)
    python monomi.py mcp setup --no-active     # turn ACTIVE tools back off
    python monomi.py mcp setup --scope FILE    # approve the scope file for ACTIVE tools
    python monomi.py mcp setup --no-scope      # clear the approved scope

Without --allow-active/--no-active or --scope/--no-scope, setup keeps
whatever the config has now. Turning active tools ON, and setting or
changing the scope, always ask you to type "yes" at a real terminal, even
with --yes: an agent running commands for you can't do either. The scope
file's sha256 is saved next to its path, so the server refuses active
checks if the file is edited after you approved it.

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

import scope
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
SCOPE_FLAG = "--scope"              # mcp_server.py's flag: the approved scope file
SCOPE_HASH_FLAG = "--scope-sha256"  # ...and the sha256 it had when you approved it


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


def scope_args(entry):
    """(scope file path, approved sha256) from a config entry, or (None, None)."""
    if not isinstance(entry, dict):
        return None, None
    args = entry.get("args") or []
    found = {}
    for flag in (SCOPE_FLAG, SCOPE_HASH_FLAG):
        if flag in args:
            i = args.index(flag)
            found[flag] = args[i + 1] if i + 1 < len(args) else None
    return found.get(SCOPE_FLAG), found.get(SCOPE_HASH_FLAG)


def with_scope(entry, path, sha256):
    """A copy of the entry with the scope pair set (or removed if path is None).
    Each flag is removed together with its value, so it's never added twice."""
    old, args, skip = entry.get("args", []), [], False
    for a in old:
        if skip:
            skip = False
        elif a in (SCOPE_FLAG, SCOPE_HASH_FLAG):
            skip = True  # also drop the value that follows the flag
        else:
            args.append(a)
    if path:
        args += [SCOPE_FLAG, path, SCOPE_HASH_FLAG, sha256]
    return {**entry, "args": args}


def build_entry(on, path, sha256):
    """The full entry: the server, the scope pair, then --allow-active last.
    Always built in this order, so the same settings give the same entry."""
    return with_active(with_scope(server_entry(), path, sha256), on)


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

    Windows can have more than one copy, and the app reads only one of them:
      %APPDATA%\\Claude                                      (standard install)
      %LOCALAPPDATA%\\Packages\\Claude_*\\LocalCache\\Roaming\\Claude  (older MSIX installs)
      %LOCALAPPDATA%\\Claude-Data\\claude_*                   (newer MSIX installs)
    so setup writes every copy it finds, and doctor checks them all.
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
        # [Cc]: this folder is lowercase "claude_..." and names match case-sensitively here
        data = os.path.join(local, "Claude-Data", "[Cc]laude_*", CONFIG)
        found += sorted(glob.glob(data))
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


def show_scope(s):
    """Everything you're approving: the file, its hash, every rule, every rejected line."""
    print(f"\n{ui.paint('Scope file for ACTIVE tools', ui.BOLD, ui.YELLOW)}")
    print(f"  file:   {s.path}")
    print(f"  sha256: {s.sha256}")
    print(f"  in scope ({len(s.inclusions)}):")
    for r in s.inclusions:
        print(f"    {ui.safe(r.text)}")
    if s.exclusions:
        print(f"  never in scope, even if a rule above matches ({len(s.exclusions)}):")
        for r in s.exclusions:
            print(f"    {ui.safe(r.text)}")
    if s.rejected:
        print(f"  {ui.paint(f'rejected lines ({len(s.rejected)}), these do NOT count:', ui.YELLOW)}")
        for r in s.rejected:
            print(f"    line {r['line']}: {ui.safe(r['text'])}  ({r['reason']})")
    print("  Active tools will only ever send requests to hosts these rules allow.")


def confirm(turning_on, new_scope):
    """Turning active tools on, or setting/changing the scope, needs a person:
    a real terminal and the word "yes". --yes never skips this, and piped
    input (how agents run commands) is refused."""
    if turning_on:
        print(f"\n{ui.paint('Turning ACTIVE tools on', ui.BOLD, ui.YELLOW)}")
        print(ACTIVE_WARNING)
    if new_scope:
        show_scope(new_scope)
    asks = [("allow active tools", turning_on), ("approve this scope", new_scope)]
    what = " and ".join(words for words, needed in asks if needed)
    if not sys.stdin.isatty():
        ui.fail(f"To {what}, you have to type it yourself at a terminal "
                "(this input isn't one).")
        return False
    try:
        return input(f'\nType "yes" to {what}: ').strip().lower() == "yes"
    except EOFError:
        return False


def load_new_scope(path):
    """Read the scope file once (what's shown is what's hashed).
    Raises SetupError if it can't be used, so nothing is written."""
    s = scope.load(os.path.abspath(path))
    if s.problem():
        if s.rejected:
            show_scope(s)
        raise SetupError(f"{s.problem()}. Nothing was changed.")
    return s


def describe_scope(path, sha256):
    return f"{path} (sha256 {sha256[:12]}...)" if path else "none"


def setup(yes=False, active=None, scope_file=None, clear_scope=False):
    """active: True = allow ACTIVE tools, False = turn them off, None = keep each config's setting.
    scope_file: approve this scope file; clear_scope: remove it; neither = keep each config's."""
    new_scope = load_new_scope(scope_file) if scope_file else None
    found, standard = config_paths()
    targets = found or [standard]
    # Read every file first: if any is broken, nothing gets written anywhere
    configs = {path: load_config(path) for path in targets}

    plans, turning_on, scope_changing = {}, False, False
    for path, cfg in configs.items():
        old = cfg.get("mcpServers", {}).get(NAME)
        on = is_active(old) if active is None else active
        if clear_scope:
            pair = (None, None)
        elif new_scope:
            pair = (new_scope.path, new_scope.sha256)
        else:
            pair = scope_args(old)
        entry = build_entry(on, *pair)
        plans[path] = (*change(cfg, entry), entry)
        turning_on = turning_on or (on and not is_active(old))
        scope_changing = scope_changing or (new_scope is not None and pair != scope_args(old))

    for path, (status, old, entry) in plans.items():
        print(f"\n{ui.paint(path, ui.BOLD, ui.WHITE)}")
        if not os.path.exists(path):
            print("  no config yet: it will be created")
        print(f"  monomi: {status}")
        print(f"  active tools: {'ON' if is_active(entry) else 'off'}")
        print(f"  scope: {describe_scope(*scope_args(entry))}")
        if status == "changing":
            show_entry("now:", old)
        if status != "unchanged":
            show_entry("will be:", entry)

    to_write = [p for p, (status, _, _) in plans.items() if status != "unchanged"]
    if not to_write:
        ui.good("Monomi is already set up in the Claude app. Nothing to change.")
        return 0
    if turning_on or scope_changing:
        if not confirm(turning_on, new_scope if scope_changing else None):
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
          "or the scope only takes effect after that restart.")
    if any(is_active(e) and not scope_args(e)[0] for _, _, e in plans.values()):
        ui.warn("ACTIVE tools are on but no scope file is approved, so every active "
                "check will refuse. Approve one with: python monomi.py mcp setup --scope FILE")
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
    scoping = parser.add_mutually_exclusive_group()
    scoping.add_argument("--scope", dest="scope_file", metavar="FILE",
                         help="approve this scope file: ACTIVE tools only reach hosts it allows "
                              "(asks you first)")
    scoping.add_argument("--no-scope", dest="clear_scope", action="store_true",
                         help="remove the approved scope (active tools then refuse everything)")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output (also respects NO_COLOR)")
    args = parser.parse_args(argv)
    if args.no_color:
        ui.disable()

    try:
        if args.print_only:
            s = load_new_scope(args.scope_file) if args.scope_file else None
            entry = build_entry(bool(args.active), s.path if s else None, s.sha256 if s else None)
            print(json.dumps({"mcpServers": {NAME: entry}}, indent=2))
            return 0
        return setup(yes=args.yes, active=args.active,
                     scope_file=args.scope_file, clear_scope=args.clear_scope)
    except SetupError as e:
        ui.fail(str(e))
        return 1
