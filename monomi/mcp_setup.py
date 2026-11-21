"""
monomi mcp setup: add Monomi to an MCP client's config (the Claude desktop
app by default; see CLIENTS for the others).

    python monomi.py mcp setup          # show the change, ask, then write it
    python monomi.py mcp setup --yes    # write without asking
    python monomi.py mcp setup --print  # only print the entry (for other MCP clients)
    python monomi.py mcp setup --rate N        # active requests per second (default 1)
    python monomi.py mcp setup --no-rate       # back to the default (1/s)
    python monomi.py mcp setup --client NAME   # set up another MCP client (see CLIENTS)

Active tools have no setting here since v1.20: each active check runs only
after a person approves it at a terminal (`python monomi.py approve ID
--scope FILE`), where the scope and research files are chosen. Setup
removes the v1.19 flags (--allow-active, --scope, --research and their
hashes) from every entry it writes; the server ignores them meanwhile.
--rate stays: it's the server-wide limit, not part of an approval.

Safe by design: only the "monomi" entry changes (other servers and settings
stay as they are), the old file is backed up first, a file that can't be
read is never overwritten, and the new file is swapped in whole.

Every client stores the same entry inside Monomi: {"command", "args"}, with
--rate in args when set. A client adapter (Client below)
only knows where that client's config lives and how to read and write it, so
the safety rules above are written once and hold for every client.
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

import io

import tomlkit
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError
from tomlkit.exceptions import TOMLKitError

from monomi import home, rate, ui

SERVER = os.path.join(home.REPO_DIR, "mcp_server.py")  # the root wrapper, in a copy of the repo
NAME = "monomi"            # the server's name in the config
CONFIG = "claude_desktop_config.json"
ACTIVE_LOG = home.data_dir("scans", "active.log")  # where mcp_server.py logs active requests
RATE_FLAG = "--rate"                      # active requests per second (v1.19)
# v1.19's flags, gone since v1.20: --allow-active alone, the others with a value.
# Setup strips them; doctor names them; the server ignores them.
ACTIVE_FLAG = "--allow-active"
SCOPE_FLAG, SCOPE_HASH_FLAG = "--scope", "--scope-sha256"
RESEARCH_FLAG, RESEARCH_HASH_FLAG = "--research", "--research-sha256"
LEGACY_FLAGS = (ACTIVE_FLAG, SCOPE_FLAG, SCOPE_HASH_FLAG, RESEARCH_FLAG, RESEARCH_HASH_FLAG)


class SetupError(Exception):
    """Something that stops setup before anything is written."""


class HasComments(SetupError):
    """The config has comments (OpenCode's JSONC): fine for the client, but
    rewriting it would delete them, so setup won't, and doctor can't look inside."""


# ---------- What to write ----------

def in_wsl():
    return "microsoft" in platform.uname().release.lower()


def server_args():
    """What comes after python to start the server.

    From a copy of the repo: the mcp_server.py wrapper's full path, as always,
    so existing configs keep matching. A plain `pip install` has no wrapper
    file, so Python is told to run the installed module instead.
    """
    if home.running_from_repo():
        return [SERVER]
    return ["-m", "monomi.mcp_server"]


def server_entry():
    """How the Claude app should start Monomi's MCP server.

    In WSL the app runs on Windows, so it starts Linux through wsl.exe:
    -d picks this Linux (WSL_DISTRO_NAME), -e runs Python directly, no shell.
    """
    if in_wsl():
        distro = os.environ.get("WSL_DISTRO_NAME")
        args = (["-d", distro] if distro else []) + ["-e", sys.executable, *server_args()]
        return {"command": "wsl.exe", "args": args}
    return {"command": sys.executable, "args": server_args()}


def flag_values(entry, *flags):
    """The value after each flag in a config entry's args (None when absent)."""
    if not isinstance(entry, dict):
        return tuple(None for _ in flags)
    args = entry.get("args") or []
    found = {}
    for flag in flags:
        if flag in args:
            i = args.index(flag)
            found[flag] = args[i + 1] if i + 1 < len(args) else None
    return tuple(found.get(flag) for flag in flags)


def without_flags(entry, *flags):
    """A copy of the entry without these flags, each removed together with its
    value, so a flag is never added twice."""
    args, skip = [], False
    for a in entry.get("args", []):
        if skip:
            skip = False
        elif a in flags:
            skip = True  # also drop the value that follows the flag
        else:
            args.append(a)
    return {**entry, "args": args}


def rate_arg(entry):
    """The --rate value (as written in the config) or None for the default."""
    return flag_values(entry, RATE_FLAG)[0]


def with_rate(entry, value):
    """A copy of the entry with --rate set (or removed if value is None)."""
    entry = without_flags(entry, RATE_FLAG)
    if value is not None:
        entry["args"] += [RATE_FLAG, value]
    return entry


def legacy_flags(entry):
    """The v1.19 flags in a config entry, in the order they appear."""
    if not isinstance(entry, dict):
        return []
    return [a for a in (entry.get("args") or []) if a in LEGACY_FLAGS]


def without_legacy(entry):
    """A copy of the entry without the v1.19 flags (each value-flag with its value)."""
    entry = {**entry, "args": [a for a in entry.get("args", []) if a != ACTIVE_FLAG]}
    return without_flags(entry, SCOPE_FLAG, SCOPE_HASH_FLAG, RESEARCH_FLAG, RESEARCH_HASH_FLAG)


def build_entry(base=None, rate_value=None):
    """The full entry: the server, then --rate when set. Never a v1.19 flag.
    base: how the client starts the server (default: the Claude app's way)."""
    return with_rate(without_legacy(base or server_entry()), rate_value)


def same_settings(base, old):
    """What doctor compares an existing entry against: base with old's rate,
    and old's v1.19 flags left where they are, so neither makes the entry
    "different" (doctor names old flags on their own line)."""
    entry = build_entry(base, rate_arg(old))
    if legacy_flags(old):
        server = without_flags({"args": base.get("args", [])}, RATE_FLAG)["args"]
        extra = [a for a in (old.get("args") or [])[len(server):]]
        entry = {**entry, "args": server + extra}
    return entry


def rate_value(text):
    """--rate N for setup: checked, then written as it reads back ("1", "0.5")."""
    try:
        return f"{rate.parse(text):g}"
    except rate.RateError as e:
        raise SetupError(f"{e}. Nothing was changed.")


def describe_rate(value):
    return f"{value}/s" if value else f"{rate.SCOPED_DEFAULT:g}/s (the default)"


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


def write_text(path, text):
    """Back up the old file, then swap the new one in whole. Returns the backup path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup = None
    if os.path.exists(path):
        backup = f"{path}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(path, backup)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)  # all at once: a crash can't leave half a file
    return backup


def write_config(path, config):
    """Write a Claude config (JSON). Returns the backup path."""
    return write_text(path, json.dumps(config, indent=2) + "\n")


# ---------- MCP clients ----------

class Client:
    """One MCP client's config: where it lives, how to read and write it, and
    how Monomi's entry looks in it. Each method gets or gives the entry in
    Monomi's own shape, {"command", "args"}; the adapter translates."""
    key = ""        # the --client name
    label = ""      # how messages name it, e.g. "the Claude app"
    restart = ""    # what to do after a change, so the client loads it

    def paths(self):
        """(config files that exist, the path to create if none do)."""
        raise NotImplementedError

    def load(self, path):
        """The parsed config; raises SetupError if it can't be used safely."""
        raise NotImplementedError

    def entry(self, doc):
        """Monomi's entry from a parsed config, in Monomi's shape, or None."""
        raise NotImplementedError

    def with_entry(self, doc, entry):
        """A copy of the config with Monomi's entry set; everything else kept."""
        raise NotImplementedError

    def dump(self, doc):
        """The config as the text to write."""
        raise NotImplementedError

    def show(self, entry):
        """Monomi's entry as it will look in this client's file."""
        raise NotImplementedError

    def printable(self, entry):
        """What --print shows: the entry inside its section, ready to paste."""
        raise NotImplementedError

    def base(self):
        """How this client starts Monomi's server (before scope and active flags)."""
        raise NotImplementedError


class Claude(Client):
    """The Claude desktop app: JSON, "mcpServers", every copy of the file
    (Windows can have several). Calls the module's functions by name, so
    tests that replace them still apply."""
    key = "claude"
    label = "the Claude app"
    restart = ("fully quit the Claude app, not just its window (Windows: "
               "right-click its tray icon > Quit; macOS: Cmd+Q), open it again, "
               "and ask Claude to run Monomi's ping tool")

    def paths(self):
        return config_paths()

    def load(self, path):
        return load_config(path)

    def entry(self, doc):
        return doc.get("mcpServers", {}).get(NAME)

    def with_entry(self, doc, entry):
        return with_entry(doc, entry)

    def dump(self, doc):
        return json.dumps(doc, indent=2) + "\n"

    def show(self, entry):
        return json.dumps(entry, indent=2)

    def printable(self, entry):
        return json.dumps({"mcpServers": {NAME: entry}}, indent=2)

    def base(self):
        return server_entry()


def direct_entry():
    """How a client that runs where Monomi runs starts the server: this
    Python, no wsl.exe (unlike the Claude app on Windows reaching into WSL)."""
    return {"command": sys.executable, "args": server_args()}


def read_text(path):
    """A config file's text ("" if it's missing). utf-8-sig also reads files
    that Windows editors saved with a BOM."""
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


class Codex(Client):
    """OpenAI's Codex CLI: TOML, one [mcp_servers.monomi] table with command
    and args, in $CODEX_HOME/config.toml or ~/.codex/config.toml. The key is
    mcp_servers with an underscore: Codex silently ignores mcpServers.
    tomlkit keeps the file's comments and layout, and any other keys in
    Monomi's own table (say a tool_timeout_sec you added) stay as they are."""
    key = "codex"
    label = "Codex"
    restart = ("start a new Codex session (`codex`) and type /mcp to check that "
               "monomi is listed")

    def paths(self):
        home = os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")
        path = os.path.join(home, "config.toml")
        return ([path] if os.path.exists(path) else []), path

    def load(self, path):
        try:
            doc = tomlkit.parse(read_text(path))
        except TOMLKitError as e:
            raise SetupError(f"{path} isn't valid TOML ({e}); fix it or move it away, "
                             "then run setup again. Nothing was changed.")
        servers = doc.get("mcp_servers", {})
        if not isinstance(servers, dict) or not isinstance(servers.get(NAME, {}), dict):
            raise SetupError(f"{path} doesn't look like a Codex config (expected "
                             "[mcp_servers.<name>] tables). Nothing was changed.")
        return doc

    def entry(self, doc):
        table = doc.get("mcp_servers", {}).get(NAME)
        if table is None:
            return None
        return {"command": str(table.get("command", "")),
                "args": [str(a) for a in table.get("args", [])]}

    def with_entry(self, doc, entry):
        new = tomlkit.parse(tomlkit.dumps(doc))  # a copy: the loaded one stays as read
        if "mcp_servers" not in new:
            # A "super table" writes only [mcp_servers.monomi], no empty [mcp_servers]
            new["mcp_servers"] = tomlkit.table(is_super_table=True)
        servers = new["mcp_servers"]
        if NAME not in servers:
            servers[NAME] = tomlkit.table()
        servers[NAME]["command"] = entry["command"]
        servers[NAME]["args"] = list(entry["args"])
        return new

    def dump(self, doc):
        return tomlkit.dumps(doc).lstrip("\n")

    def show(self, entry):
        return self.printable(entry)

    def printable(self, entry):
        return self.dump(self.with_entry(tomlkit.document(), entry)).rstrip("\n")

    def base(self):
        return direct_entry()


class OpenCode(Client):
    """OpenCode: JSON in ~/.config/opencode/opencode.json (or .jsonc), with
    Monomi as {"type": "local", "command": [python, mcp_server.py, ...]}.

    Two shapes: V1 puts servers right under "mcp", V2 under "mcp.servers".
    V2 still reads V1, but V1 can't read V2, so Monomi writes the V1 shape
    unless the file already uses mcp.servers, and never mixes the two.

    OpenCode allows comments and trailing commas (JSONC). Python's json
    can't keep comments, so a file with them is never rewritten: setup
    stops and says how to get the entry to paste in by hand. Other keys in
    Monomi's own object (environment, timeout...) are kept."""
    key = "opencode"
    label = "OpenCode"
    restart = "quit OpenCode and start it again so it reads the new config"

    def paths(self):
        # OpenCode's docs give ~/.config/opencode on Linux and macOS; on
        # Windows they don't say, so the same folder under your profile is
        # used and doctor names the path it checked
        home = os.path.expanduser(os.path.join("~", ".config", "opencode"))
        files = [os.path.join(home, n) for n in ("opencode.json", "opencode.jsonc")]
        return [f for f in files if os.path.exists(f)], files[0]

    def load(self, path):
        text = read_text(path)
        if not text.strip():
            return {}
        try:
            doc = json.loads(text)
        except ValueError:
            raise HasComments(
                f"{path} can't be read as plain JSON: it probably has comments or trailing "
                "commas (OpenCode allows those). Rewriting it would delete them, so it "
                "wasn't touched. Get the entry with `python monomi.py mcp setup --client "
                "opencode --print` and paste it in by hand. Nothing was changed.")
        mcp = doc.get("mcp", {}) if isinstance(doc, dict) else None
        holder = mcp.get("servers", mcp) if isinstance(mcp, dict) else None
        if not isinstance(holder, dict) or not isinstance(holder.get(NAME, {}), dict):
            raise SetupError(f"{path} doesn't look like an OpenCode config (expected "
                             '{"mcp": {...}}). Nothing was changed.')
        return doc

    @staticmethod
    def _servers(doc):
        """Where the servers live: mcp.servers (V2) or mcp itself (V1)."""
        mcp = doc.get("mcp", {})
        return mcp["servers"] if isinstance(mcp.get("servers"), dict) else mcp

    def entry(self, doc):
        server = self._servers(doc).get(NAME)
        command = server.get("command") if server else None
        if not command:
            return None
        command = [command] if isinstance(command, str) else list(command)
        return {"command": str(command[0]), "args": [str(a) for a in command[1:]]}

    def with_entry(self, doc, entry):
        new = json.loads(json.dumps(doc))  # a copy: the loaded one stays as read
        new.setdefault("mcp", {})
        servers = self._servers(new)
        servers[NAME] = {**servers.get(NAME, {}), "type": "local",
                         "command": [entry["command"], *entry["args"]]}
        return new

    def dump(self, doc):
        return json.dumps(doc, indent=2) + "\n"

    def show(self, entry):
        return json.dumps(self.with_entry({}, entry)["mcp"][NAME], indent=2)

    def printable(self, entry):
        return json.dumps(self.with_entry({}, entry), indent=2)  # the V1 shape: both versions read it

    def base(self):
        return direct_entry()


class Hermes(Client):
    """Nous Research's Hermes Agent: YAML, mcp_servers.monomi with command and
    args, in $HERMES_HOME/config.yaml or ~/.hermes/config.yaml (Hermes' own
    Windows installer sets HERMES_HOME, so that case is covered too).

    ruamel.yaml edits the file in place: comments, key order and quotes stay,
    and the file's own indentation is detected and kept. Other keys in
    Monomi's own entry (env, timeout, tools...) stay as they are."""
    key = "hermes"
    label = "Hermes"
    restart = ("type /reload-mcp in a running Hermes chat, or start a new `hermes` "
               "session, so it reconnects to its MCP servers")

    def paths(self):
        home = os.environ.get("HERMES_HOME") or os.path.expanduser(os.path.join("~", ".hermes"))
        path = os.path.join(home, "config.yaml")
        return ([path] if os.path.exists(path) else []), path

    @staticmethod
    def _indentation(text):
        """(mapping indent, list-dash offset) this YAML text uses, measured
        from its own lines; (2, 0) when it has no nested keys or lists.
        ruamel's own guess misreads files whose first nested block is a list,
        and a wrong guess would re-indent the whole file when it's written."""
        lines = [(len(ln) - len(ln.lstrip(" ")), ln.strip()) for ln in text.splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]
        mapping = offset = None
        for i, (col, body) in enumerate(lines):
            parent = next((c for c, _ in reversed(lines[:i]) if c < col), None)
            if parent is None:
                continue
            if body.startswith("- ") and offset is None:
                offset = col - parent
            elif not body.startswith("-") and ":" in body and mapping is None:
                mapping = col - parent
        return mapping or 2, offset or 0

    @classmethod
    def _yaml(cls, text=""):
        """A round-trip YAML handler set to the indentation this text uses."""
        yaml = YAML()
        yaml.preserve_quotes = True
        mapping, offset = cls._indentation(text)
        yaml.indent(mapping=mapping, sequence=offset + 2, offset=offset)
        return yaml

    def load(self, path):
        text = read_text(path)
        try:
            doc = self._yaml(text).load(text) if text.strip() else None
        except YAMLError as e:
            raise SetupError(f"{path} isn't valid YAML ({e}); fix it or move it away, "
                             "then run setup again. Nothing was changed.")
        doc = CommentedMap() if doc is None else doc
        servers = doc.get("mcp_servers") if isinstance(doc, dict) else None
        if not isinstance(doc, dict) or not isinstance(servers or {}, dict) \
                or not isinstance(servers and servers.get(NAME) or {}, dict):
            raise SetupError(f"{path} doesn't look like a Hermes config (expected "
                             "mcp_servers: with one entry per server). Nothing was changed.")
        doc.yaml_text = text  # kept so dump() writes with the file's own indentation
        return doc

    def entry(self, doc):
        server = (doc.get("mcp_servers") or {}).get(NAME)
        if not server:
            return None
        return {"command": str(server.get("command", "")),
                "args": [str(a) for a in server.get("args") or []]}

    def with_entry(self, doc, entry):
        text = getattr(doc, "yaml_text", "")
        yaml = self._yaml(text)
        out = io.StringIO()
        yaml.dump(doc, out)
        new = yaml.load(out.getvalue()) or CommentedMap()  # a copy: the loaded one stays as read
        new.yaml_text = text
        if not new.get("mcp_servers"):
            new["mcp_servers"] = CommentedMap()
        servers = new["mcp_servers"]
        if NAME not in servers:
            servers[NAME] = CommentedMap()
        args = CommentedSeq(entry["args"])
        args.fa.set_flow_style()  # args: [a, b], like Hermes' own docs
        servers[NAME]["command"] = entry["command"]
        servers[NAME]["args"] = args
        return new

    def dump(self, doc):
        out = io.StringIO()
        self._yaml(getattr(doc, "yaml_text", "")).dump(doc, out)
        return out.getvalue()

    def show(self, entry):
        return self.dump(self.with_entry(CommentedMap(), entry)).rstrip("\n")

    def printable(self, entry):
        return self.show(entry)

    def base(self):
        return direct_entry()


CLIENTS = {c.key: c for c in (Claude(), Codex(), OpenCode(), Hermes())}


# ---------- The command ----------

def show_entry(label, entry, client=None):
    print(f"  {ui.paint(label, ui.GREY)}")
    for line in (client or CLIENTS["claude"]).show(entry).splitlines():
        print(f"    {line}")


def ask(question):
    try:
        return input(question).strip().lower() in ("y", "yes")
    except EOFError:  # no keyboard (e.g. piped): treat as "no"
        return False


def setup(yes=False, client=None, rate_text=None, clear_rate=False):
    """rate_text: set --rate; clear_rate: back to the default; neither = keep
    each config's. Every entry written loses the v1.19 flags.
    client: which MCP client to set up (a Client; default the Claude app)."""
    client = client or CLIENTS["claude"]
    new_rate = rate_value(rate_text) if rate_text is not None else None
    found, standard = client.paths()
    targets = found or [standard]
    # Read every file first: if any is broken, nothing gets written anywhere
    configs = {path: client.load(path) for path in targets}

    plans = {}
    for path, cfg in configs.items():
        old = client.entry(cfg)
        speed = None if clear_rate else new_rate if new_rate is not None else rate_arg(old)
        entry = build_entry(client.base(), speed)
        status = "new" if old is None else "unchanged" if old == entry else "changing"
        plans[path] = (status, old, entry)

    for path, (status, old, entry) in plans.items():
        print(f"\n{ui.paint(path, ui.BOLD, ui.WHITE)}")
        if not os.path.exists(path):
            print("  no config yet: it will be created")
        print(f"  monomi: {status}")
        print("  active checks: each one needs your approval in a terminal (python monomi.py approve)")
        print(f"  active request rate: {describe_rate(rate_arg(entry))}")
        if legacy_flags(old):
            print(f"  removing flags not used since v1.20: {', '.join(legacy_flags(old))}")
        if status == "changing":
            show_entry("now:", old, client)
        if status != "unchanged":
            show_entry("will be:", entry, client)

    to_write = [p for p, (status, _, _) in plans.items() if status != "unchanged"]
    if not to_write:
        ui.good(f"Monomi is already set up in {client.label}. Nothing to change.")
        return 0
    if not yes and not ask("\nWrite this? [y/N] "):
        ui.info("Nothing was changed.")
        return 0

    for path in to_write:
        backup = write_text(path, client.dump(client.with_entry(configs[path], plans[path][2])))
        ui.good(f"Updated {path}")
        if backup:
            ui.info(f"Backup of the old file: {backup}")
    print(f"\nNext: {client.restart}. A change to the rate only takes effect after that restart.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="monomi.py mcp",
        description="set up Monomi's MCP server in an MCP client (default: the Claude desktop app)")
    parser.add_argument("action", choices=["setup"])
    parser.add_argument("--client", choices=sorted(CLIENTS), default="claude",
                        help="which MCP client to set up (default: claude, the Claude desktop app)")
    parser.add_argument("--yes", action="store_true", help="write without asking")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="only print the config entry (for other MCP clients)")
    pacing = parser.add_mutually_exclusive_group()
    pacing.add_argument("--rate", dest="rate_text", metavar="N",
                        help=f"ACTIVE requests per second, in total (default {rate.SCOPED_DEFAULT:g})")
    pacing.add_argument("--no-rate", dest="clear_rate", action="store_true",
                        help=f"back to the default rate ({rate.SCOPED_DEFAULT:g}/s)")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output (also respects NO_COLOR)")
    args = parser.parse_args(argv)
    if args.no_color:
        ui.disable()

    try:
        client = CLIENTS[args.client]
        if args.print_only:
            speed = rate_value(args.rate_text) if args.rate_text is not None else None
            print(client.printable(build_entry(client.base(), speed)))
            return 0
        return setup(yes=args.yes, client=client, rate_text=args.rate_text, clear_rate=args.clear_rate)
    except SetupError as e:
        ui.fail(str(e))
        return 1
