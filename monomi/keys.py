"""
API keys for Monomi's MCP server.

The Claude app starts the MCP server without reading ~/.bashrc, so a key set
there never reaches it, and the OTX source quietly falls back to its saved
copy. So the server loads keys at startup from one file, shared by the whole
0x41 suite (`0x41 mcp` reads the same file):

    ~/.config/0x41/keys.env        OTX_API_KEY=...   (one per line, # comments ok)

Rules:
- Monomi loads only the keys it uses (USED). The file may also hold keys
  other 0x41 tools use (SUITE, e.g. NVD_API_KEY for kaidoku): those are
  left alone, never loaded here and never dropped when Monomi rewrites the
  file. Any other name is ignored with a note. No ANTHROPIC_API_KEY on
  purpose: nothing over MCP uses AI.
- The file is refused unless only you can read it (a real file, owned by
  you, permissions 600), the same rule ssh uses for private keys. Native
  Windows has no such permissions, so there it isn't checked.
- Values are never printed, logged or returned: only names.
- A key already set in the environment wins.

`python monomi.py mcp keys` writes the file from the keys set in your
terminal, so you never type them: it shows names (not values) and asks first.
"""

import os
import stat
import sys

USED = ("OTX_API_KEY",)                  # what Monomi loads
SUITE = ("OTX_API_KEY", "NVD_API_KEY")   # what the shared file may hold


def keys_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".config", "0x41", "keys.env")


def private_problem(path: str) -> str | None:
    """Why the file can't be trusted with keys, or None."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return f"{path} is a link; use a real file"
    if os.name != "posix":
        return None  # native Windows: no Unix permissions to check
    if st.st_uid != os.getuid():
        return f"{path} isn't owned by you"
    if st.st_mode & 0o077:
        return f"{path} can be read by others (permissions {stat.S_IMODE(st.st_mode):o}); run: chmod 600 {path}"
    return None


def read(path: str) -> tuple[dict, list]:
    """(every suite key in the file, notes). Notes name lines, never values."""
    keys, notes = {}, []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            name, eq, value = line.partition("=")
            name, value = name.strip(), value.strip().strip("'\"")
            if not eq or not name:
                notes.append(f"line {n} isn't NAME=value, skipped")
            elif name not in SUITE:
                notes.append(f"{name} ignored (the key file holds only {', '.join(SUITE)})")
            elif not value:
                notes.append(f"{name} is empty, skipped")
            else:
                keys[name] = value
    return keys, notes


def load(path: str | None = None, environ=None) -> list:
    """Put the keys Monomi uses into the environment, so every tool call sees
    them. Returns lines for the server's startup message: names only."""
    path = path or keys_path()
    environ = os.environ if environ is None else environ
    if not os.path.lexists(path):
        return [f"no key file ({path}): OTX runs without a key over MCP "
                "(`python monomi.py mcp keys` writes one)"]
    problem = private_problem(path)
    if problem:
        return [f"key file refused, running without it: {problem}"]
    keys, notes = read(path)
    loaded, kept = [], []
    for name in USED:
        if name not in keys:
            continue
        if environ.get(name):
            kept.append(name)
        else:
            environ[name] = keys[name]
            loaded.append(name)
    out = [f"keys loaded from {path}: {', '.join(loaded) or 'none'}"]
    if kept:
        out.append(f"already set in the environment, kept: {', '.join(kept)}")
    return out + notes


def write_from_env(path: str | None = None, environ=None, ask=input, out=print) -> int:
    """`monomi.py mcp keys`: write the keys Monomi uses, as set in this
    terminal, to the shared key file, readable only by you. Keeps the other
    tools' keys already in it. Shows names, never values; asks first."""
    path = path or keys_path()
    environ = os.environ if environ is None else environ
    names = [n for n in USED if environ.get(n)]
    if not names:
        out(f"None of {', '.join(USED)} is set in this terminal, so there's nothing to write.")
        return 1
    existing = {}
    if os.path.lexists(path):
        problem = private_problem(path)
        if problem and "permissions" not in problem:  # a loose mode gets fixed by the rewrite below
            out(f"Not touching it: {problem}")
            return 1
        existing, _ = read(path)
    keys = {**existing, **{n: environ[n] for n in names}}
    out(f"Will write {', '.join(names)} (from this terminal; values not shown) to {path}")
    if existing:
        out(f"  keeping from the file: {', '.join(k for k in existing if k not in names) or 'nothing else'}")
    out("  readable only by you (permissions 600)")
    try:
        if ask("Write it? [y/N] ").strip().lower() not in ("y", "yes"):
            out("Nothing was written.")
            return 0
    except EOFError:
        out("Nothing was written.")
        return 0
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 600 from the first byte
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("# API keys for the 0x41 suite's MCP servers. Only you can read this file.\n")
        for name, value in keys.items():
            f.write(f"{name}={value}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    out(f"Wrote {path}. Fully quit and reopen the Claude app so the server loads it.")
    return 0


def main(argv=None) -> int:
    return write_from_env()


if __name__ == "__main__":
    sys.exit(main())
