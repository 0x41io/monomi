"""
Where Monomi's own files are, and where it keeps its data.

These are two different questions, kept apart on purpose:

- The repo folder (code): requirements.txt and the mcp_server.py wrapper that
  the Claude app starts. These only exist when Monomi runs from a copy of the
  repo (`python monomi.py`, or `pip install -e .`).
- The data folder: scans/, reports/ and cache/. Chosen by data_home():
    1. the MONOMI_HOME environment variable, if it's set
    2. else the repo folder, when Monomi runs from one (same place as always)
    3. else ~/.monomi (a plain `pip install`, so nothing is ever written
       inside Python's own package folder)

Each module builds its folder constants from this once, when it's imported.
"""

import os
import tomllib

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(PACKAGE_DIR)  # the folder above monomi/
ENV_VAR = "MONOMI_HOME"


def running_from_repo(folder=REPO_DIR):
    """True if the folder above the monomi/ package is a copy of the Monomi repo.

    After a plain `pip install` the package sits in site-packages, where there's
    no pyproject.toml, so a leftover .git folder (or any other project's files)
    can't make Monomi think it's in the repo. The name is checked too, so some
    other project's pyproject.toml doesn't count.
    """
    try:
        with open(os.path.join(folder, "pyproject.toml"), "rb") as f:
            return tomllib.load(f).get("project", {}).get("name") == "monomi"
    except (OSError, tomllib.TOMLDecodeError):
        return False


def where_data_lives():
    """(data folder, why that one). doctor shows both."""
    chosen = os.environ.get(ENV_VAR, "").strip()
    if chosen:
        return os.path.abspath(os.path.expanduser(chosen)), f"{ENV_VAR} is set"
    if running_from_repo():
        return REPO_DIR, "running from the Monomi repo folder"
    return os.path.join(os.path.expanduser("~"), ".monomi"), "installed package, no repo folder"


def data_home():
    """The folder that holds scans/, reports/ and cache/."""
    return where_data_lives()[0]


def data_dir(*parts):
    """A path inside the data folder, e.g. data_dir("scans", "mcp")."""
    return os.path.join(data_home(), *parts)
