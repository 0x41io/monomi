"""Load subfinder's output as an extra source of hostnames.

subfinder (ProjectDiscovery) asks dozens of passive sources for subdomains.
Monomi doesn't run it: you run subfinder yourself and pass its output file,
so Monomi stays passive and has nothing extra to install. Every host still
goes through Monomi's own checks (DNS, the validation gate).

Formats read, one host per line:
  plain text   a.example.com                       (subfinder -o FILE)
  JSON lines   {"host": "a.example.com", "source": "crtsh", ...}   (-oJ)
               with "sources": [...] instead when run with -cs
  host,ip      a.example.com,192.0.2.1             (-oI); the IP is ignored:
               Monomi looks hosts up itself
"""

import json
import os
from datetime import datetime, timezone

from monomi.common import is_hostname

MAX_HOSTS = 5000  # a wide subfinder run can list tens of thousands
MAX_BYTES = 50 * 1024 * 1024  # don't read a huge or wrong file into memory


def _from_line(line: str) -> tuple[str | None, list[str]]:
    """(hostname, the subfinder sources that found it) from one line, or (None, [])."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None, []
    if line.startswith("{"):
        try:
            data = json.loads(line)
        except ValueError:
            return None, []
        if not isinstance(data, dict) or not isinstance(data.get("host"), str):
            return None, []
        found = data.get("sources", data.get("source"))
        if isinstance(found, str):
            found = [found]
        if not isinstance(found, list):
            found = []
        return data["host"], sorted({s for s in found if isinstance(s, str) and s})
    return line.split(",")[0], []


def load(path: str, domain: str) -> dict:
    """Read a subfinder output file. Only the target domain and its subdomains are kept.

    Returns {"hosts": {host: [subfinder sources]}, "skipped": [reasons],
    "file_time": when the file was last written (UTC), i.e. when subfinder ran}.
    Raises OSError if the file can't be read, ValueError if it's too big.
    """
    size = os.path.getsize(path)
    if size > MAX_BYTES:
        raise ValueError(f"the file is {size // (1024 * 1024)} MB; subfinder output over "
                         f"{MAX_BYTES // (1024 * 1024)} MB isn't read")
    file_time = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat(timespec="seconds")
    hosts, not_hostname, other_domain = {}, 0, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            name, found = _from_line(line)
            if name is None:
                if line.strip() and not line.strip().startswith("#"):
                    not_hostname += 1
                continue
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]  # a wildcard entry stands for the name it covers
            if not is_hostname(name):
                not_hostname += 1
            elif name != domain and not name.endswith("." + domain):
                other_domain += 1  # e.g. a run over several domains (-dL)
            else:
                hosts.setdefault(name, set()).update(found)
    skipped = []
    if other_domain:
        skipped.append(f"{other_domain} hostname{'s' if other_domain != 1 else ''} not part of {domain}")
    if not_hostname:
        skipped.append(f"{not_hostname} line{'s' if not_hostname != 1 else ''} that aren't hostnames")
    names = sorted(hosts)
    if len(names) > MAX_HOSTS:
        skipped.append(f"{len(names) - MAX_HOSTS} more hostnames: over the {MAX_HOSTS} limit")
        names = names[:MAX_HOSTS]
    return {"hosts": {h: sorted(hosts[h]) for h in names}, "skipped": skipped, "file_time": file_time}


def to_source(loaded: dict, path: str) -> dict:
    """The import as a Monomi source record, like the ones collectors return.

    collected_at is when subfinder wrote the file, not now: the hostnames are
    as old as that run. imported_at marks it as another tool's data.
    """
    return {
        "source": "subfinder",
        "file": path,
        "collected_at": loaded["file_time"],
        "imported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subdomain_count": len(loaded["hosts"]),
        "subdomains": sorted(loaded["hosts"]),
        "found_by": loaded["hosts"],  # host -> subfinder's own sources (empty for plain text)
        "skipped": loaded["skipped"],
    }
