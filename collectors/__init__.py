VERSION = "0.7"
USER_AGENT = f"0x41-monomi/{VERSION} (passive OSINT research)"

import re

# Real hostnames only use letters, digits, dots, hyphens (and sometimes underscores).
# Certificates can contain any text, so anything else is dropped: it protects the
# terminal (escape codes), the AI prompt, and file names from junk or tricks.
_HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$")


def is_hostname(name: str) -> bool:
    return len(name) <= 253 and bool(_HOSTNAME_RE.match(name))
