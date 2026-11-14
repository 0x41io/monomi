"""
crt.sh database collector (third source, backup for the crt.sh website).

Besides its website, crt.sh runs a public, read-only PostgreSQL database
(user "guest", no password) with the same Certificate Transparency data.
The website is often overloaded (502s, timeouts) while the database still
answers, so this gets crt.sh's full history without depending on the web
front end. Still 100% passive: we only ask crt.sh, never the target itself.
"""

import socket
import time

import psycopg

from monomi.common import now_utc, subdomains_in, wildcards_in
from monomi.ui import warn

DB = {"host": "crt.sh", "port": 5432, "dbname": "certwatch", "user": "guest"}
DEFAULT_BUDGET = 120  # seconds across all tries; the MCP server passes a shorter one
MAX_ROWS = 50000      # safety cap so a huge domain can't flood memory

QUERY = """
    SELECT DISTINCT certificate_id, lower(name_value)
    FROM certificate_and_identities
    WHERE plainto_tsquery('certwatch', %(domain)s) @@ identities(certificate)
      AND lower(name_value) LIKE %(pattern)s
    LIMIT %(limit)s
"""


def fetch_raw(domain: str, budget: float = DEFAULT_BUDGET, retries: int = 2) -> list[tuple]:
    """Ask the crt.sh database for (certificate_id, name) rows under *.domain.

    The database sometimes drops long queries, so we try again once.
    budget is the total number of seconds for all tries together.
    """
    params = {"domain": domain, "pattern": f"%.{domain}", "limit": MAX_ROWS}
    last_error = "time budget used up"
    deadline = time.monotonic() + budget
    tries = 0

    for attempt in range(1, retries + 1):
        remaining = deadline - time.monotonic()
        if remaining < 10:
            break  # too little time left for a useful try
        tries += 1
        try:
            # IPv4 only: crt.sh also has an IPv6 address, and networks without
            # an IPv6 route (like WSL) fail on it with "Network is unreachable"
            ipv4 = socket.gethostbyname(DB["host"])
            with psycopg.connect(**DB, hostaddr=ipv4, connect_timeout=10, autocommit=True) as conn:
                # Time left AFTER connecting (that can take up to 10s); never 0, which means no limit
                remaining = deadline - time.monotonic()
                conn.execute(f"SET statement_timeout = {max(1000, int(remaining * 1000))}")
                return conn.execute(QUERY, params).fetchall()
        except psycopg.Error as e:
            last_error = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
        except OSError as e:
            last_error = f"couldn't look up {DB['host']}'s IPv4 address ({e})"
        if attempt < retries:
            warn(f"crt.sh database attempt {attempt} failed ({last_error}), retrying...")

    raise RuntimeError(f"crt.sh database gave up after {tries} tries ({budget:.0f}s budget): {last_error}")


def parse_subdomains(rows: list[tuple], domain: str) -> list[str]:
    """Turn raw (certificate_id, name) rows into a clean, sorted, de-duplicated list."""
    return subdomains_in((name for _, name in rows), domain)


def parse_wildcards(rows: list[tuple], domain: str) -> list[str]:
    """Pull the wildcard cert names (*.domain) out of the raw rows."""
    return wildcards_in((name for _, name in rows), domain)


def collect(domain: str, budget: float = DEFAULT_BUDGET) -> dict:
    """Run the collector and return a structured result for the report/AI layer."""
    rows = fetch_raw(domain, budget=budget)
    collected_at = now_utc()
    subdomains = parse_subdomains(rows, domain)
    wildcards = parse_wildcards(rows, domain)
    result = {
        "source": "crt.sh database",
        "collected_at": collected_at,
        "domain": domain,
        "certificates_seen": len({cert_id for cert_id, _ in rows}),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "wildcards": wildcards,
    }
    if len(rows) >= MAX_ROWS:
        result["partial"] = f"stopped at the {MAX_ROWS}-row cap"  # there may be more
    return result
