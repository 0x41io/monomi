"""
Email spoofing check: can someone send email pretending to be this domain?

Looks up the domain's SPF, DMARC and DKIM records. These are normal DNS
lookups (asked of DNS servers, not the target's own servers), so nothing
is sent to the target directly.

If the system's DNS can't answer (WSL's DNS relay often times out on TXT
lookups), it retries with public DNS: Cloudflare, then Google.
"""

from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]


class DNSLookupError(Exception):
    """No DNS server answered at all (different from 'no record exists')."""


def _query_txt(resolver, name: str) -> list[str]:
    """Ask one resolver for a name's TXT records. Raises on any DNS problem."""
    answers = resolver.resolve(name, "TXT", lifetime=5)
    records = []
    for rdata in answers:
        # One TXT record can be split into 255-byte chunks; join them back up.
        records.append(b"".join(rdata.strings).decode(errors="replace"))
    return records


def get_txt(name: str) -> list[str]:
    """All TXT records for a DNS name, as plain strings.

    [] means DNS answered and there are no TXT records.
    Raises DNSLookupError if no DNS server would answer at all.
    """
    system = dns.resolver.Resolver()
    public = dns.resolver.Resolver(configure=False)
    public.nameservers = FALLBACK_NAMESERVERS

    for resolver in (system, public):
        try:
            return _query_txt(resolver, name)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []  # DNS answered: there's just no TXT record here
        except dns.exception.DNSException:
            continue  # this resolver failed (timeout etc.), try the next one

    raise DNSLookupError(f"no DNS server answered a TXT lookup for {name}")


# Every way an SPF record can end, telling receivers what to do with
# mail from servers that AREN'T on its list.
ALL_RULES = ("all", "+all", "-all", "~all", "?all")


def find_spf(records: list[str]) -> list[str]:
    """Pick out the SPF records (the ones starting with 'v=spf1')."""
    spf = []
    for record in records:
        lowered = record.lower()
        if lowered == "v=spf1" or lowered.startswith("v=spf1 "):
            spf.append(record)
    return spf


def check_spf(records: list[str]) -> dict:
    """Judge a domain's SPF setup from its TXT records.

    Returns {"record": the SPF text (or None), "issues": [...]}.
    Each issue: {"problem", "detail"}. No issues = SPF looks strong.
    """
    spf = find_spf(records)
    issues = []

    def flag(problem, detail):
        issues.append({"problem": problem, "detail": detail})

    # 1. No SPF at all: nothing says which servers may send as this domain
    if not spf:
        flag("missing", "no SPF record, so nothing says which servers may send mail for this domain")
        return {"record": None, "issues": issues}

    # 2. More than one SPF record is an error (RFC 7208), so SPF breaks completely
    if len(spf) > 1:
        flag("multiple", f"{len(spf)} SPF records found; receivers treat this as an error and SPF fails")
        return {"record": " | ".join(spf), "issues": issues}

    record = spf[0]
    terms = record.lower().split()[1:]  # every part after 'v=spf1'

    # 3. The 'all' rule: what happens to mail from servers NOT on the list
    all_terms = [t for t in terms if t in ALL_RULES]
    if not all_terms:
        # 'redirect=' hands the whole policy to another domain, so no 'all' is fine
        if not any(t.startswith("redirect=") for t in terms):
            flag("no-all", "no 'all' rule, so mail from unlisted servers isn't failed")
    else:
        rule = all_terms[-1]
        if rule in ("all", "+all"):
            flag("too-open", f"'{rule}' allows ANY server to send mail as this domain")
        elif rule == "?all":
            flag("neutral", "'?all' takes no stance on unlisted servers, so it gives no protection")
        elif rule == "~all":
            flag("softfail", "'~all' only marks spoofed mail as suspicious; it's blocked only if DMARC enforces")
        # '-all' is the strong setting: nothing to flag

    return {"record": record, "issues": issues}

# The only valid DMARC policies, weakest to strongest.
VALID_POLICIES = ("none", "quarantine", "reject")


def parse_tags(record: str) -> dict:
    """'v=DMARC1; p=reject; pct=100' -> {"v": "dmarc1", "p": "reject", "pct": "100"}"""
    tags = {}
    for part in record.split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            tags[name.strip().lower()] = value.strip().lower()
    return tags


def find_dmarc(records: list[str]) -> list[str]:
    """Pick out the DMARC records (the ones whose first tag is 'v=DMARC1')."""
    dmarc = []
    for record in records:
        first = record.split(";")[0].replace(" ", "").lower()
        if first == "v=dmarc1":
            dmarc.append(record)
    return dmarc


def check_dmarc(records: list[str]) -> dict:
    """Judge a domain's DMARC setup from the TXT records at _dmarc.<domain>.

    Returns {"record": the DMARC text (or None), "policy": p= value (or None),
    "issues": [...]}. No issues = DMARC is enforcing.
    """
    dmarc = find_dmarc(records)
    issues = []

    def flag(problem, detail):
        issues.append({"problem": problem, "detail": detail})

    # 1. No DMARC at all
    if not dmarc:
        flag("missing", "no DMARC record, so receivers get no instructions for mail that fails SPF/DKIM")
        return {"record": None, "policy": None, "issues": issues}

    # 2. More than one DMARC record: receivers ignore DMARC entirely
    if len(dmarc) > 1:
        flag("multiple", f"{len(dmarc)} DMARC records found; receivers ignore DMARC when there's more than one")
        return {"record": " | ".join(dmarc), "policy": None, "issues": issues}

    record = dmarc[0]
    tags = parse_tags(record)
    policy = tags.get("p")

    # 3. The policy: what receivers should do with mail that fails
    if policy is None:
        flag("no-policy", "no p= policy tag, so receivers may ignore the record")
    elif policy not in VALID_POLICIES:
        flag("invalid-policy", f"p={policy} isn't a real policy (none/quarantine/reject)")
    elif policy == "none":
        flag("monitor-only", "p=none only collects reports; spoofed mail is still delivered")
    else:
        # 4. Enforcing, but maybe only for some of the mail
        pct = tags.get("pct", "100")
        if pct != "100":
            flag("partial", f"pct={pct}, so the policy only applies to {pct}% of failing mail")

    return {"record": record, "policy": policy, "issues": issues}


# Common DKIM selectors used by big email providers. DKIM keys live at
# <selector>._domainkey.<domain>, and DNS can't list them, so we can only
# try names we know are commonly used.
COMMON_SELECTORS = [
    "google",                   # Google Workspace
    "selector1", "selector2",   # Microsoft 365
    "k1", "k2",                 # Mailchimp
    "s1", "s2",                 # SendGrid
    "cf2024-1",                 # Cloudflare Email Routing
    "default", "dkim", "mail",  # common generic names
]


def _has_dkim_key(domain: str, selector: str) -> bool:
    """True if this selector has a real DKIM key (an empty p= means revoked)."""
    for record in get_txt(f"{selector}._domainkey.{domain}"):
        if parse_tags(record).get("p"):
            return True
    return False


def check_dkim(domain: str, selectors: list[str] = COMMON_SELECTORS) -> dict:
    """Look for DKIM keys under common selector names, all in parallel.

    Returns {"record": found selectors as text (or None), "selectors": [...],
    "issues": [...]}. Not finding one is a lead, not proof: the domain may
    use a selector name we didn't try.
    """
    with ThreadPoolExecutor(max_workers=len(selectors)) as pool:
        results = list(pool.map(lambda s: _has_dkim_key(domain, s), selectors))

    found = [s for s, has_key in zip(selectors, results) if has_key]

    issues = []
    if not found:
        issues.append({
            "problem": "not-confirmed",
            "detail": f"no DKIM key under {len(selectors)} common selectors; "
                      "it may use a custom one, so this is a lead, not proof",
        })

    return {"record": ", ".join(found) if found else None,
            "selectors": found, "issues": issues}


# What each enforcing DMARC policy tells receivers to do with failing mail.
ACTIONS = {
    "reject": "bounce failing mail",
    "quarantine": "send failing mail to spam",
}


def email_verdict(spf: dict, dmarc: dict, dkim: dict) -> dict:
    """Combine SPF, DMARC and DKIM into one answer: can this domain be spoofed?

    DMARC decides: it's the rule that tells receivers what to do when mail
    fails SPF/DKIM. Returns {"verdict": "protected" | "partial" | "spoofable",
    "summary": one plain-English sentence, "notes": [extra context]}.
    """
    spf_problems = {i["problem"] for i in spf["issues"]}
    dmarc_problems = {i["problem"] for i in dmarc["issues"]}
    policy = dmarc["policy"]
    enforcing = policy in ACTIONS
    notes = []

    if enforcing and "partial" not in dmarc_problems:
        verdict = "protected"
        summary = f"DMARC p={policy} tells receivers to {ACTIONS[policy]}, so spoofed mail is stopped"
        if "softfail" in spf_problems:
            notes.append("SPF's ~all softfail is fine here: DMARC blocks what SPF only marks as suspicious")
    elif enforcing:
        verdict = "partial"
        summary = "DMARC enforces, but only on some failing mail (pct under 100), so some spoofed mail gets through"
    else:
        verdict = "spoofable"
        summary = "DMARC doesn't enforce, so mail pretending to be this domain can still reach inboxes"
        if spf["record"] and not spf_problems:
            notes.append("SPF -all helps, but without DMARC the From address people see can still be faked")

    if enforcing and spf["record"] is None and not dkim["selectors"]:
        notes.append("no SPF and no DKIM found, so this domain's own real mail may get rejected too")

    return {"verdict": verdict, "summary": summary, "notes": notes}


def check_email(domain: str) -> dict:
    """Run the whole email check for one domain: SPF, DMARC, DKIM and the verdict.

    Raises DNSLookupError if DNS can't be reached at all.
    """
    spf = check_spf(get_txt(domain))
    dmarc = check_dmarc(get_txt(f"_dmarc.{domain}"))
    dkim = check_dkim(domain)
    return {"spf": spf, "dmarc": dmarc, "dkim": dkim,
            "verdict": email_verdict(spf, dmarc, dkim)}


if __name__ == "__main__":
    import sys

    try:
        report = check_email(sys.argv[1])
    except DNSLookupError as e:
        print(f"error: {e}")
        sys.exit(1)

    for label, key in (("SPF", "spf"), ("DMARC", "dmarc"), ("DKIM", "dkim")):
        result = report[key]
        print(f"{label} record: {result['record']}")
        if not result["issues"]:
            print(f"  {label} looks strong")
        for issue in result["issues"]:
            print(f"  {issue['problem']}: {issue['detail']}")

    verdict = report["verdict"]
    print(f"\nVERDICT: {verdict['verdict'].upper()}")
    print(f"  {verdict['summary']}")
    for note in verdict["notes"]:
        print(f"  note: {note}")
