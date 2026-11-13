"""
The validation gate: one fixed checklist every attack path must pass
before Monomi calls it a finding.

The rules in paths.py don't decide whether what they built is an attack
path or only a lead. Each rule builds a candidate and says what it rests
on (its "gate input"). The gate runs every candidate through the same
checks, in the same order, and decides:

  finding  passes every check: an attack path (P1, P2...)
  lead     fails a check: something to investigate (L1, L2...), with the
           failed check's reason as its "missing" line

Deterministic code only: the AI narrates the result, it never decides a check.
"""


def way_in(candidate: dict, results: dict) -> str | None:
    """Check 5, observed way in: the path's door is an observed fact (a risky
    open service, a matched CVE, a claimable dangling CNAME, a DMARC record).
    Returns why it fails, or None when it passes."""
    gate_input = candidate["gate_input"]
    if gate_input["door"]:
        return None
    return gate_input["no_door"]


# (number, name, check), run in this order. Numbers match the design in
# issue #15, so a failed check reads the same in every output.
CHECKS = [
    (5, "observed way in", way_in),
]


def failed_checks(candidate: dict, results: dict) -> list[dict]:
    """Every check this candidate fails, in order, each with its reason."""
    failed = []
    for number, name, check in CHECKS:
        why = check(candidate, results)
        if why is not None:
            failed.append({"check": number, "name": name, "why": why})
    return failed


def review(candidates: list[dict], results: dict) -> tuple[list[dict], list[dict]]:
    """Split candidates into (attack paths, leads), each in the order given.

    A lead's "missing" line is the reason of the first check it failed.
    The gate input is only for the gate, so it never leaves this function.
    """
    paths, leads = [], []
    for candidate in candidates:
        failed = failed_checks(candidate, results)
        out = {k: v for k, v in candidate.items() if k != "gate_input"}
        if failed:
            out["missing"] = failed[0]["why"]
            leads.append(out)
        else:
            paths.append(out)
    return paths, leads
