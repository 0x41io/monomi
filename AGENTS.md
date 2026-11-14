# AGENTS.md: how we work on Monomi

Read this before changing anything. It applies to every AI agent working on
this repo (Claude, Grok, or anyone else). Roi (øk) owns 0x41 and makes the
final call on every change.

## What Monomi is

Passive, AI-explained external recon: "know your exposure, explained."
Brand promise: **Monomi proves what it finds and never invents a finding.**

- Facts, severity, classification and attack-path chaining come from
  deterministic code. The LLM only narrates. The same scan gives the same
  findings every run, on every model.
- Passive by default. Nothing contacts a target unless the user asked for it
  (`--fingerprint` and `--exposed-files` are the only active checks, gated by
  `--allow-active` and an approved scope over MCP). Suggestions never run anything.
- Whether something is an attack path, a lead or set aside is decided in one
  place: `gate.py`. Path rules build candidates and say what they rest on; they
  never decide the tier themselves. A new check goes into the gate's checklist
  with a test that removes it and shows the result change.
- Data controlled by the target (DNS TXT, titles, cert names, archives) is
  untrusted evidence in AI prompts, never instructions.
- Honest status words over comforting ones. Never hide a failure: report it
  (a gap, a "behind", an error), and in the MCP server write diagnostics to
  stderr, since stdout carries the protocol.
- Keep the Anthropic SDK behind the one synthesis seam. Don't scatter it.
- Must run on Linux, macOS, WSL and native Windows. No Linux-only modules
  without a Windows path (the v1.9.1 `fcntl` crash).

## Code layout (since v1.14.1)

- All code lives in the `monomi/` package. A new module goes in `monomi/`
  (or `monomi/collectors/`, `monomi/importers/`), never at the repo root.
- Imports between Monomi's own files are absolute: `from monomi import scope`,
  `from monomi.ui import warn`. Never a bare `import scope`: installed, that
  would be a loose top-level module (tests/test_package.py catches it).
- The CLI is `monomi/cli.py`. The root `monomi.py` and `mcp_server.py` are
  wrappers that only call `main()`. Keep them that way, with no logic, since
  existing commands and MCP configs point at them.
- Data folders (`scans/`, `reports/`, `cache/`) come from
  `home.data_dir(...)`. Never build a path from `__file__` anywhere else.
  Code files (`requirements.txt`, the wrapper the MCP config starts) come from
  `home.REPO_DIR` and only exist when running from a copy of the repo.
- Install for development with `pip install -e .` (editable).

## Before you write code

1. **Check with Roi before any change of direction**: anything beyond what
   was agreed, new features, renamed outputs, or a different design.
2. **Think about how the output is used, not only whether it works.** MCP
   tools are stateless: each call sees only its own results, never what the
   agent ran before. An agent calls them in chains, so anything that looks
   across calls (suggestions, counts, "already done") must be designed for
   that.
3. Read the existing pattern in the file you're touching and follow it
   (for MCP tools: `finish()`, summary + full, `full_results_file`).

## Branches, tags, releases

- Work on a branch, never directly on `main`. Name the branch differently
  from the tag it will get (e.g. branch `v1.10.2-fix`, tag `v1.10.2`), since
  the same name for both causes "src refspec matches more than one".
- **Nothing is merged into `main` or tagged until Claude has reviewed it.**
  If the review can't happen tonight, the work waits on the branch.

## Release checklist (every release, no exceptions)

- [ ] `VERSION` in `monomi/common.py` bumped
- [ ] README roadmap: release added under done **and** removed from "Next"
- [ ] Tests for every tool or function touched (behavior, not key presence)
- [ ] Full test suite passes: `source venv/bin/activate && pytest -q`
- [ ] PEP 8 clean on changed files: `pycodestyle <files>` (two blank lines
      between top-level functions, one before nested defs, import groups)
- [ ] `git diff --check` shows no trailing whitespace
- [ ] Live check on the lab (41xlab): CLI run without `--ai` (free); MCP run
      after restarting the Claude app if MCP code changed
- [ ] Claude review passed, then merge to `main`, tag, GitHub release notes
- [ ] Credit community feedback in release notes when an idea came from it

## Handing code to Roi

Roi is learning as he goes and types or applies every change himself.

- Explain in depth what each piece of code does and why.
- Say exactly where every piece goes: which file and where in it. His
  keyboard has no Home or End key.
- Preferred: patch files made with `git format-patch -M` (renames kept),
  saved to Downloads and applied with `git am` from
  `/mnt/c/Users/17203/Downloads` (makes the commit with its message;
  `git am --abort` undoes a failed one), then `pytest`. Test-apply each
  patch on a clean copy first and check the tree matches the tested copy.
- If pasting instead: heredocs at the bash prompt (never inside nano),
  each paste under ~4 KB, never three backticks in a row, and no real
  domain names in pasted code (his chat app turns them into links). Build
  test domains from pieces or use dotless / `.test` / `.invalid` names.
- Paste a step that can fail on its own, since bash runs the next line anyway.

## Dependabot

For each PR: `gh pr diff`, compare to what's installed, run tests, then
merge. Several PRs touching one file are cleaner applied by hand in one commit.

## Lessons from past reviews

- v1.10.1: suggestions re-proposed checks that had already run, because
  each MCP tool only sees its own results. The version bump and README
  line were also missed, errors were silently swallowed, and the release
  was tagged before review. Every item above exists to prevent that.
  Fixed in v1.10.2: each tool suggests only what its own results back up,
  and the agent passes `already_ran` (the server can't remember a session).
