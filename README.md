<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/0x41io/monomi/main/assets/monomi-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/0x41io/monomi/main/assets/monomi-light.png">
    <img src="https://raw.githubusercontent.com/0x41io/monomi/main/assets/monomi-banner.png" alt="mønømi by 0x41" width="420">
  </picture>
</p>

**mønømi: passive attack surface recon and IP threat-intel, with AI-written analysis and an MCP server, by 0x41.**

Most recon tools hand you a raw list of hostnames. Monomi collects a domain's public footprint and then has Claude explain it in plain English: how the infrastructure is organized, what deserves a closer look, how an attacker would most likely get in, and who should fix what first.

> ⚠️ **Authorized use only.** By default Monomi is fully passive: it reads public Certificate Transparency logs and never sends traffic to the target. The optional `--enrich`, `--email` and `--takeover` steps add standard DNS lookups. Four optional checks are **active** — they contact the target's own servers: `--fingerprint` (one homepage request per host), `--probe` (the homepage plus one request per redirect, to see where it really lands), `--exposed-files` (a few requests per host to find public API specs and source maps) and `--content` (content discovery: about 160 requests per host). All four send an honest active User-Agent and only run when you ask for them, and `--scope FILE` limits them to the hosts you're allowed to test (over MCP each one needs your approval in a terminal, with a scope file). Only assess domains you own or have permission to review.
---

## Features
- **Subdomain discovery** from four sources, asked in parallel:
  - [crt.sh](https://crt.sh) website (broadest coverage, includes expired certificates)
  - crt.sh's public certificate database (same data as the website, queried directly over PostgreSQL; often answers when the website is slow or down)
  - [Cert Spotter](https://sslmate.com/certspotter/) (currently valid certificates, more reliable; waits and retries when rate-limited, and an outage only fails this source, never the scan)
  - [AlienVault OTX](https://otx.alienvault.com) passive DNS (hostnames DNS sensors have seen answer, including ones that never had a certificate). Works without a key, but keyless requests get rate-limited almost at once, so set a free key in `OTX_API_KEY` (see [OTX key](#otx-key-recommended))
- **subfinder import (`--subfinder FILE`):** add the hostnames from a [subfinder](https://github.com/projectdiscovery/subfinder) output file (plain, `-oJ` or `-oI`). Monomi never runs subfinder itself: run it, then pass the file. Only the target and its subdomains are kept, hosts get the same checks and validation gate as any other, facts say they were imported, and they stay out of scan history (they're only there on runs that pass the file). Over MCP, `find_subdomains` takes `subfinder_file` (a file inside Monomi's `scans/` folder)
- **BBOT import (`--bbot FILE`, v1.29):** add the in-scope hostnames from a [BBOT](https://github.com/blacklanternsecurity/bbot) `output.json`. Monomi never runs or bundles BBOT: run it, then pass the file. A host is kept only if BBOT itself marked it in scope (scope distance 0, so a provider's nameservers BBOT found one hop out stay out) **and** it's the target or one of its subdomains; it then gets the same checks, scope rules and validation gate as any other, and stays out of scan history. Every other BBOT event type (open ports, technologies, findings, URLs) is counted and named, never imported: Monomi checks those itself, with evidence it can stand behind. Over MCP, `find_subdomains` takes `bbot_file` (a file inside Monomi's `scans/` folder)
- **Automatic fallback:** if a source is down, the scan continues with the others
- **Saved source copies:** every good answer from a source is saved per domain (`scans/<domain>/sources/`). If that source fails on a later run, Monomi uses the saved copy (up to 30 days old) and labels it `from_saved` with its original collection time, so an outage only costs fresh data, not the hosts found before
- **Shared pacing:** crt.sh (5 requests a minute) and Cert Spotter's free tier are paced across every run and domain, so multi-domain sweeps stay under their limits. After Cert Spotter rate-limits, it is skipped for the rest of the cooldown instead of failing on every domain
- **Honest source status:** when the crt.sh database answers with 0 certificates while another source found some, crt.sh is reported as **behind** (it can take days to index new certificates), not as failed. A source that stops early (Cert Spotter rate-limited after its first page, or a page or row cap reached) keeps what it got but is marked **partial**, and the scan says its list may be incomplete
- **History per source:** change detection keeps each source's list separately. A source that failed or was cut short keeps its hosts from the last scan, so it never makes hosts look **[GONE]**; a source that's new to a domain (OTX on its first run) starts from what it finds, so it never makes hosts look **[NEW]**. When a source that was cut short last time comes back complete, the hosts it adds are listed as **[FILL]** (may not be new), not [NEW]. Every scan is saved, and an incomplete one says which source and why
- **Merged, de-duplicated results**
- **Hosting enrichment (`--enrich`):** resolves each host to its IP and looks up the network owner (ASN), provider, and country via Team Cymru's free IP-to-ASN service. Shows a host table, a hosting breakdown chart, and flags hosts that point to private/internal IPs in public DNS. Hosts with no IPv4 address get a second DNS look that says why: **no_such_host** (the name doesn't exist, double-checked with two DNS-over-HTTPS servers, Cloudflare and Google), **dangling_cname** (a CNAME pointing to a deleted name), **ipv6_only**, **no_address** (the name exists but has no address, often a retired host), **conflicting** (system DNS and DNS-over-HTTPS disagree, so it's unknown), **servfail** (the DNS servers tried but couldn't get an answer, even after a retry: often a broken zone or a rate limit) or **lookup_failed**. Every check uses the same DNS helper and the same status words. **Wildcards (v1.18):** a zone with a wildcard record (`*.example.com`) answers for any name, so junk names from passive DNS look live. Monomi asks DNS about 3 made-up names in each zone a host sits in; where they resolve, hosts whose answer matches the wildcard (the same CNAME end, or IPs from its pool) are set aside: one line per wildcard with a few example names, the full list in `--json` (`wildcard_only`), and left out of every count, check and attack path, since DNS can't tell them apart from names nobody set up. A CDN wildcard answers in every subzone, so zones with the same answer print as one block (biggest zones first), and set-aside names that a certificate names exactly (crt.sh, Cert Spotter) are listed on their own line as likely real (`with_certificate` in `--json`). A resolver that answers for names that don't exist (some ISPs and VPNs) is caught first, and then the check is skipped with a note
- **Open ports and CVEs (`--ports`):** looks up each IP in [Shodan InternetDB](https://internetdb.shodan.io/) (free, no key, passive: Shodan's existing data, no traffic to the target). Flags risky internet-facing services (RDP, SMB, databases, Docker API), counts known CVEs, and separates shared CDN edge IPs (Cloudflare, Fastly, Akamai, Imperva, Vercel, and AWS CloudFront, detected from [Amazon's published IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)) so their ports aren't blamed on the target. Edge IPs are also caught from Shodan's service fingerprints (CPEs), which finds Cloudflare and Okta on IP ranges they don't own, and each one says why it was flagged (`edge_reason`). A hostname whose CNAME points to an edge service (CloudFront, Okta, Fastly, Akamai, Cloudflare, Imperva, Azure Front Door, Vercel) also marks its IPs as edge. Only IPs that matter get a row
- **Hand-off to [kaidøku](https://github.com/0x41io/kaidoku) (`--cves FILE`):** saves every CVE found, ready for `python kaidoku.py --file FILE`
- **Web tech + security headers (`--fingerprint`, active):** one homepage request per live host reads headers like Server and X-Powered-By to spot web servers, frameworks and exposed versions, and checks the same response for missing or weak security headers (HSTS, CSP, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy). Hosts that redirect aren't judged, and the header check makes no extra requests. If HTTPS fails with a TLS error or is refused (not on a timeout), it retries once over plain HTTP and flags the broken HTTPS
- **Exposed API specs and source maps (`--exposed-files`, active):** for each live host, checks a short list of well-known paths for a public OpenAPI/Swagger spec, and reads the homepage's own scripts for JavaScript source maps (`.map`). GET requests only — never POSTs, never follows a spec to call the API. A file counts only when it really parses as what it claims to be, so a site that returns a page for every path isn't mistaken for a spec. Reports a spec's endpoint count, any internal server names it lists and whether it declares auth; for a source map, how many source files it names and whether the original code is embedded (`sourcesContent`) — the code itself is never saved or shown. At most 13 requests per host
- **Live pages (`--probe`, active):** loads each live host's homepage the way a browser does and follows its redirects (up to 5), so you see where it really lands (to `www`, a login page, another site) and the page's title. A redirect is where the target picks the next address, so each one is checked before anything is sent: http(s) on port 80 or 443 only, a URL that names one clear host, in your scope, and never a private or local address (an IP like `127.0.0.1` or `169.254.169.254`, or a name that resolves to one). A refused redirect is reported with its reason, never followed. At most 12 requests and 60 seconds per host, enforced in code. The record says what the server claims the body is (`content_type`) and what it really looked like (`body_kind`: json, html, empty, other), so "no title" always comes with its reason. Only HTML-labeled pages are read, at most 64 KB. The first module of the app-mapper
- **Content discovery (`--content`, active, v1.26):** tries a fixed list of 155 paths on each live host: exposed version control (`.git`, `.svn`, `.hg`), environment and config files (`.env`, `wp-config.php` backups, `web.config`), keys and credential files, backups and database dumps (including ones named after the host), debug and status pages (phpinfo, Apache server-status, Spring Boot `/env` and heap dumps, Go pprof), and 40 admin or internal paths. What sets it apart from a status-code scanner: each file path knows what the real thing looks like, so `/.git/HEAD` counts only if it reads like a Git HEAD and `/backup.zip` only if it starts like a zip. A 200 error page is never a finding. Three made-up paths first show what each host's "not found" looks like: an admin path that answers the same way is dropped, and if a made-up path passes a file check (a site that serves a zip for every URL), that check isn't trusted on that host. Results are **found** (the content is the real thing, with a severity: `secrets`, `source` or `info`) or **lead** (a path that answered unlike a made-up one: worth a look, never a claimed flaw). Since v1.27 the files found on each host become one attack path (rule `exposed_file`), which Akashi can re-check. Findings say what a file is ("an environment file with 12 settings, 3 named like secrets"), never what it holds: no values, keys or code are kept. GET only, no redirect is ever followed (where it points is recorded, without its query, which can carry tokens), never another host, at most 16 KB read per answer and 159 requests per host, enforced in code. A server that sends its body a byte at a time can't stretch a request past its deadline: the body is read a few bytes at a time against the clock. A not-found page that echoes the path back can't make a file check pass, and an `.env.example` is reported as a template, not as secrets. `--wordlist FILE` adds your own paths (one per line, SecLists style), as leads only; a line that isn't a plain path (`..`, a query, `://`, a backslash or an encoded dot or slash) stops the run before anything is sent
- **Email spoofing check (`--email`):** looks up the domain's SPF, DMARC and DKIM records (DNS lookups only, nothing sent to the target's servers) and gives one verdict: **protected**, **partial** or **spoofable**. DMARC decides the verdict, so an SPF `~all` softfail isn't flagged when DMARC enforces. DKIM is checked under common selector names, and a key that isn't found is reported as "not confirmed", never "missing". If the system's DNS can't answer (WSL's DNS relay often times out on TXT lookups), Monomi retries with public DNS (Cloudflare, then Google)
- **Subdomain takeover check (`--takeover`):** for every hostname, follows its CNAME and flags it if the target no longer exists (DNS lookups only). A dead target on a service that lets deleted names be claimed again (Azure App Service, Blob Storage, Traffic Manager, CDN and others, plus AWS Elastic Beanstalk) is a **takeover lead**; a dead target anywhere else is a **dangling CNAME** (worth checking, e.g. an expired domain someone could buy). A dead target on a service whose names can never be claimed again (AWS load balancers, CloudFront) is marked **stale**: an old DNS record worth cleaning up, not a takeover risk. A dead target inside the scanned domain itself is also **stale**, since only the domain's owner can create that name. **Lame delegations (v1.17):** a subzone whose NS records point at nameservers that refuse to answer for it (the zone was deleted where it was hosted, but the delegation was left behind) is reported once per delegated zone, with the hosts under it and the nameservers that refused. On a pooled DNS service (AWS Route 53) getting that exact nameserver set again is impractical, so it's graded **theoretical**; on nameservers Monomi doesn't recognize it's graded **investigate**. Told apart from an ordinary SERVFAIL only by what the DNS-over-HTTPS servers say about why. Monomi never tries to claim anything, so leads stay leads
- **IP threat-intel (`--investigate-ip`):** look into suspicious IPs from logs or alerts (up to 20 per run): is each one a Tor exit, VPN/proxy, hosting/cloud server or CDN edge? Checks the Tor Project's exit list, the network owner (ASN) via Team Cymru, reverse DNS and Shodan InternetDB, then Monomi's rules put labels on each IP, and every label names its source and reason. CVEs Shodan saw on a CDN edge IP come with a note that they most likely belong to another site behind it. Passive: asks public sources about the IP and never contacts the IP itself. Private and junk input is rejected with a reason. With `--ai`, Claude writes a verdict with a confidence level based on how many sources agree, cites the evidence, and never claims where a person is or who they are: a country is where the network is registered, not where its user is
- **SpiderFoot import (`--import FILE`):** run Monomi on a [SpiderFoot](https://github.com/smicallef/spiderfoot) CSV export instead of querying certificate logs. Keeps the target's own hosts (with IPs, banners, ASNs; `--enrich` looks up current IPs fresh instead), separates third-party services, drops noisy modules (username/account checks, co-hosted sites, raw data), and passes SpiderFoot's flagged findings to the AI with their source module so weak reputation hits aren't reported as confirmed threats. Works with `--enrich`, `--ports` and `--ai`; doesn't touch scan history
- **Change detection:** every scan is saved and compared with the last one, flagging new and removed hostnames
- **AI analysis (optional):** Claude groups hosts by purpose (and by hosting provider when `--enrich` is on), flags names worth reviewing (High / Medium / Low), suggests defensive steps, and states the limits of the data
- **Evidence-backed findings:** before the AI step, Monomi's code turns the collected data into a numbered evidence list (E1, E2, ...), each item a plain fact with its source and UTC collection time. Every finding in the AI report cites the evidence it rests on (e.g. `[E12, E194]`) and is labeled **Observed**, **Inference** or **Lead**. After the report is written, Monomi checks every citation and warns if the AI cited evidence that doesn't exist. Saved reports end with an **Evidence** section listing each cited item, written by code, not by the AI
- **Attack paths:** Monomi's code chains findings into the ways an attacker would most likely try to get in: a claimable subdomain takeover (made worse when the domain's email is spoofable), email impersonation, services that shouldn't face the internet, known-vulnerable versions, and non-production hosts sharing a server with production. Every step cites evidence and is labeled Observed / Inference / Lead by code, and a path is only as strong as its weakest step. The paths print at the end of every scan that ran a check, with no AI needed. With `--ai`, Claude writes them up in a report section of their own, but can't add, drop or reorder a path or change a label, and Monomi checks the report afterwards. If nothing chains, the answer is "no attack path found", never an invented one
- **Leads, kept apart from attack paths:** something that looks like a way in but is missing a piece is a lead (L1, L2...), not an attack path, and it says what's missing. A test host on the production server is a lead until a risky open service or a known CVE shows a way into that server. A software version with no matched CVE is a lead. "Go around the CDN" (some hosts behind a CDN, others pointing straight at a web server of the target's own) is always a lead, since a CDN hides its origin. Leads are listed after the attack paths, never count as one, and never appear in "fix this first"
- **Validation gate (v1.13):** before anything is called an attack path, code runs it through one fixed checklist, in the same order every time: (1) in scope (one of the scan's hosts or under the domain, and allowed by `--scope` when given), (2) the target's own (not a shared CDN edge, third-party hosting like a hosted store or forum, or a shared front door like AWS Global Accelerator), (3) seen this run (not a saved copy or an import), (4) confirmed twice (a "doesn't exist" was double-checked over DNS-over-HTTPS, not system DNS alone), (5) an observed way in, (6) claimable / reachable (a takeover target on a service known to let deleted names be claimed again; no private IPs). Out-of-scope hosts are left out of every rule's evidence before the checks run, so an excluded host can never hold up a path or lead about other hosts, and each output says how many were left out. Passing all six makes an attack path (`gate 6/6`); failing 3 to 6 makes a lead that names the failed check; failing 1 or 2 sets the item aside (out of scope, or not the target's own), listed with the reason and never treated as a path or lead. Email spoofing and a version with no matched CVE carry a note that bug bounty programs often exclude them. **Scope caution (v1.16):** anything that runs through a pre-release host (`alpha`, `beta`, `preview`, `experimental`, `canary`, `nightly`) or a non-production host (`dev`, `staging`, `stage`, `stg`, `test`, `testing`, `uat`, `qa`, `sandbox`, `nonprod`, `preprod`) gets a note naming those hosts, because programs often close them as Not Applicable or list them as out of scope; MCP `check_takeover` records get it too. Names match the same way as categories (`dev` matches `dev2` and `api-dev`, not `devices`), and only the labels in front of the target domain count. A note never changes the result: it's a reminder to check the program's rules, never a reason to drop a finding. Every output shows the gate: terminal, `--json`, Markdown and HTML exports, and the AI prompt (which must state it as given)
- **Owners and "fix this first":** every finding carries the roles that would fix it (DNS admin, email admin, web app team, CDN / proxy admin, server / infrastructure admin, cloud / service account owner), worked out by code and never naming people. Recommendations start with their owner, and the report leads with the one fix that closes the most attack paths. When a path needs several fixes (three test hosts on one server), it lists all of them ("Fix these 3 first ... together they close P1") and never says one of them closes it
- **Next checks:** every scan ends with the checks worth running next and the reason from that scan ("1 IP is a server of the target's own: `--ports` shows its open ports and known CVEs"). Suggestions only: nothing runs unless you add the flag, and `--fingerprint` is marked as active
- **Known hostnames (`--hosts FILE`):** check hostnames you already know alongside the ones from certificate logs, one per line. Only the target domain and its subdomains are kept, so a file can't point Monomi outside the scan, and the file's hosts stay out of scan history
- **Formatted terminal reports:** the AI report renders in the terminal with colored headings, real tables, and High / Medium / Low badges (via [rich](https://github.com/Textualize/rich); plain Markdown if rich isn't installed or `--no-color` is set)
- **Saved reports:** each AI analysis is written to `reports/<domain>_<timestamp>.md`
- **Report exports (`--export`):** the scan as Markdown, a self-contained HTML page and a findings CSV for ticketing, built by code with or without `--ai` (see [Exporting reports](#exporting-reports))
- **JSON export** for use in other tools
- **Setup check (`python monomi.py doctor`):** checks Python, packages, the API key, DNS and every data source in about 10 seconds, and gives a one-line fix for anything that's wrong (see [Check your setup](#check-your-setup))
- **One-command MCP setup (`python monomi.py mcp setup`):** adds Monomi to the Claude desktop app's config, or with `--client codex|opencode|hermes` to Codex CLI, OpenCode or Hermes Agent, changing only Monomi's entry, keeping the file's comments and layout, and backing up the old file first (see [MCP server mode](#mcp-server-mode))
- **MCP server mode:** run Monomi as an MCP server so AI agents can call its checks directly. Seven passive tools cover subdomain discovery with hostname categories, host enrichment, ports/CVEs, email spoofing, takeover checks, and suspicious-IP investigation; four active tools (`fingerprint_hosts`, `check_exposed_files`, `probe_hosts`, `discover_content`) send nothing until you approve each request in a terminal with your scope file (then `active_run` runs it once; `discover_content` runs as a background job you follow with `active_status`), and every request and refusal goes to an audit log. `find_subdomains` labels each hostname with a category (non-production, legacy, access, management, iot-ot, partner-portal, internal-tools and more), and `check_ports` starts with a summary: CDN edge vs origin IPs, CVEs and risky ports on origin IPs only, hostnames that don't resolve, and IPs Shodan has no data on. Findings carry their owners, and inputs that aren't hostnames (pasted links, URLs, wildcards) come back in `rejected` with the reason. Replies are short summaries by default, with the full result saved to a file, and tools pass hosts to each other as files instead of long hostname lists, so big scans don't fill the agent's context.

## Try it (field testers)

Monomi is being field-tested by bug bounty hunters who already run recon through an AI agent. If that's you, one pass takes about ten minutes:

1. **Install** (see [Installation](#installation)) and run `python monomi.py doctor`. Every line should be `[+]`, or a `[!]` warning with its fix.
2. **Run it passively on a program you're already in scope for.** Passive checks never contact the target's own servers: they read public sources and make DNS lookups.
   ```bash
   python monomi.py your-target.example --ports --email --takeover --json run.json
   ```
   Or over MCP: run `python monomi.py mcp setup`, restart your client, and give your agent the [Monomi skill](skills/monomi/SKILL.md).
3. **Leave the active checks off on a first run.** If you try them later, approve a scope file first and check what it refuses (see [Scope file](#mcp-server-mode)).
4. **Tell us what broke** with a [field test issue](https://github.com/0x41io/monomi/issues/new?template=field-test.md). The version is in the banner (`by Øx41 · v...`). Leave out secrets, tokens and anything outside the program's scope, and redact target names if the program doesn't allow disclosure.

## Installation

Requires Python 3.14+.

```bash
git clone https://github.com/0x41io/monomi.git
cd monomi
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e .                # installs the requirements and Monomi itself
python monomi.py doctor         # check the setup
python monomi.py mcp setup      # optional: add Monomi to the Claude app
```

### Installing on Windows

Monomi runs on Windows without WSL. In PowerShell:

```powershell
python --version                # must be 3.14 or newer
git clone https://github.com/0x41io/monomi.git
cd monomi
python -m venv venv
venv\Scripts\Activate.ps1
pip install -e .
python monomi.py doctor         # check the setup
python monomi.py mcp setup      # optional: add Monomi to the Claude app
```

If something goes wrong:
- **`python` isn't found, or opens the Microsoft Store:** install Python from python.org (tick **"Add python.exe to PATH"**). If `python` still opens the Store or runs an old version, open **Settings > Apps > Advanced app settings > App execution aliases**, turn off the "App Installer" and older Python entries for `python.exe` / `python3.exe`, and turn on the new ones. Then open a new PowerShell window.
- **"running scripts is disabled on this system"** when activating: run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate again.
- **The prompt shows `(venv)` but the command isn't found:** another venv is active. Run `deactivate`, then activate the one inside the `monomi` folder.

`pip install -e .` installs Monomi as the `monomi` package in editable mode: Python uses this folder's code directly, so a `git pull` takes effect right away. It also adds the commands `monomi` (the same as `python monomi.py`) and `monomi-mcp`, and `python -m monomi` works too. `pip install -r requirements.txt` still works if you only want `python monomi.py`.

### Where Monomi keeps its data

Scans, reports and the AWS range cache go in `scans/`, `reports/` and `cache/`:

1. inside the folder set in the `MONOMI_HOME` environment variable, if it's set
2. else in this repo folder, when Monomi runs from a copy of the repo (`python monomi.py`, or `pip install -e .`)
3. else in `~/.monomi` (a plain `pip install .`), so nothing is written inside Python's own package folder

`python monomi.py doctor` shows which folder is used and why. Over MCP, `hosts_file` only reads files inside that folder's `scans/`.

### Using Monomi from other tools

Monomi is one package, `monomi`, so other tools (like 0x41's Akashi) can import it:

```python
from monomi import emailauth, evidence, takeover
```

Install a released version straight from GitHub: `pip install "monomi @ git+https://github.com/0x41io/monomi@v1.21.0"`. It isn't on PyPI yet. The scan fields and functions other tools rely on are locked by `tests/test_contract.py`, and the approvals core the rest of the 0x41 suite builds on by `tests/test_approvalcore.py`.

**Reading a saved scan (`--json`, since v1.15.0).** The file starts with `"monomi_version"`. Compare it as numbers with `monomi.common.scan_version(results)` (as text, `"1.15.0"` sorts before `"1.9.0"`); it's `None` for scans saved before v1.15.0, which don't have the fields below. In `"paths"`, every item in `paths`, `leads` and `set_aside` has:

- `"rule"`: which rule built it, one of `takeover`, `takeover_unknown`, `email_spoofing`, `exposed_service`, `known_cves`, `version_check`, `side_door`, `around_cdn`, `dangling_ns` (v1.17). Names never change once released.
- `"targets"`: what it's about. Always `"hosts"` and `"ips"` (lists, maybe empty), so any item can be checked against a scope file the same way, plus keys for its rule:

| `rule` | extra `targets` keys |
|---|---|
| `takeover`, `takeover_unknown` | `cname`, `service` (null if unknown), `claimable`, `nxdomain_confirmed_by` (DoH servers that agreed; `[]` = system DNS only, null = not recorded) |
| `email_spoofing` | `verdict` |
| `exposed_service` | `services` (e.g. `5432/PostgreSQL`) |
| `known_cves` | `cves`, `versions` |
| `version_check` | `versions` (each `host`, `tech`, `version`) |
| `side_door` | `shared_with` (the production hosts on the same server) |
| `around_cdn` | `fronted` (every host behind the CDN; try a few, not all), `cdn` (null when hosts sit behind more than one); one lead per origin server, its IP in `ips` |
| `dangling_ns` | `cut` (the delegated zone), `ns_ips` (the nameservers that refused), `provider` (null if not recognized), `grade` (`theoretical` or `investigate`); the hosts under the cut in `hosts` |

Rely only on the keys listed for that rule. Build requests from `targets`, never from the `title` or step text, which can change between releases.

### API key (only for `--ai`)

The AI analysis uses the Claude API. Get a key at [console.anthropic.com](https://console.anthropic.com), then:

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

On Windows (PowerShell): `$env:ANTHROPIC_API_KEY = "your-key-here"` (for the current window only).

Never commit your key. The tool reads it from the environment only.

By default the tool uses the newest Claude Sonnet model available to your key. To choose a specific model:

```bash
export CLAUDE_MODEL="model-id-here"
```

### OTX key (recommended)

AlienVault OTX answers without a key, but keyless requests were rate-limited on the first try in testing. A free key raises the limit:

1. Make an account at [otx.alienvault.com](https://otx.alienvault.com)
2. Copy the **OTX Key** from Settings (API Integration)
3. `export OTX_API_KEY="your-otx-key"` (add it to `~/.bashrc` to keep it)

Without a key, scans still run on the other sources and say OTX was rate-limited. `python monomi.py doctor` shows whether a key is set (never the key itself).

### Check your setup

Run this after installing, and whenever a scan looks off:

```bash
python monomi.py doctor
```

It checks, in about 10 seconds:
- **Setup:** the Python version, every package in `requirements.txt` (installed and new enough), and that `scans/`, `reports/` and `cache/` can be written to (and which folder holds them, see [Where Monomi keeps its data](#where-monomi-keeps-its-data))
- **Claude API:** whether `ANTHROPIC_API_KEY` is set (only its first 7 characters are ever shown), whether the API accepts it (one free call that lists models, no tokens used), and which model `--ai` would use
- **DNS:** system DNS and public DNS on port 53, and DNS-over-HTTPS (Cloudflare and Google). A VPN's DNS can drop lookups under load, and doctor says so when port 53 fails
- **Sources:** crt.sh (website and database), Cert Spotter (how much of the free hourly quota is used, or when a cooldown ends), AlienVault OTX (and whether `OTX_API_KEY` is set), Shodan InternetDB, Amazon's IP range list and the Tor exit list
- **MCP:** whether the Claude desktop app's config has Monomi in it and points at this copy of Monomi (read-only; `python monomi.py mcp setup` fixes it), the API key file the server loads, approvals waiting for your yes, the last active request, the rate, and any v1.19 flags still in a config

```
Setup
  [+] Python 3.14.4
  [+] packages: requests, anthropic, rich, dnspython, mcp, psycopg
  [+] scans/, reports/, cache/ writable

Claude API
  [+] ANTHROPIC_API_KEY set (sk-ant-…, 106 chars)
  [+] key accepted · --ai would use claude-sonnet-5-5

DNS
  [+] system DNS (port 53) answered
  [+] public DNS on port 53 (1.1.1.1, 8.8.8.8) answered
  [+] DNS-over-HTTPS: Cloudflare, Google

Sources
  [!] crt.sh website: timed out after 10s
      fix: it's often overloaded; scans still use the other sources
  [+] crt.sh database reachable
  [+] Cert Spotter reachable · 10 of 90 free queries used this hour
  [+] Shodan InternetDB reachable
  [+] AWS IP ranges (cached 16h ago)
  [+] Tor exit list reachable (for --investigate-ip)

MCP
  [+] Claude app config points at this Monomi

14 ok · 1 warning · 0 problems: ready to scan
```

Each line is `[+]` ok, `[!]` a warning (a feature is weaker or off, but scans still work) or `[x]` a problem, and every warning or problem comes with a one-line fix. The exit code is 1 if anything failed, so scripts can check it. Doctor sends one request to each source, through the same rate-limit pacing scans use, and nothing to any scan target.

## Usage

```bash
# Subdomain discovery only (no API key needed)
python monomi.py example.com

# Add IPs, hosting provider/ASN, and country for each host
python monomi.py example.com --enrich

# Add open ports and known CVEs from Shodan InternetDB (turns on --enrich)
python monomi.py example.com --ports

# Save the CVEs and triage them with kaidoku
python monomi.py example.com --ports --cves cves.txt

# Fingerprint web servers (ACTIVE: one request per host; turns on --enrich)
python monomi.py example.com --fingerprint

# Look for exposed API specs and source maps (ACTIVE: a few requests per host; turns on --enrich)
python monomi.py example.com --exposed-files

# Where each homepage really lands, and its title (ACTIVE: one request per redirect hop; turns on --enrich)
python monomi.py example.com --probe

# Content discovery: exposed .git/.env/backups/debug pages and admin paths (ACTIVE: ~160 requests per host)
python monomi.py example.com --content --scope scope.txt

# ...plus your own paths, reported as leads (one per line, like a SecLists file)
python monomi.py example.com --content --wordlist paths.txt --scope scope.txt

# Only let the active checks reach hosts your scope file allows (see "Scope file" below);
# attack paths through hosts the file doesn't allow are set aside, with or without active checks
python monomi.py example.com --fingerprint --exposed-files --scope scope.txt

# Bug bounty rules (v1.19): cap active requests (1/s is the default with --scope) and
# send the identifying header the program asks for (research.txt: "X-Intigriti: yourname")
python monomi.py example.com --fingerprint --scope scope.txt --rate 1 --research research.txt

# Single hosts on other domains from the same program (checked on their own: their
# domains are never searched for subdomains; with --scope each must be in scope)
python monomi.py example.com --enrich --takeover --extra-hosts extra.txt --scope scope.txt

# Check email spoofing protection (SPF, DMARC, DKIM; DNS lookups only)
python monomi.py example.com --email

# Check for dangling CNAMEs / subdomain takeover leads (DNS lookups only)
python monomi.py example.com --takeover

# Also check hostnames you already know (one per line), e.g. ones certificate logs miss
python monomi.py example.com --takeover --hosts known-hosts.txt

# Add subfinder's results (run subfinder first; Monomi never runs it)
subfinder -d example.com -silent -oJ -o example-subfinder.json
python monomi.py example.com --takeover --subfinder example-subfinder.json

# Add BBOT's results (run BBOT first, passive and quiet; Monomi never runs it)
bbot -t example.com -f subdomain-enum -rf passive -ef loud -om json -n example -y
python monomi.py example.com --takeover --bbot ~/.bbot/scans/example/output.json

# Investigate suspicious IPs: Tor exit, VPN/proxy, hosting, CDN edge (asks public sources, never the IP)
python monomi.py --investigate-ip 171.25.193.25 8.8.8.8

# ...with Claude's verdict, saved to reports/ip_<ip>_<timestamp>.md
python monomi.py --investigate-ip 171.25.193.25 --ai

# With AI analysis + saved Markdown report
python monomi.py example.com --ai

# Analyze a SpiderFoot export (CSV: scan > Export > CSV) instead of querying CT logs
python monomi.py --import spiderfoot.csv --ports --ai

# Save raw results as JSON
python monomi.py example.com --json results.json

# Export the report as Markdown, HTML and a findings CSV (see below)
python monomi.py example.com --email --takeover --export all

# Plain output, no colors (also honors the NO_COLOR env var)
python monomi.py example.com --no-color
```

### Exporting reports

`--export` saves the scan as files in `reports/`: `md` (the full report as Markdown), `html` (one self-contained page that opens offline; print it to get a PDF) and `csv` (one row per finding, for ticketing systems and spreadsheets). Use `all`, or pick some with commas:

```bash
python monomi.py example.com --email --takeover --export all
python monomi.py example.com --ports --export html,csv
```

Exports are built by code, so they don't need `--ai`. Each has the summary, "fix this first", the findings (every fact with an owner, worst attack path first), the attack paths and the evidence they cite. A finding's severity is the worst attack path it's part of; findings in no path have none. With `--ai`, Claude's summary goes at the top, labeled as AI-written.

To export a scan again later without scanning, save it with `--json` and use the `report` command. It uses the evidence saved in the file, so the IDs an AI summary cites still match:

```bash
python monomi.py example.com --takeover --json scans/example.json
python monomi.py report scans/example.json --format html
```

Everything from the scanned domain is escaped in the HTML, which also carries a strict Content-Security-Policy (no scripts, nothing loaded from outside), and CSV cells starting with `=`, `+`, `-` or `@` get a `'` in front so spreadsheets can't run them as formulas.

### Example output

```
[*] Target: example.com
[*] Querying certificate transparency logs (crt.sh)...
[+] crt.sh: 412 certificates -> 37 hostnames
[*] Querying certificate transparency logs (Cert Spotter)...
[+] Cert Spotter: 130 certificates -> 29 hostnames

[+] 41 unique hostnames total:

    api.example.com
    status.example.com
    www.example.com
    ...

[*] Asking Claude to analyze the results...
[+] Report saved to reports/example.com_2026-10-03_0643.md
```

A report includes:

1. **Overview** of the public footprint
2. **Infrastructure layout:** hosts grouped by apparent purpose, plus naming patterns
3. **Worth reviewing:** prioritized findings (High / Medium / Low), each labeled and cited
4. **Attack paths:** how an attacker would most likely get in, step by step
5. **Recommendations:** "fix this first", then concrete defensive steps, each with its owner
6. **Limitations:** what passive data can and can't tell you
7. **Evidence:** every cited fact with its source, collection time and owner, written by Monomi's code (not the AI)
8. **Attack paths (built by code):** the paths exactly as the code built them, so the report can be checked against them

### Example finding

```
### High
- **Observed:** app.example.com resolves to 203.0.113.10, which Shodan lists
  with 2 CVEs on ports 80/443 [E14, E52, E53]. These are matched from version
  banners and must be verified.

## Evidence
- **E52**: 203.0.113.10 (app.example.com) has open ports: 80, 443; Shodan tags: cloud
  - Source: Shodan InternetDB, collected 2026-10-18T18:35:13+00:00
```

## MCP server mode

Monomi can also run as an MCP server, so AI agents (like the Claude app) can call its checks directly. It's a second way in alongside the CLI. The checks are **passive by default**; the two active checks run only after you approve each one in a terminal (see **Active tools** below).

Passive tools: `ping`, `find_subdomains` (with hostname categories), `enrich_hosts`, `check_ports`, `check_email_auth`, `check_takeover`, `investigate_ip` (suspicious IPs, up to 10 per call). Results with something to fix carry `owners`: the roles that would fix them.

**Active tools: you approve each one (v1.20).** `fingerprint_hosts`, `check_exposed_files`, `probe_hosts` and `discover_content` contact the target's own servers, so an agent can only *ask*: calling one sends nothing and looks nothing up, and returns an `approval_id` with the exact command for you. You run it in a terminal:

```
$ python monomi.py approve k7m2-x9pq --scope scope.txt --research research.txt
fingerprint_hosts: 1 host(s) in scope, at most 2 GET request(s) each (2 at most in total)
  staging.example.com
      GET https://staging.example.com/
      and http://staging.example.com/ once, only if HTTPS fails with a TLS error or is refused
Not in scope, will get no request and no DNS lookup (1):
  nope.example.net: no rule matches
Scope: scope.txt (sha256 c926207465f3...)
Research header: X-HackerOne-Researcher: you (sha256 b7f41dd083da...)
Approve k7m2-x9pq? It can be used once, within 15 minutes. Type yes to approve: yes
```

Then the agent calls `active_run` with that id, and it runs once. What you approve is locked in: the in-scope hosts, the URLs (for `check_exposed_files`, the fixed spec paths and homepage plus the rule for the rest: up to 3 same-host scripts and their `.map` files, never another host, at most 13 requests per host; for `probe_hosts`, the homepage plus the rule for redirects: followed only to the hosts you approved that have a public IP, only if the scope allows, only over http(s) on port 80 or 443, a redirect anywhere else reported but never requested, at most 12 requests per probed host, enforced in code), and the scope and research files' sha256. `active_run` refuses, and sends nothing, if the id wasn't approved, was already used, expired, or either file changed since. Only the word `yes` at a real terminal approves (there's no `--yes`). No MCP tool takes a scope file, a research file or a yes. Each approval is its own audit trail (`scans/approvals/<id>.json`: requested, approved, used, refused), and every request and refusal also goes to `scans/active.log`. Honest limit: an agent that has a shell on your machine can fake a terminal; the gate is against agents with MCP tools only. `check_exposed_files` never returns source code it finds, only that it's present.

**Content discovery over MCP is a background job (v1.26).** `discover_content` sends about 160 requests per host, which at the server's rate takes minutes, longer than one tool call may run. So after your yes, `active_run` looks the hosts up, starts the requests in the background and returns a `job_id` at once; `active_status` with that id shows progress (requests sent, paths tried, an estimate) and, when it's done, the results. Only one active check runs at a time, a call or a job (they share one rate limit): that's taken in one step before the approval is claimed, so two calls arriving together can't both start, and a refused call leaves its approval unused. A job has a hard 30-minute limit, and the slot it holds expires 2 minutes after that even if one request is still hanging, so nothing stays blocked. Its state is saved in `scans/mcp/jobs/` (again every 10 requests), so if the Claude app restarts mid-run, `active_status` says it was interrupted, with about how much it sent (`active.log` has every request). At most 5 hosts per approval, and the approval shows the full list of paths once.

**Scope file.** One rule per line, so a bug bounty program's scope list can be pasted in:

```
# comments and blank lines are ignored
example.com          # exactly this host
*.example.com        # any subdomain, NOT example.com itself (list it separately)
!blog.example.com    # never in scope, even if a rule above matches: exclusions always win
```

**What a refusal looks like** (real outputs, v1.20):

- **An id that wasn't approved, or was already used**: nothing is sent, and the reason reaches the agent:
  ```
  approval 6cep-p263 was already used; each approval runs once. Nothing was sent.
  ```
- **The scope file was edited after you approved**: the approval can't be used; ask for a new one.
- **Every refusal is logged** in `scans/active.log`, one JSON line each; requests are logged the same way with `"event": "request"`, the rule that allowed them and the scope's sha256:
  ```json
  {"time": "2026-11-21T04:15:23+00:00", "event": "request", "via": "mcp", "tool": "fingerprint_hosts", "host": "staging.41xlab.com", "url": "https://staging.41xlab.com/", "scope_rule": "*.41xlab.com", "scope_sha256": "c9262074...", "rate": 1.0, "research_sha256": "b7f41dd0..."}
  ```

Out-of-scope hosts are dropped before any DNS lookup and come back in `out_of_scope` with the reason, and every URL is checked again right before it's fetched (homepage, HTTP fallback, scripts, source maps). `scans/active.log` records each request with the rule that allowed it and the scope's sha256, plus every refusal (out-of-scope hosts, unapproved or used approvals, changed files), and whether it came from the CLI or MCP. On the CLI, `--scope FILE` is optional (you're the one running it) but strict when given.

**Rate and research header (v1.19).** Programs often limit automated tools ("max 1 request per second") and ask for an identifying header (`X-Intigriti: <you>`, `X-HackerOne-Researcher: <you>`). `--rate N` caps every active request, in total across all threads (one limiter per run; `0.5` = one every 2 seconds); with `--scope` and no `--rate` it's 1/s, without `--scope` there's no limit unless you ask. `--research FILE` (one `Name: value` header per line, `#` comments) adds those headers to active requests only, never to passive lookups; `Host`, `Content-Length`, `Transfer-Encoding` and `Connection` are refused, since the file may only say who sent a request. A bad file stops the run before anything is sent. Every `active.log` line has the `rate` and the file's `research_sha256`. Over MCP the research file comes with each approval (`monomi.py approve ID --scope FILE --research FILE`, sha256 locked in like the scope), and the rate is a server setting: `python monomi.py mcp setup --rate N` (default 1/s). Each active request then checks only as many hosts as fit in about 40 seconds at that rate (at 1/s: 20 for `fingerprint_hosts`, 3 for `check_exposed_files`, the rest in batches), replies say how they were sent (`sent_as`), and `doctor` shows the rate. Akashi reads the same file format.

Rejected lines (they don't count, and setup and doctor show why): a bare `*`, `*` anywhere but the start, single labels (`com`, `*.com`), shared suffixes many owners use (`co.uk`, `com.au`, `vercel.app`, `github.io`, `cloudfront.net`...; `example.co.uk` is fine), non-ASCII names, URLs, and IP addresses or ranges. Limit: scope is by hostname only (the IP a host resolves to isn't checked).

Every call is built to fit the Claude app's 60-second tool limit: `find_subdomains` gives its sources 45 seconds in total, returns whatever finished, and lists skipped sources in `errors`.

**Gated takeover leads (v1.13).** Each `check_takeover` lead has a `gate` (checks 4 and 6 above): `finding` only when DNS-over-HTTPS confirmed the target doesn't exist (see `nxdomain_confirmed_by`) and the service is known to let deleted names be claimed again, otherwise `lead` with each failed check and why. The summary counts them in `leads_passing_gate`. Even a `finding` is unverified: Monomi never claims the name.

**Summary replies (v1.9).** `find_subdomains`, `check_takeover`, `enrich_hosts` and `check_ports` take `detail="summary"` (the default) or `detail="full"`. A summary gives the counts plus the hosts that matter (risky categories, takeover leads and stale records, dangling CNAMEs, origin IPs), and saves the full result to `scans/mcp/` as `full_results_file`. Use `detail="full"` to get everything in the reply.

**Passing hosts as a file.** Instead of copying hostnames into the next tool, pass `find_subdomains`' `full_results_file` (or a `.txt` list, one host per line) as `hosts_file` to `check_takeover`, `enrich_hosts` or `check_ports`. Only files inside Monomi's `scans/` folder are accepted, so an agent can't point a tool at other files on your machine. Big files are checked in batches (200 hosts, 100 for `check_ports`): call again with `start` set to the reply's `batch.next_start` until it is `null`.

```
find_subdomains(domain="example.com")
  -> full_results_file: ".../scans/mcp/..._find_subdomains.json"
check_takeover(hosts_file="<that file>", domain="example.com")
check_ports(hosts_file="<that file>")
```

**Next checks over MCP (v1.10.2).** Every tool's reply has `next_checks`: the checks worth running next, each with the reason from that call. Suggestions only, nothing runs. An MCP call only sees its own results, never what the agent ran before, so each tool suggests only what its own results back up (`find_subdomains`: enrich and email; `enrich_hosts` and `check_ports`: ports, takeover, fingerprint; `fingerprint_hosts` and `probe_hosts`: ports, takeover, exposed-files, content; `check_exposed_files` and `discover_content`: ports, takeover), and the agent passes the tools it already called as `already_ran` to leave those out. Active checks in the list are marked `active: true`. A misspelled name in `already_ran` is refused before any lookup runs. Checks only the CLI can run (`--cves`) are marked `cli_only`. If the suggestions can't be worked out, `next_checks` is empty and `next_checks_error` says why.

```
fingerprint_hosts(hostnames=[...])
  -> next_checks: --ports (check_ports), --exposed-files (check_exposed_files, active)
```

**Agent skill.** [`skills/monomi/SKILL.md`](skills/monomi/SKILL.md) teaches an AI agent to use these tools well: summary replies first, chaining tools with `hosts_file`, `already_ran` for next checks, reporting leads and gaps honestly, and never running an active check on its own. Copy the `skills/monomi` folder into your agent's skills folder or skill bundle.

### Setting it up

For the Claude desktop app, one command does it:

```bash
python monomi.py mcp setup
```

It shows the change and asks before writing (`--yes` skips the question). Only the `monomi` entry is added or updated: other MCP servers and settings stay as they are, the old config is backed up next to it (`claude_desktop_config.json.bak-<date>-<time>`), and a config that isn't valid JSON is never overwritten. On Windows it updates every copy of the config the app may read. Run from WSL, it sets the app up to start Monomi inside your WSL distro (`wsl.exe -d <distro> -e ...`).

Then fully quit the Claude app, not just its window (Windows: right-click its tray icon > Quit; macOS: Cmd+Q), open it again, and ask Claude to run Monomi's `ping` tool. `python monomi.py doctor` also checks the entry. Run setup again after moving the Monomi folder or rebuilding the venv.

**API keys over MCP (v1.20).** The Claude app doesn't read `~/.bashrc`, so the server loads `OTX_API_KEY` from the 0x41 suite's key file, `~/.config/0x41/keys.env` (the same file `0x41 mcp` uses). `python monomi.py mcp keys` writes it from your terminal's keys without showing them; it must be readable only by you (permissions 600), values are never printed, and other tools' keys in it are kept. `doctor` checks it.

**Upgrading from v1.19.** `--allow-active`, `--scope` and `--research` are gone from `mcp setup` and the server config. The server ignores them (with a note), and `python monomi.py mcp setup` removes them from every config copy; `doctor` names any that are left.

**Other MCP clients (v1.13).** Add `--client` to set up another client, with the same rules (only Monomi's entry changes, a backup first). `--print` shows the entry in that client's format without writing anything.

| `--client` | Config file | Monomi's entry |
|---|---|---|
| `claude` (default) | the Claude desktop app's config (every copy on Windows) | `mcpServers.monomi` |
| `codex` | `$CODEX_HOME/config.toml`, else `~/.codex/config.toml` | `[mcp_servers.monomi]` |
| `opencode` | `~/.config/opencode/opencode.json` (or `.jsonc`) | `mcp.monomi`, or `mcp.servers.monomi` when the file already uses OpenCode's V2 layout |
| `hermes` | `$HERMES_HOME/config.yaml`, else `~/.hermes/config.yaml` | `mcp_servers.monomi` |

```bash
python monomi.py mcp setup --client codex           # show the change, ask, write it
python monomi.py mcp setup --client hermes --print  # only print the entry
```

Comments, key order and indentation in Codex and Hermes configs are kept, and any keys you added to Monomi's own entry (a timeout, env) stay. An OpenCode file with comments (JSONC) is never rewritten, since that would delete them: setup stops and points you to `--print`. `python monomi.py doctor` checks Monomi in every client that has a config file. Any other MCP client: `python monomi.py mcp setup --print` gives the Claude-style JSON entry to adapt.
## How it works

```
domain ──► crt.sh website ───┐
domain ──► crt.sh database ──┤
domain ──► Cert Spotter ─────┼──► merge + de-duplicate ──► terminal / JSON
domain ──► AlienVault OTX ───┤   (or SpiderFoot CSV    │
subfinder file (--subfinder) ┤    via --import)        ├──► DNS + ASN (--enrich)
BBOT file (--bbot) ──────────┘
                                                       ├──► Shodan InternetDB (--ports)
                                                       ├──► email / takeover / fingerprint checks
                                                       └──► evidence ──► attack paths (code)
                                                                              └──► Claude (--ai) ──► Markdown report
```

Certificate Transparency (CT) is a public log of every TLS certificate issued by trusted authorities. Certificates list the hostnames they cover, so CT logs reveal subdomains an organization has requested certificates for, without touching the organization's servers. Passive DNS (OTX) adds hostnames that DNS sensors saw answer, including ones that never had a certificate.

## Project structure

```
monomi/                     # the repo
├── monomi.py               # runs the CLI: python monomi.py example.com (a wrapper for monomi/cli.py)
├── mcp_server.py           # starts the MCP server; the Claude app config points here (wrapper)
├── pyproject.toml          # makes Monomi installable: pip install -e .
├── monomi/                 # the monomi package: all the code
│   ├── __init__.py         # package marker, monomi.__version__
│   ├── __main__.py         # python -m monomi
│   ├── home.py             # where data lives: MONOMI_HOME, the repo folder, or ~/.monomi
│   ├── cli.py              # the command line (was monomi.py)
│   ├── doctor.py           # setup check: packages, API key, DNS, sources, MCP (monomi.py doctor)
│   ├── analysis.py         # Claude analysis layer
│   ├── enrich.py           # DNS + ASN/provider enrichment
│   ├── internetdb.py       # Shodan InternetDB: open ports + CVEs per IP
│   ├── fingerprint.py      # HTTP header fingerprinting (--fingerprint, active)
│   ├── headers.py          # security headers check (reads the --fingerprint response)
│   ├── exposed.py          # exposed API specs + JS source maps (--exposed-files, active)
│   ├── probe.py            # live pages: redirects followed per scope, title (--probe, active)
│   ├── content.py          # content discovery: checked files + leads (--content, active)
│   ├── categorize.py       # rule-based hostname categories
│   ├── mcp_server.py       # MCP server mode (7 passive tools, 4 active that need approval, active_run, active_status)
│   ├── approvalcore.py     # approvals core shared by the 0x41 suite (records, typed yes, single-use claim)
│   ├── approvals.py        # terminal approvals for active MCP checks (monomi.py approve)
│   ├── keys.py             # API keys for the MCP server from ~/.config/0x41/keys.env (monomi.py mcp keys)
│   ├── mcp_setup.py        # adds Monomi to an MCP client's config: Claude, Codex, OpenCode, Hermes (monomi.py mcp setup)
│   ├── scope.py            # scope file for active checks: parse, match, hash pinning
│   ├── activelog.py        # scans/active.log: every active request and refusal
│   ├── rate.py             # --rate: one shared limiter for active requests
│   ├── research.py         # --research: the identifying header file (Akashi imports it)
│   ├── emailauth.py        # email spoofing check: SPF, DMARC, DKIM + verdict (--email)
│   ├── takeover.py         # dangling CNAME / subdomain takeover check (--takeover)
│   ├── threatintel.py      # IP threat-intel: Tor list, ASN, reverse DNS, Shodan, labels (--investigate-ip)
│   ├── aws_ranges.py       # AWS CloudFront detection (Amazon's IP range list, cached daily)
│   ├── evidence.py         # evidence list, owners, citation check, Evidence section
│   ├── paths.py            # attack paths and leads built from the evidence, "fix this first"
│   ├── gate.py             # validation gate: the fixed checklist that decides path, lead or set aside
│   ├── suggest.py          # next checks worth running, from what the scan found
│   ├── report.py           # report exports: Markdown, HTML, findings CSV (--export, monomi.py report)
│   ├── dnscheck.py         # shared DNS helper: status words, DNS-over-HTTPS double-check
│   ├── history.py          # scan history per source + change detection
│   ├── ui.py               # colored banner + terminal output
│   ├── common.py           # shared helpers: version, hostname checks, timestamps
│   ├── collectors/
│   │   ├── crtsh.py        # crt.sh collector (with retries)
│   │   ├── crtsh_db.py     # crt.sh database collector (PostgreSQL)
│   │   ├── certspotter.py  # Cert Spotter collector (pagination, rate-limit retry, partial lists)
│   │   ├── otx.py          # AlienVault OTX passive DNS collector (optional OTX_API_KEY)
│   │   ├── pacing.py       # shared request pacing for crt.sh, Cert Spotter and OTX
│   │   └── saved.py        # saved per-domain copies of each source, used when a source fails
│   └── importers/
│       ├── spiderfoot.py   # SpiderFoot CSV export parser
│       ├── subfinder.py    # subfinder output reader (--subfinder)
│       └── bbot.py         # BBOT output.json reader (--bbot)
├── skills/
│   └── monomi/SKILL.md     # agent skill: how to use the MCP tools well
├── scans/                  # saved scans per domain (git-ignored)
├── reports/                # generated reports (git-ignored)
├── cache/                  # cached AWS IP range list (git-ignored)
├── tests/                  # pytest suite (run: pytest)
├── pytest.ini              # pytest settings
├── requirements.txt
└── requirements-dev.txt    # requirements + pytest, for development
```

## Limitations

- CT logs only show hosts that have had TLS certificates; hosts behind wildcard certificates or without TLS won't appear. OTX passive DNS and a subfinder import fill some of that gap, but only with what those sources have seen.
- Passive DNS and subfinder's sources include old and sometimes garbled names (a wide run can add hundreds of hostnames that no longer resolve, or never did). `--enrich` shows which are live; nothing is treated as a finding just for being listed.
- A hostname appearing in CT logs doesn't mean it's currently live. `--enrich` shows which ones still have DNS records, but a DNS record doesn't prove a server is up.
- AI analysis only sees what Monomi collected (hostnames, plus DNS/hosting, Shodan or SpiderFoot data when those options are used). Every finding cites numbered evidence and is labeled Observed / Inference / Lead, but treat findings as leads to verify, not confirmed issues. The citation check confirms that every cited evidence ID exists; it can't prove an ID fully supports the sentence, so spot-check important findings against the report's Evidence section.
- `--fingerprint` only sees the homepage of each host over HTTPS. Behind a CDN (Cloudflare, Vercel, Fastly) it mostly sees the CDN, not the origin server, and many servers hide their versions.
- `--probe` starts at each host's homepage (`/`) and follows at most 5 redirects; it reads a title only from pages labeled HTML (the first 64 KB). A redirect it refuses (out of scope, not approved, another port, a private address...) is reported, not followed, so the page behind it isn't seen. A title is written by the site: evidence, not proof of what the site is. Two honest limits: a redirect's address is checked when the redirect arrives, and `requests` looks the name up again to connect, so a DNS answer that changes in between (DNS rebinding) isn't caught; and a server that sends its headers very slowly can hold one request for up to the read timeout, since the per-host time limit is checked between requests and between body chunks.
- `--exposed-files` checks only a fixed list of well-known spec paths and the scripts the homepage itself links, so absence is not proof: a spec or source map behind a different path, a login, or a redirect won't be found. It reads JSON specs and `.map` files only (not YAML specs or Swagger UI HTML pages).
- The security headers check only judges hosts that served a real page (HTTP 2xx), and only the homepage. Other pages can send different headers, and a missing header is a missing defense, not a confirmed vulnerability.
- `--email` checks DKIM only under common selector names (Google, Microsoft 365, Mailchimp, SendGrid, Cloudflare and a few generic ones), because DNS can't list selectors. A domain using a custom selector will show DKIM as "not confirmed" even if it's set up.
- `--takeover` only catches services where a deleted resource's name stops resolving in DNS. Services that answer for every name (GitHub Pages, S3, Heroku, Netlify) need an HTTP check to spot a takeover, and aren't covered yet.
- A takeover `no_cname` status only means DNS returned no CNAME record. Some DNS providers (e.g. Cloudflare) answer the same way for names that don't exist, so it doesn't prove a host is live.
- `--investigate-ip` only uses free public sources. The Tor exit list is authoritative, but VPN and proxy labels come from reverse DNS names and Shodan tags, so many commercial VPNs won't be caught; "no anonymizer found" doesn't prove there isn't one. A country is where the network is registered, never where the person using the IP is.
- crt.sh (website and database) and Cert Spotter are free services and are sometimes slow or rate-limited. Over MCP, sources still running after 45 seconds are skipped so the call fits the Claude app's tool limit. Pacing keeps sweeps under the limits, so a big multi-domain sweep runs slower on purpose.
- crt.sh can fall days behind the CT logs, so a new domain may show 0 crt.sh results while Cert Spotter finds certificates. Monomi reports this as **behind**, and history keeps crt.sh's last list until it catches up, so hosts aren't later flagged as new or gone by mistake.
- A source that failed or was cut short keeps its last list in history, so a host that really disappeared is only reported **[GONE]** once every source that had it works fully again.
- A saved source copy is only used when the live source fails, and it can be up to 30 days old: hosts added or removed since then won't show.
- A lame delegation is spotted only when a DNS-over-HTTPS server explains its SERVFAIL ("name servers refused", or EDE codes 22/23). A SERVFAIL with no reason stays **servfail**, and `dangling_ns` never checks whether the nameservers could actually be claimed: **investigate** means look at the exact NS names yourself.
- Some DNS providers (Cloudflare among them) never say a name doesn't exist, so a retired hostname on those zones shows as **no_address**, not **no_such_host**.
- DNS answers are cached. Right after a DNS change, a name that was looked up before it existed can still read as **no_such_host** until the zone's negative-cache time runs out (often up to 30 minutes), and a deleted record can keep resolving until its TTL runs out.
- Attack paths come from fixed rules applied to what the scan saw. A path shows how an attack would most likely go, not proof that it works, and "no attack path found" means no rule matched, not that the target is safe. A lead is weaker still: a question to check, not a finding. Paths are only as complete as the checks that ran.
- "The target's own" (check 2) knows CDN edges, a short list of third-party hosting services by name (GitHub, Shopify, Squarespace, WordPress.com, Netlify, HubSpot, Zendesk, Salesforce, Discourse) and AWS Global Accelerator from Amazon's own IP range list. A site on another vendor's servers can still read as the target's own: judge third-party hosts by hand when a program excludes them.
- The validation gate checks what the scan's own data can show. "Set aside" means out of scope or on shared infrastructure by Monomi's rules, not proof that nothing is there, and a program note is a reminder to check the program's rules, not a verdict on eligibility.
- `mcp setup --client` sets a client up in the environment setup runs in: from WSL, Codex, OpenCode and Hermes get WSL paths. A client running natively on Windows that should reach Monomi inside WSL isn't covered (only the Claude app gets the `wsl.exe` launcher). OpenCode's docs don't give a Windows config path, so on Windows setup uses `.config\opencode` under your user folder and `doctor` shows the path it checked.

- `--content` tries a fixed list of 155 common paths (plus your `--wordlist`), so it finds the usual mistakes, not every file a site serves. A host whose WAF answers every path with the same page shows no leads (calibration drops what it can't tell apart, rather than guess). Only the first 16 KB of an answer is read, so a settings count on a huge `.env` says "N+", and two pages that are the same for their first 16 KB count as the same. A server that sends its *headers* very slowly can still hold one request for a long time (the same limit as `--probe`); over MCP the job's slot expires anyway, so other checks aren't blocked. Over MCP it's a background job: if the Claude app restarts mid-run, the job stops (reported as interrupted, with what it sent in `active.log`). The same DNS-rebinding limit as `--probe` applies.

## Development

Install the dev requirements and run the test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

The tests cover hostname filtering, domain cleaning, evidence citation checks, change detection, the email check, the takeover check (using fake DNS records), the IP threat-intel labels, owners, the attack-path rules and the validation gate (each check proven by a test that removes it; golden-file tests: saved and planted scans in `tests/golden/` whose evidence and attack paths must not change by accident), the doctor checks (with fake network calls), the report exports (HTML escaping, CSV formula guard) and MCP setup for every client (with fake config files, never your real one).

## Roadmap

**Done**
- [x] Passive subdomain discovery (crt.sh + Cert Spotter)
- [x] Change detection between scans
- [x] DNS + hosting provider enrichment
- [x] Open ports and known CVEs via Shodan InternetDB, with hand-off to [kaidøku](https://github.com/0x41io/kaidoku)
- [x] SpiderFoot import (`--import`): run monomi's AI analysis on SpiderFoot exports
- [x] Evidence-backed findings: numbered evidence, Observed / Inference / Lead labels, citation check, Evidence section in reports
- [x] v1.0: code cleanup, shared helpers, test suite
- [x] v1.1: opt-in HTTP tech fingerprinting (`--fingerprint`)
- [x] v1.2: security headers check (from the `--fingerprint` request)
- [x] v1.3: email spoofing check (`--email`: SPF, DMARC, DKIM + overall verdict)
- [x] v1.4: subdomain takeover / dangling DNS detection (`--takeover`)
- [x] v1.5: MCP server mode
- [x] v1.6: IP threat-intel mode (`--investigate-ip`, `investigate_ip` MCP tool)
- [x] v1.6.2: smarter field-test results: CDN/Okta edge detection from Shodan CPEs, `stale` takeover status, `legacy` and `internal-tools` hostname categories
- [x] v1.7: third subdomain source (crt.sh database) + Cert Spotter rate-limit retry, 45s MCP deadline, DNS status for hosts with no IPv4, CNAME-based edge detection, `iot-ot` and `partner-portal` categories, `check_ports` summary
- [x] v1.7.1: takeover fixes from field testing: dangling CNAMEs inside the scanned domain marked `stale` (not leads), new `no_such_host` status, optional `domain` argument for the `check_takeover` MCP tool

- [x] v1.8: attack paths built by code (every step evidence-cited and labeled), `owner` roles on every finding and "fix this first", `--hosts FILE`, DNS reliability (shared DNS helper, DNS-over-HTTPS double-check, one set of status words), MCP input cleanup
- [x] v1.8.1: fixes from a 2,000+ host field test: newer AWS load balancer names (region after `elb`) marked `stale`, dangling CNAMEs under a cloud provider domain get a "check it" label instead of an expired-name path, side doors skip private IPs, load balancers and shared front doors, and side-door wording follows the host category
- [x] v1.9: MCP summary replies with full results saved to a file, `hosts_file` input and batches, shared crt.sh / Cert Spotter pacing, saved per-domain source copies as a fallback, crt.sh "behind" status, Google as a second DNS-over-HTTPS server with one retry and a `servfail` status, Vercel counted as shared edge

- [x] v1.9.1: runs on Windows without WSL (Windows file locking for pacing, install guide), email check falls back to DNS-over-HTTPS when port 53 fails
- [x] v1.9.2: report exports (`--export`: Markdown, HTML, findings CSV; `monomi.py report` for saved scans), setup check (`monomi.py doctor`), one-command MCP setup (`monomi.py mcp setup`)
- [x] v1.10: fix groups (a path lists every fix it needs, and "fix this first" never says one fix closes a path that needs several), leads kept apart from attack paths (side doors, unverified versions, "go around the CDN"), next-check suggestions. In `--json`, a path's `fix` list is now `actions`, `fix_first` holds a list of actions, and `paths` gains `leads`
- [x] v1.10.1: next-check suggestions in MCP tool results (same list the CLI already shows; nothing runs unless the agent calls the tool)
- [x] v1.10.2: MCP next checks fixed: each tool suggests only what its own results back up, `already_ran` leaves out tools the agent already called, `cli_only` marks checks only the CLI can run, and a failure shows in `next_checks_error` instead of an empty list; version number fixed (v1.10.1 still reported 1.10.0)

- [x] v1.11: active checks over MCP, off by default behind an `--allow-active` gate with an `scans/active.log` audit trail: `fingerprint_hosts` (web server, versions, security headers; retries over plain HTTP when HTTPS fails) and `check_exposed_files` (public OpenAPI/Swagger specs and JS source maps, CLI `--exposed-files`, source code never returned). `monomi.py doctor` reports the active-tools setting and finds the Claude config across Windows install layouts; active requests send an honest active User-Agent
- [x] v1.11.1: `--exposed-files` / `check_exposed_files` only fetch source maps on the host being checked (a script could point its map at another site or a cloud metadata address); found in review

- [x] v1.12: a human-approved, fail-closed scope file for the active tools (`mcp setup --scope`, typed `yes`, sha256 pinned at server start; CLI `--scope`). Out-of-scope hosts get no DNS lookup and no request, every URL is re-checked in the fetch layer, and `scans/active.log` records the rule and scope hash for each request plus every refusal, from the CLI and MCP alike

- [x] v1.13: a validation gate (one fixed checklist that decides attack path, lead or set aside, shown in every output and on MCP takeover leads; an unknown dangling CNAME and a takeover resting on system DNS alone are now leads) and `mcp setup --client` for Codex CLI, OpenCode and Hermes Agent, with `doctor` checking every client. Plus an agent skill (`skills/monomi`), a "Try it" section and a field test issue template
- [x] v1.13.1: gate fixes from the first bug bounty field run: out-of-scope hosts never feed a path rule (anything about them alone is set aside, and outputs say how many were left out), check 2 knows third-party hosting and AWS Global Accelerator (not just CDNs), and dangling CNAMEs to AWS API Gateway names are stale, not leads
- [x] v1.14: finds more: AlienVault OTX passive DNS as a fourth source (optional free key, `doctor` check), subfinder import (`--subfinder`, MCP `subfinder_file`), history kept per source (a failed, cut-short or new source can't make hosts look new or gone), cut-short sources marked **partial** (fixes fake [GONE] hosts after Cert Spotter was rate-limited mid-way), and honest cooldown wording when a source is skipped
- [x] v1.14.1: installable package: the code moves into `monomi/`, `pip install -e .` installs it (plus `monomi` and `monomi-mcp` commands, `python -m monomi`), so other tools like Akashi can `from monomi import ...`. Data stays where it was when running from the repo, `MONOMI_HOME` can move it, and a plain install uses `~/.monomi`. `python monomi.py` and existing MCP configs keep working unchanged. Requires Python 3.14+
- [x] v1.15.0: Akashi-ready leads: every path, lead and set-aside item in a saved scan has a `rule` and structured `targets` (see [Reading a saved scan](#using-monomi-from-other-tools)), "go around the CDN" gives one lead per origin server instead of one lead for the whole scan, and saved scans start with `monomi_version`
- [x] v1.15.1: a Cert Spotter error reply (e.g. HTTP 503 during an outage) fails just that source and the scan carries on with its saved copy, instead of crashing the whole scan; found on the lab during Akashi's release gate
- [x] v1.16.0: scope caution: paths, leads, set-aside items and MCP takeover records that run through pre-release (beta, preview...) or non-production (dev, staging, test...) hosts carry a note naming them, since programs often close those as Not Applicable or out of scope. Warns, never drops: the note never changes the result
- [x] v1.17.0: lame (dangling NS) delegations: `--takeover` and MCP `check_takeover` report a subzone delegated to nameservers that refuse it, grouped by the delegated zone, graded **theoretical** on AWS Route 53 or **investigate** on nameservers it doesn't recognize, as a new `dangling_ns` lead (rule name for tools like Akashi). Found as a SERVFAIL cluster on a bug bounty run
- [x] v1.17.1: lame delegations tidy-up: hosts under a lame delegation count as checked (they have an answer) in the CLI's "hosts checked" line and stay out of MCP `unknown_count`/`unknown_hosts` (their `results` status is still `servfail`); the zone-cut walk no longer re-asks the host, asks each ancestor once per DoH server with no retry pause, and shares one cache across the run, so a walk takes seconds instead of ~30s
- [x] v1.18.0: wildcard DNS detection: hosts that only resolve through a wildcard record are set aside (one line per wildcard, full list in `--json`, left out of counts, checks and attack paths), including private ingress wildcards, grouped by answer, with certificate-backed names called out; go-around-the-CDN leads about the same CDN hosts are printed as one block, one line per origin server, each keeping its own lead id for Akashi. Found on a bug bounty run where most of 959 subdomains were wildcard noise

- [x] v1.19.0: bug bounty rules on Monomi's own active checks: `--rate N` (one limiter shared by every thread, 1/s by default with `--scope`) and `--research FILE` (identifying headers, sha256 in `active.log`; module shared with Akashi), both over MCP through `mcp setup` (research file pinned, host count per call fitted to the rate) and in `doctor`; `--extra-hosts FILE` checks a program's single hosts on other domains in the same run (no subdomain search for their domains, scope fail-closed, labeled `[extra]`, left out of change history); the takeover section says how many names under a wildcard DNS can't check. From an Intigriti field run

- [x] v1.20.0: active MCP checks need a person's approval each time: `fingerprint_hosts` and `check_exposed_files` only ask (nothing sent, no lookup) and return an id; `monomi.py approve ID --scope FILE [--research FILE]` shows every host, URL, rule and the request cap and needs a typed yes at a real terminal; `active_run(id)` runs it once (15 minutes, single use across processes, scope and research sha256 re-checked, scope applied again before every request). `--allow-active` and the config-pinned scope/research are gone (setup strips them, the server ignores them, doctor names them). The MCP server loads `OTX_API_KEY` from the suite's `~/.config/0x41/keys.env` (`monomi.py mcp keys`), so OTX works over MCP. Approvals idea from Harry Siu and @deeponailabs (issue #27)

- [x] v1.21.0: one approvals core for the whole 0x41 suite: the record keeping, typed yes and single-use claim (one `.used` file only one process can create) move into `monomi/approvalcore.py`, so every human-approval gate (Monomi's active checks, 0x41's active proofs, later ones) shares one tested copy. Nothing changes for Monomi users: same commands, same messages, every approval test unchanged. `scope.check_pinned` and `research.check_pinned` take an optional `fix=` command for their messages

- [x] v1.22.0: a `management` hostname category for device and infrastructure consoles (`mdm`, `intune`, `airwatch`, `unifi`, `fortigate`, `pfsense`, `vcenter`, `esxi`, `idrac`, `ilo`, `ipmi`, `proxmox`, `portainer`, `rancher`, `citrix`), ranked right after `access` and treated as risky like it (a live console gets its own evidence fact, shows in MCP `risky_categories`, and side doors through one say "a device or infrastructure console"), and `extranet` / `intranet` added to `access`. Same matching as every category (`ilo` matches `ilo4`, never `pilot` or `milo`). From the Marionnaud field run, where `cp-unifi`, `mdm` and `extranet` came back uncategorized
- [x] v1.22.1: Microsoft 365 (Exchange Online's published IPv4 blocks) and Google's shared front end for custom domains (its four A-record IPs) count as third-party hosting by address, since the network owner alone can't tell them from a customer's own Azure or Google Cloud server. They're never an origin for "go around the CDN" or a side door, and a version or CVE seen on one is set aside naming the service. From the Marionnaud field run, where an `autodiscover` host on Microsoft 365 and a Google-hosted host made 8 of 9 around-the-CDN leads
- [x] v1.23.0: signal cleanup, from the Marionnaud, Exoscale, Kruidvat, Superdrug and Savers field runs. Whether a server is the target's own now reads each host's CNAME too, so a passive scan without `--ports` gets the same answer as one with it: Azure Front Door by where its chain ends (`tm-azurefd.net`, `t-msedge.net`), Azure Static Web Apps, App Service's shared front ends (`waws-prod-...`), Shopify (by CNAME and its storefront block), hosted careers sites, help desks and email platforms, and Zoho by network owner. "Go around the CDN" skips hosts whose CNAME leaves the target's domain: a known vendor is third-party hosting, an unknown one is set aside naming the CNAME, and a load balancer or VM the target rents (AWS, Azure, Google) stays a lead and ranks first. Leads that tie are ranked by host category, then by IP as numbers (not text), and `more_leads_hosts` names the hosts behind the leads that were cut. `tst`, `pre`, `pp`, `etst` and `euat` count as non-production. IPs Team Cymru doesn't know are checked against Amazon's CloudFront list. A clean `--exposed-files` / `check_exposed_files` result says what was checked on each host
- [x] v1.23.1: CVEs and risky services on someone else's server are never the target's. Each Shodan IP that's third-party hosting or a shared front door (the same check the gate uses) gets a `not_own` label saying what it is, and is left out of `unique_cves`, `risky`, `--cves`, the CLI table (one line instead), MCP `check_ports`' origin IPs (`third_party_ips` instead) and the AI report. From the Superdrug run, where 5 jQuery UI CVEs on Google's shared front end were counted as Superdrug's and 0x41's report listed them as the target's
- [x] v1.24.0: one "go around the CDN" lead per CDN, listing every origin candidate, ranked (a rented load balancer or VM first, then by host category, then IP), instead of one lead per origin: Exoscale's 11 leads for one question are one lead. Vendor-named origins go into one set-aside item per CDN, with the CNAMEs named. Contract change: an around-the-CDN lead's targets gain `origins` (`[{"ip", "hosts"}]`, ranked), and `ips` / `hosts` hold every origin and direct host in that order (Akashi v0.4.0 proves it). `--exposed-files` / `check_exposed_files` fall back to plain HTTP like `--fingerprint`: the homepage goes first and decides the scheme (HTTP once when HTTPS fails with a TLS error or is refused, never after a timeout), and a host that answers neither gets nothing more (up to 14 requests a host, was 13). Bounty mode lives in 0x41 v0.10.0, which passes a program's scope file and exact hosts to this scan
- [x] v1.25.0, **security fix**: the scope check now asks which host a request will really connect to. Python's URL parser and `requests` can read the same URL differently (`http://evil.test\@good.test/` is `good.test` to one and `evil.test` to the other), so before v1.25 a target could get a request sent outside the scope: in `--exposed-files` / `check_exposed_files`, a page linking `<script src="https://evil.test\@its-own-host/x.js">` made Monomi fetch it from `evil.test`, through the scope file and an MCP approval, logged as allowed. Affected: every release from v1.11.1 (the same-host rule) to v1.24.0; only a GET, and only after the target planted the link, but it broke what a scope file promises. Now any URL the two parsers read differently is refused in every mode, and only http(s) is ever sent. Found in Claude's review of `--probe`
- [x] v1.25.0: `--probe` / `probe_hosts`, the first app-mapper module (`probe.py`): each live host's homepage followed through its redirects to where it really lands, with the page title. Redirects are followed by hand, so every hop gets the same steps as `--fingerprint` (scope check, `--rate` slot, `active.log` line, research header); one that leaves scope is recorded in `redirect_blocked`, never requested, and over MCP a redirect is followed only to the hosts you approved (`redirect_blocked_reason`: `out_of_scope` or `not_approved`). Each record says what the server claims the body is (`content_type`) and what it looked like (`body_kind`), so "no title" always says why: from the lab, where a JSON API looked like a page with no title. Titles are cleaned of control characters and handled as untrusted text. `--exposed-files` is now also suggested after `--probe` finds live pages. Hardened in review before release: every redirect goes through one check (valid http(s) URL, port 80/443, one clear host, in scope, approved over MCP, and never a private or local address, including where its name resolves) with the reason recorded in `redirect_blocked_reason`; the 12-request cap and a per-host time limit (60s, 30s over MCP) are enforced in code; a broken redirect address or an unknown charset is recorded instead of crashing the scan; titles use the charset the server states, else UTF-8

- [x] v1.26.0: `--content` / `discover_content`, content discovery (`content.py`), Phase 1 brick two. 155 paths, 115 of them with a content check (Git/SVN/Mercurial folders, `.env` files, keys and credential files, config backups, archives and SQL dumps, phpinfo, server-status, Spring Boot env and heap dumps, pprof and more) and 40 leads. Calibration with three made-up paths per host drops soft-404s and catch-all pages; a file check that a made-up path passes isn't trusted on that host. Evidence describes, never copies. `--wordlist FILE` adds your own paths as leads. Over MCP it's Monomi's first background job: `active_run` starts it, the new `active_status` follows it, and no other active check starts until it's done. Built in Python on Monomi's own guards (scope per request, `--rate`, `active.log`, research header, a per-host cap), not on ffuf, so every request goes through the same checks as the rest of Monomi. Hardened in review before release: a body sent a byte at a time can't hold a request past its deadline; one active check at a time is now one atomic step (two calls at once could both start before); a job that can't be saved never starts; an interrupted job keeps a real request count; login headers and redirect queries from the target are trimmed to safe parts; path-echoing not-found pages, BOM'd or comment-led HTML, JavaScript `from` lines and similar no longer pass file checks; redirect leads are told apart by where they go; a `.tar.gz` the server decompressed on the way still counts; `--wordlist` takes printable path characters only
- [x] v1.27.0: `--content` findings become attack paths, so Akashi can prove them. Each file found is an evidence fact ("staging serves /.env to anyone: an environment file with 12 settings, 3 named like secrets"), and a new rule, `exposed_file`, builds one path per host listing every file found there, so one leaky host can't fill the list. High when any file holds secrets or source code, Medium when they only reveal internals; one fix per file, and a secrets file's fix says to change what it held. A host behind a CDN keeps its path (the CDN only passes the file on), while a file on third-party hosting (a store, a forum) is set aside as that service's. Leads (an admin path that answered) stay leads in the `--content` results: they aren't facts yet. New `content.recheck_file(url, kind, scope=...)` asks for one file again (the three made-up paths, then the file, through the same guards and the same file check, now one shared `judge_file()`) and says `still_served`, `gone`, `untrusted` or `unclear`: what Akashi's proof runs. A path refused on its own counts as gone (that's the fix), but a host that refuses every path, made-up ones too, is unclear. Contract addition: rule `exposed_file`, targets `files` ([{path, url, kind, severity}]) and `scheme`, and `recheck_file` with its four result words
- [x] v1.27.1: exposed files strengthen side doors. When a side-door host (a dev or staging host on the same server as production) serves a readable secrets file (an `.env`, keys, credentials), that file is an observed way in, so the side door becomes an attack path: "Use staging as a side door into ...". Source files (a Git folder, a backup) add a step labeled Lead, like a version does, and the lead's "Missing" line names them, but they don't promote it on their own: the code may hold passwords, but that isn't shown. Info files (phpinfo and similar) and files on the production host itself don't change the side door. Nothing Akashi reads changes
- [x] v1.27.2: "Fix this first" knows that taking a host off the internet removes everything it serves. A side door's "Take staging off the internet or restrict who can reach it" now also closes the exposed-files path on that same host, so on the 41xlab lab it reads "closes P1, P2" instead of only the side door, and it wins over a fix that closes one path. Only exposed-files paths count: a CVE or open service rests on the server's IP, which is still there. A path the action now closes outright is no longer listed as one it's only part of
- [x] v1.28.0: fixes from the PlayStation field run, and a new license. (1) A dangling CNAME nobody on the public internet can ever create is a stale record, not a takeover lead: into a brand TLD only one company registers under (`.aws`, `.google`, `.microsoft`...), a private TLD (`.internal`, `.local`, `.corp`...) or a "TLD" that can't be real (`preview.direct.q1-pqa`). PlayStation's twelve `*.internal.aws` CNAMEs stop being "confirm by hand" leads, and saved scans are graded the same way. (2) Around-the-CDN leads try the likeliest origins first: one named for a host behind the CDN (`origin-api.bridges` next to `api.bridges`), then one the operator named "origin", then one sharing service words with the fronted hosts (environment words like stage or dev don't count), then the order as before. Akashi tries origins in this order, so its five tries go to the best candidates. Nothing is dropped or added. (3) A differential check for releases: real targets' scans can be golden fixtures in `tests/golden/private/` (gitignored, never committed), and a failing golden test lists what moved (leads added or gone, origin order, facts) instead of a JSON dump. (4) Licensed AGPL-3.0-only from this version on; earlier versions stay MIT (see Licensing)
- [x] v1.28.1: broken DNS delegations graded right. The refusing nameservers are read out of the resolver's answer in IPv6 too (`[2600:9000:...]:53`), not only IPv4, and every Route 53 nameserver range from AWS's published list counts as Route 53 (v1.17 knew one IPv4 range). On PlayStation, a delegation to a Route 53 nameserver given only by its IPv6 address had come out "investigate" (Medium); it's "theoretical" (Low) like the others. Saved scans are graded again the same way
- [x] v1.29.0: BBOT import (`--bbot FILE`, MCP `bbot_file`). Reads BBOT's `output.json` (checked on a real BBOT 3.1.0 run): its in-scope DNS names (scope distance 0) under the target become one more source, every other event type is counted and named, never used. Monomi never runs or bundles BBOT, and every host goes through Monomi's own checks and evidence model
- [x] v1.29.1: from the first BBOT run on a real program (PlayStation). BBOT's own placeholder names (`_wildcard.<zone>`, made up while it tests a zone for wildcard DNS) are skipped and counted, never hosts: one had become a fake "Take over DNS for `_wildcard.nonprod.pcs...`" lead. And a dangling CNAME to an Amazon OpenSearch Service endpoint (`search-<name>-<ID>.<region>.es.amazonaws.com`, the ID generated by AWS) is a stale record, like a load balancer's, since a deleted domain's endpoint can't be created again; saved scans are graded the same way
- [x] v1.29.2: Shodan InternetDB checks every one of the target's own servers (up to 1,000) and looks up CDN edges only within the old 200-IP limit, since an edge's open ports belong to the CDN. Before, it took the first 200 IPs in text order: on PlayStation (about 660 IPs, 236 of them its own servers) it skipped servers with banner CVEs while checking Akamai edges. The output says what was left out (`ips_skipped_edges` over MCP)
- [x] v1.29.3: vendor-named servers set aside from around-the-CDN leads get one short reason (their vendors' domains and two example CNAMEs) instead of one per server joined together, and set-aside items with the same reason say it once, in the terminal and in the report. On PlayStation the same ~1,700-character paragraph was printed three times, once per CDN
- [x] v1.29.4: a host whose CNAME points at an AWS API Gateway endpoint (`d-….execute-api.<region>.amazonaws.com`) sits on Amazon's shared API front end, so its IP's banners and CVEs are Amazon's: it's a shared front door, set aside like AWS Global Accelerator. ServiceNow instances (`*.service-now.com`) are third-party hosting, and a CNAME to a vendor's bare domain (`mailgun.org`) counts like one under it. On PlayStation, an API Gateway IP had become "Exploit known flaws on 52.25.236.1", and a ServiceNow server a side-door lead

**Next**
- [ ] BBOT import, next steps: BBOT's scope distance as a setting, and capped recursion
- [ ] ffuf as an optional `--content` backend, for big wordlists on targets that allow a high rate: keeping Monomi's scope check, request log and per-host cap in front of it
- [ ] Fewer "non-production" false positives on names like `prod-...-demo`; the `--fingerprint` suggestion leaving out-of-scope hosts out of its count; Vercel's newer IPs (216.150.1.x, 216.198.79.x) labeled Vercel, not AWS
- [ ] Rule-based checks before the AI step
- [ ] Scheduled monitoring with alerts on new hostnames
- [ ] IP / IP-range input (`--ip`)

**Later**
- [ ] IP / CIDR rules in the scope file, and the full Public Suffix List
- [ ] HTTP-based takeover checks for wildcard services (GitHub Pages, S3, Heroku, Netlify)
- [ ] Liveness checks for discovered hosts
- [ ] Plugin system for data sources
- [ ] Per-target scan history (SQLite)
- [ ] HTML graph export
- [ ] Publish on PyPI (`pip install monomi`)
- [ ] Web interface

## Licensing

Copyright (c) 2026 0x41.

From v1.28.0 on, mønømi is licensed under the **GNU Affero General Public License v3.0 only** (AGPL-3.0-only); see [LICENSE](LICENSE). Versions before v1.28.0 were released under the MIT License and stay under it.

In short: you can use, study, change and share it. If you share a changed version, or run one as a network service other people use, you must make its source available to them under the same license. This is a summary; the LICENSE text is what counts.

Outside contributions need a contributor license agreement (CLA), so 0x41 can keep licensing the project as a whole. Open an issue and ask before sending a pull request.

---

Built by **0x41**.
