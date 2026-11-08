<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/0x41io/monomi/main/assets/monomi-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/0x41io/monomi/main/assets/monomi-light.png">
    <img src="https://raw.githubusercontent.com/0x41io/monomi/main/assets/monomi-banner.png" alt="mønømi by 0x41" width="420">
  </picture>
</p>

**mønømi: passive attack surface recon and IP threat-intel, with AI-written analysis and an MCP server, by 0x41.**

Most recon tools hand you a raw list of hostnames. Monomi collects a domain's public footprint and then has Claude explain it in plain English: how the infrastructure is organized, what deserves a closer look, how an attacker would most likely get in, and who should fix what first.

> ⚠️ **Authorized use only.** By default Monomi is fully passive: it reads public Certificate Transparency logs and never sends traffic to the target. The optional `--enrich`, `--email` and `--takeover` steps add standard DNS lookups, and `--fingerprint` is the one active check: a single homepage request per host. Only assess domains you own or have permission to review.
---

## Features
- **Subdomain discovery** from Certificate Transparency logs via three sources, asked in parallel:
  - [crt.sh](https://crt.sh) website (broadest coverage, includes expired certificates)
  - crt.sh's public certificate database (same data as the website, queried directly over PostgreSQL; often answers when the website is slow or down)
  - [Cert Spotter](https://sslmate.com/certspotter/) (currently valid certificates, more reliable; waits and retries when rate-limited)
- **Automatic fallback:** if a source is down, the scan continues with the others. A scan is only left out of history when both crt.sh sources fail, since crt.sh is the only one with full certificate history
- **Saved source copies:** every good answer from a source is saved per domain (`scans/<domain>/sources/`). If that source fails on a later run, Monomi uses the saved copy (up to 30 days old) and labels it `from_saved` with its original collection time, so an outage only costs fresh data, not the hosts found before
- **Shared pacing:** crt.sh (5 requests a minute) and Cert Spotter's free tier are paced across every run and domain, so multi-domain sweeps stay under their limits. After Cert Spotter rate-limits, it is skipped for the rest of the cooldown instead of failing on every domain
- **Honest source status:** when the crt.sh database answers with 0 certificates while another source found some, crt.sh is reported as **behind** (it can take days to index new certificates), not as failed
- **Merged, de-duplicated results**
- **Hosting enrichment (`--enrich`):** resolves each host to its IP and looks up the network owner (ASN), provider, and country via Team Cymru's free IP-to-ASN service. Shows a host table, a hosting breakdown chart, and flags hosts that point to private/internal IPs in public DNS. Hosts with no IPv4 address get a second DNS look that says why: **no_such_host** (the name doesn't exist, double-checked with two DNS-over-HTTPS servers, Cloudflare and Google), **dangling_cname** (a CNAME pointing to a deleted name), **ipv6_only**, **no_address** (the name exists but has no address, often a retired host), **conflicting** (system DNS and DNS-over-HTTPS disagree, so it's unknown), **servfail** (the DNS servers tried but couldn't get an answer, even after a retry: often a broken zone or a rate limit) or **lookup_failed**. Every check uses the same DNS helper and the same status words
- **Open ports and CVEs (`--ports`):** looks up each IP in [Shodan InternetDB](https://internetdb.shodan.io/) (free, no key, passive: Shodan's existing data, no traffic to the target). Flags risky internet-facing services (RDP, SMB, databases, Docker API), counts known CVEs, and separates shared CDN edge IPs (Cloudflare, Fastly, Akamai, Imperva, Vercel, and AWS CloudFront, detected from [Amazon's published IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)) so their ports aren't blamed on the target. Edge IPs are also caught from Shodan's service fingerprints (CPEs), which finds Cloudflare and Okta on IP ranges they don't own, and each one says why it was flagged (`edge_reason`). A hostname whose CNAME points to an edge service (CloudFront, Okta, Fastly, Akamai, Cloudflare, Imperva, Azure Front Door, Vercel) also marks its IPs as edge. Only IPs that matter get a row
- **Hand-off to [kaidøku](https://github.com/0x41io/kaidoku) (`--cves FILE`):** saves every CVE found, ready for `python kaidoku.py --file FILE`
- **Web tech + security headers (`--fingerprint`, active):** one homepage request per live host reads headers like Server and X-Powered-By to spot web servers, frameworks and exposed versions, and checks the same response for missing or weak security headers (HSTS, CSP, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy). Hosts that redirect aren't judged, and the header check makes no extra requests
- **Email spoofing check (`--email`):** looks up the domain's SPF, DMARC and DKIM records (DNS lookups only, nothing sent to the target's servers) and gives one verdict: **protected**, **partial** or **spoofable**. DMARC decides the verdict, so an SPF `~all` softfail isn't flagged when DMARC enforces. DKIM is checked under common selector names, and a key that isn't found is reported as "not confirmed", never "missing". If the system's DNS can't answer (WSL's DNS relay often times out on TXT lookups), Monomi retries with public DNS (Cloudflare, then Google)
- **Subdomain takeover check (`--takeover`):** for every hostname, follows its CNAME and flags it if the target no longer exists (DNS lookups only). A dead target on a service that lets deleted names be claimed again (Azure App Service, Blob Storage, Traffic Manager, CDN and others, plus AWS Elastic Beanstalk) is a **takeover lead**; a dead target anywhere else is a **dangling CNAME** (worth checking, e.g. an expired domain someone could buy). A dead target on a service whose names can never be claimed again (AWS load balancers, CloudFront) is marked **stale**: an old DNS record worth cleaning up, not a takeover risk. A dead target inside the scanned domain itself is also **stale**, since only the domain's owner can create that name. Monomi never tries to claim anything, so leads stay leads
- **IP threat-intel (`--investigate-ip`):** look into suspicious IPs from logs or alerts (up to 20 per run): is each one a Tor exit, VPN/proxy, hosting/cloud server or CDN edge? Checks the Tor Project's exit list, the network owner (ASN) via Team Cymru, reverse DNS and Shodan InternetDB, then Monomi's rules put labels on each IP, and every label names its source and reason. CVEs Shodan saw on a CDN edge IP come with a note that they most likely belong to another site behind it. Passive: asks public sources about the IP and never contacts the IP itself. Private and junk input is rejected with a reason. With `--ai`, Claude writes a verdict with a confidence level based on how many sources agree, cites the evidence, and never claims where a person is or who they are: a country is where the network is registered, not where its user is
- **SpiderFoot import (`--import FILE`):** run Monomi on a [SpiderFoot](https://github.com/smicallef/spiderfoot) CSV export instead of querying certificate logs. Keeps the target's own hosts (with IPs, banners, ASNs; `--enrich` looks up current IPs fresh instead), separates third-party services, drops noisy modules (username/account checks, co-hosted sites, raw data), and passes SpiderFoot's flagged findings to the AI with their source module so weak reputation hits aren't reported as confirmed threats. Works with `--enrich`, `--ports` and `--ai`; doesn't touch scan history
- **Change detection:** every scan is saved and compared with the last one, flagging new and removed hostnames
- **AI analysis (optional):** Claude groups hosts by purpose (and by hosting provider when `--enrich` is on), flags names worth reviewing (High / Medium / Low), suggests defensive steps, and states the limits of the data
- **Evidence-backed findings:** before the AI step, Monomi's code turns the collected data into a numbered evidence list (E1, E2, ...), each item a plain fact with its source and UTC collection time. Every finding in the AI report cites the evidence it rests on (e.g. `[E12, E194]`) and is labeled **Observed**, **Inference** or **Lead**. After the report is written, Monomi checks every citation and warns if the AI cited evidence that doesn't exist. Saved reports end with an **Evidence** section listing each cited item, written by code, not by the AI
- **Attack paths:** Monomi's code chains findings into the ways an attacker would most likely try to get in: a claimable subdomain takeover (made worse when the domain's email is spoofable), email impersonation, services that shouldn't face the internet, known-vulnerable versions, and non-production hosts sharing a server with production. Every step cites evidence and is labeled Observed / Inference / Lead by code, and a path is only as strong as its weakest step. The paths print at the end of every scan that ran a check, with no AI needed. With `--ai`, Claude writes them up in a report section of their own, but can't add, drop or reorder a path or change a label, and Monomi checks the report afterwards. If nothing chains, the answer is "no attack path found", never an invented one
- **Owners and "fix this first":** every finding carries the roles that would fix it (DNS admin, email admin, web app team, CDN / proxy admin, server / infrastructure admin, cloud / service account owner), worked out by code and never naming people. Recommendations start with their owner, and the report leads with the one fix that closes the most attack paths
- **Known hostnames (`--hosts FILE`):** check hostnames you already know alongside the ones from certificate logs, one per line. Only the target domain and its subdomains are kept, so a file can't point Monomi outside the scan, and the file's hosts stay out of scan history
- **Formatted terminal reports:** the AI report renders in the terminal with colored headings, real tables, and High / Medium / Low badges (via [rich](https://github.com/Textualize/rich); plain Markdown if rich isn't installed or `--no-color` is set)
- **Saved reports:** each AI analysis is written to `reports/<domain>_<timestamp>.md`
- **JSON export** for use in other tools
- **MCP server mode (passive-only):** run Monomi as an MCP server so AI agents can call its checks directly. Seven tools cover subdomain discovery with hostname categories, host enrichment, ports/CVEs, email spoofing, takeover checks, and suspicious-IP investigation. `find_subdomains` labels each hostname with a category (non-production, legacy, access, iot-ot, partner-portal, internal-tools and more), and `check_ports` starts with a summary: CDN edge vs origin IPs, CVEs and risky ports on origin IPs only, hostnames that don't resolve, and IPs Shodan has no data on. Findings carry their owners, and inputs that aren't hostnames (pasted links, URLs, wildcards) come back in `rejected` with the reason. Replies are short summaries by default, with the full result saved to a file, and tools pass hosts to each other as files instead of long hostname lists, so big scans don't fill the agent's context.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/0x41io/monomi.git
cd monomi
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Installing on Windows

Monomi runs on Windows without WSL. In PowerShell:

```powershell
python --version                # must be 3.10 or newer
git clone https://github.com/0x41io/monomi.git
cd monomi
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If something goes wrong:
- **`python` isn't found, or opens the Microsoft Store:** install Python from python.org (tick **"Add python.exe to PATH"**). If `python` still opens the Store or runs an old version, open **Settings > Apps > Advanced app settings > App execution aliases**, turn off the "App Installer" and older Python entries for `python.exe` / `python3.exe`, and turn on the new ones. Then open a new PowerShell window.
- **"running scripts is disabled on this system"** when activating: run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate again.
- **The prompt shows `(venv)` but the command isn't found:** another venv is active. Run `deactivate`, then activate the one inside the `monomi` folder.

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

# Check email spoofing protection (SPF, DMARC, DKIM; DNS lookups only)
python monomi.py example.com --email

# Check for dangling CNAMEs / subdomain takeover leads (DNS lookups only)
python monomi.py example.com --takeover

# Also check hostnames you already know (one per line), e.g. ones certificate logs miss
python monomi.py example.com --takeover --hosts known-hosts.txt

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

# Plain output, no colors (also honors the NO_COLOR env var)
python monomi.py example.com --no-color
```

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

Monomi can also run as an MCP server, so AI agents (like the Claude app) can call its checks directly. It's a second way in alongside the CLI, and **passive-only**: no active scanning is exposed over MCP.

Tools: `ping`, `find_subdomains` (with hostname categories), `enrich_hosts`, `check_ports`, `check_email_auth`, `check_takeover`, `investigate_ip` (suspicious IPs, up to 10 per call). Results with something to fix carry `owners`: the roles that would fix them.

Every call is built to fit the Claude app's 60-second tool limit: `find_subdomains` gives its sources 45 seconds in total, returns whatever finished, and lists skipped sources in `errors`.

**Summary replies (v1.9).** `find_subdomains`, `check_takeover`, `enrich_hosts` and `check_ports` take `detail="summary"` (the default) or `detail="full"`. A summary gives the counts plus the hosts that matter (risky categories, takeover leads and stale records, dangling CNAMEs, origin IPs), and saves the full result to `scans/mcp/` as `full_results_file`. Use `detail="full"` to get everything in the reply.

**Passing hosts as a file.** Instead of copying hostnames into the next tool, pass `find_subdomains`' `full_results_file` (or a `.txt` list, one host per line) as `hosts_file` to `check_takeover`, `enrich_hosts` or `check_ports`. Only files inside Monomi's `scans/` folder are accepted, so an agent can't point a tool at other files on your machine. Big files are checked in batches (200 hosts, 100 for `check_ports`): call again with `start` set to the reply's `batch.next_start` until it is `null`.

```
find_subdomains(domain="example.com")
  -> full_results_file: ".../scans/mcp/..._find_subdomains.json"
check_takeover(hosts_file="<that file>", domain="example.com")
check_ports(hosts_file="<that file>")
```

Add Monomi to your MCP client's config:

```json
{
  "mcpServers": {
    "monomi": {
      "command": "/path/to/monomi/venv/bin/python",
      "args": ["/path/to/monomi/mcp_server.py"]
    }
  }
}
```
## How it works

```
domain ──► crt.sh website ───┐
domain ──► crt.sh database ──┼──► merge + de-duplicate ──► terminal / JSON
domain ──► Cert Spotter ─────┘   (or SpiderFoot CSV    │
                                  via --import)        ├──► DNS + ASN (--enrich)
                                                       ├──► Shodan InternetDB (--ports)
                                                       ├──► email / takeover / fingerprint checks
                                                       └──► evidence ──► attack paths (code)
                                                                              └──► Claude (--ai) ──► Markdown report
```

Certificate Transparency (CT) is a public log of every TLS certificate issued by trusted authorities. Certificates list the hostnames they cover, so CT logs reveal subdomains an organization has requested certificates for, without touching the organization's servers.

## Project structure

```
monomi/
├── monomi.py             # CLI entry point
├── analysis.py           # Claude analysis layer
├── enrich.py             # DNS + ASN/provider enrichment
├── internetdb.py         # Shodan InternetDB: open ports + CVEs per IP
├── fingerprint.py        # HTTP header fingerprinting (--fingerprint, active)
├── headers.py            # security headers check (reads the --fingerprint response)
├── categorize.py         # rule-based hostname categories
├── mcp_server.py         # MCP server mode (7 passive tools)
├── emailauth.py          # email spoofing check: SPF, DMARC, DKIM + verdict (--email)
├── takeover.py           # dangling CNAME / subdomain takeover check (--takeover)
├── threatintel.py        # IP threat-intel: Tor list, ASN, reverse DNS, Shodan, labels (--investigate-ip)
├── aws_ranges.py         # AWS CloudFront detection (Amazon's IP range list, cached daily)
├── evidence.py           # evidence list, owners, citation check, Evidence section
├── paths.py              # attack paths built from the evidence, "fix this first"
├── dnscheck.py           # shared DNS helper: status words, DNS-over-HTTPS double-check
├── history.py            # scan history + change detection
├── ui.py                 # colored banner + terminal output
├── common.py             # shared helpers: version, hostname checks, timestamps
├── collectors/
│   ├── crtsh.py          # crt.sh collector (with retries)
│   ├── crtsh_db.py       # crt.sh database collector (PostgreSQL)
│   ├── certspotter.py    # Cert Spotter collector (pagination, rate-limit retry)
│   ├── pacing.py         # shared request pacing for crt.sh and Cert Spotter
│   └── saved.py          # saved per-domain copies of each source, used when a source fails
├── importers/
│   └── spiderfoot.py     # SpiderFoot CSV export parser
├── scans/                # saved scans per domain (git-ignored)
├── reports/              # generated reports (git-ignored)
├── cache/                # cached AWS IP range list (git-ignored)
├── tests/                # pytest suite (run: pytest)
├── pytest.ini            # pytest settings
├── requirements.txt
└── requirements-dev.txt  # requirements + pytest, for development
```

## Limitations

- CT logs only show hosts that have had TLS certificates; hosts behind wildcard certificates or without TLS won't appear.
- A hostname appearing in CT logs doesn't mean it's currently live. `--enrich` shows which ones still have DNS records, but a DNS record doesn't prove a server is up.
- AI analysis only sees what Monomi collected (hostnames, plus DNS/hosting, Shodan or SpiderFoot data when those options are used). Every finding cites numbered evidence and is labeled Observed / Inference / Lead, but treat findings as leads to verify, not confirmed issues. The citation check confirms that every cited evidence ID exists; it can't prove an ID fully supports the sentence, so spot-check important findings against the report's Evidence section.
- `--fingerprint` only sees the homepage of each host over HTTPS. Behind a CDN (Cloudflare, Vercel, Fastly) it mostly sees the CDN, not the origin server, and many servers hide their versions.
- The security headers check only judges hosts that served a real page (HTTP 2xx), and only the homepage. Other pages can send different headers, and a missing header is a missing defense, not a confirmed vulnerability.
- `--email` checks DKIM only under common selector names (Google, Microsoft 365, Mailchimp, SendGrid, Cloudflare and a few generic ones), because DNS can't list selectors. A domain using a custom selector will show DKIM as "not confirmed" even if it's set up.
- `--takeover` only catches services where a deleted resource's name stops resolving in DNS. Services that answer for every name (GitHub Pages, S3, Heroku, Netlify) need an HTTP check to spot a takeover, and aren't covered yet.
- A takeover `no_cname` status only means DNS returned no CNAME record. Some DNS providers (e.g. Cloudflare) answer the same way for names that don't exist, so it doesn't prove a host is live.
- `--investigate-ip` only uses free public sources. The Tor exit list is authoritative, but VPN and proxy labels come from reverse DNS names and Shodan tags, so many commercial VPNs won't be caught; "no anonymizer found" doesn't prove there isn't one. A country is where the network is registered, never where the person using the IP is.
- crt.sh (website and database) and Cert Spotter are free services and are sometimes slow or rate-limited. Over MCP, sources still running after 45 seconds are skipped so the call fits the Claude app's tool limit. Pacing keeps sweeps under the limits, so a big multi-domain sweep runs slower on purpose.
- crt.sh can fall days behind the CT logs, so a new domain may show 0 crt.sh results while Cert Spotter finds certificates. Monomi reports this as **behind** and doesn't save a history baseline until crt.sh catches up, so hosts aren't later flagged as new by mistake.
- A saved source copy is only used when the live source fails, and it can be up to 30 days old: hosts added or removed since then won't show.
- Some DNS providers (Cloudflare among them) never say a name doesn't exist, so a retired hostname on those zones shows as **no_address**, not **no_such_host**.
- DNS answers are cached. Right after a DNS change, a name that was looked up before it existed can still read as **no_such_host** until the zone's negative-cache time runs out (often up to 30 minutes), and a deleted record can keep resolving until its TTL runs out.
- Attack paths come from fixed rules applied to what the scan saw. A path shows how an attack would most likely go, not proof that it works, and "no attack path found" means no rule matched, not that the target is safe. Paths are only as complete as the checks that ran.

## Development

Install the dev requirements and run the test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

The tests cover hostname filtering, domain cleaning, evidence citation checks, change detection, the email check, the takeover check (using fake DNS records), the IP threat-intel labels, owners and the attack-path rules.

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

**Next**
- [ ] v1.9.2: report exports (Markdown, HTML, findings CSV), `monomi doctor` (API keys, source reachability), `monomi mcp setup`
- [ ] v1.10: finds more: subfinder import and a free passive DNS source for subdomain breadth, a "go around the CDN" attack path, next-check suggestions, security header and exposed API spec checks over MCP
- [ ] Rule-based checks before the AI step
- [ ] Scheduled monitoring with alerts on new hostnames
- [ ] IP / IP-range input (`--ip`)

**Later**
- [ ] HTTP-based takeover checks for wildcard services (GitHub Pages, S3, Heroku, Netlify)
- [ ] Liveness checks for discovered hosts
- [ ] Plugin system for data sources
- [ ] Per-target scan history (SQLite)
- [ ] HTML graph export
- [ ] Installable package (`pip install monomi`)
- [ ] Web interface

## License

MIT. See [LICENSE](LICENSE).

---

Built by **0x41**.
