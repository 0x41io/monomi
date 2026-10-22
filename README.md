# mønømi

```
 ██████╗ ██╗  ██╗██╗  ██╗ ██╗
██╔═████╗╚██╗██╔╝██║  ██║███║
██║██╔██║ ╚███╔╝ ███████║╚██║
████╔╝██║ ██╔██╗ ╚════██║ ██║
╚██████╔╝██╔╝ ██╗     ██║ ██║
 ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝   mønømi
```

**monomi** by 0x41: **passive domain reconnaissance with AI-written analysis.**

Most recon tools hand you a raw list of hostnames. Monomi collects a domain's public footprint and then has Claude explain it in plain English: how the infrastructure is organized, what deserves a closer look, and what the owner can do about it.

> ⚠️ **Authorized use only.** By default Monomi is fully passive: it reads public Certificate Transparency logs and never sends traffic to the target. The optional `--enrich` step adds standard DNS lookups, and `--fingerprint` is the one active check: a single homepage request per host. Only assess domains you own or have permission to review.
---

## Features
- **Subdomain discovery** from Certificate Transparency logs via two sources:
  - [crt.sh](https://crt.sh) (broadest coverage, includes expired certificates)
  - [Cert Spotter](https://sslmate.com/certspotter/) (currently valid certificates, more reliable)
- **Automatic fallback:** if one source is down, the scan continues with the other
- **Merged, de-duplicated results**
- **Hosting enrichment (`--enrich`):** resolves each host to its IP and looks up the network owner (ASN), provider, and country via Team Cymru's free IP-to-ASN service. Shows a host table, a hosting breakdown chart, and flags hosts that point to private/internal IPs in public DNS
- **Open ports and CVEs (`--ports`):** looks up each IP in [Shodan InternetDB](https://internetdb.shodan.io/) (free, no key, passive: Shodan's existing data, no traffic to the target). Flags risky internet-facing services (RDP, SMB, databases, Docker API), counts known CVEs, and separates shared CDN edge IPs (Cloudflare, Fastly, Akamai, Imperva, and AWS CloudFront, detected from [Amazon's published IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)) so their ports aren't blamed on the target. Only IPs that matter get a row
- **Hand-off to [kaidøku](https://github.com/0x41io/kaidoku) (`--cves FILE`):** saves every CVE found, ready for `python kaidoku.py --file FILE`
- **SpiderFoot import (`--import FILE`):** run Monomi on a [SpiderFoot](https://github.com/smicallef/spiderfoot) CSV export instead of querying certificate logs. Keeps the target's own hosts (with IPs, banners, ASNs; `--enrich` looks up current IPs fresh instead), separates third-party services, drops noisy modules (username/account checks, co-hosted sites, raw data), and passes SpiderFoot's flagged findings to the AI with their source module so weak reputation hits aren't reported as confirmed threats. Works with `--enrich`, `--ports` and `--ai`; doesn't touch scan history
- **Change detection:** every scan is saved and compared with the last one, flagging new and removed hostnames
- **AI analysis (optional):** Claude groups hosts by purpose (and by hosting provider when `--enrich` is on), flags names worth reviewing (High / Medium / Low), suggests defensive steps, and states the limits of the data
- **Evidence-backed findings:** before the AI step, Monomi's code turns the collected data into a numbered evidence list (E1, E2, ...), each item a plain fact with its source and UTC collection time. Every finding in the AI report cites the evidence it rests on (e.g. `[E12, E194]`) and is labeled **Observed**, **Inference** or **Lead**. After the report is written, Monomi checks every citation and warns if the AI cited evidence that doesn't exist. Saved reports end with an **Evidence** section listing each cited item, written by code, not by the AI
- **Formatted terminal reports:** the AI report renders in the terminal with colored headings, real tables, and High / Medium / Low badges (via [rich](https://github.com/Textualize/rich); plain Markdown if rich isn't installed or `--no-color` is set)
- **Saved reports:** each AI analysis is written to `reports/<domain>_<timestamp>.md`
- **JSON export** for use in other tools

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/0x41io/monomi.git
cd monomi
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### API key (only for `--ai`)

The AI analysis uses the Claude API. Get a key at [console.anthropic.com](https://console.anthropic.com), then:

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

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
3. **Worth reviewing:** prioritized hosts whose names suggest they may not need to be public
4. **Recommendations:** concrete defensive steps
5. **Limitations:** what passive data can and can't tell you
6. **Evidence:** every cited fact with its source and collection time, written by Monomi's code (not the AI)

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

## How it works

```
domain ──► crt.sh ───────┐
                         ├──► merge + de-duplicate ──► terminal / JSON
domain ──► Cert Spotter ─┘   (or SpiderFoot CSV    │
                              via --import)        ├──► DNS + ASN (--enrich)
                                                   ├──► Shodan InternetDB (--ports)
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
├── aws_ranges.py         # AWS CloudFront detection (Amazon's IP range list, cached daily)
├── evidence.py           # evidence list, citation check, Evidence section
├── history.py            # scan history + change detection
├── ui.py                 # colored banner + terminal output
├── common.py             # shared helpers: version, hostname checks, timestamps
├── collectors/
│   ├── crtsh.py          # crt.sh collector (with retries)
│   └── certspotter.py    # Cert Spotter collector (with pagination)
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
- crt.sh and Cert Spotter are free services and are sometimes slow or rate-limited.

## Development

Install the dev requirements and run the test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

The tests cover hostname filtering, domain cleaning, evidence citation checks and change detection. They run offline in under a second.

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

**Next**
- [ ] Email spoofing check (SPF / DKIM / DMARC)
- [ ] Subdomain takeover / dangling DNS detection
- [ ] Rule-based checks before the AI step
- [ ] HTML report
- [ ] Scheduled monitoring with alerts on new hostnames
- [ ] IP / IP-range input (`--ip`)

**Later**
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
