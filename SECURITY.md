# Security Policy

## Supported versions

Only the latest release of Monomi gets security fixes. Please update to the
newest version before reporting an issue.

| Version        | Supported |
| -------------- | --------- |
| Latest release | ✅        |
| Older releases | ❌        |

## Reporting a vulnerability

Please **don't open a public issue** for security problems.

Report it privately through GitHub instead:
**Security** tab → **Report a vulnerability**
(https://github.com/0x41io/monomi/security/advisories/new)

Include what you found, how to reproduce it, and the impact you expect.
You'll get a reply within **7 days**. Once a fix is ready, it ships in a new
release and you'll be credited in the release notes unless you'd rather not be.

## Scope

Monomi is **passive by default**: it reads public sources (Certificate
Transparency logs, DNS, Team Cymru, Shodan InternetDB, the Tor exit list) and
doesn't send traffic to the target. `--fingerprint` is the only active check
(one homepage request per host), and the MCP server mode is passive-only.

In scope:
- Bugs in Monomi's own code, e.g. untrusted data (hostnames, banners, DNS
  records, SpiderFoot imports) breaking out of the terminal output, the AI
  prompt, saved reports or JSON
- The MCP server exposing more than its passive tools, or skipping its input
  checks and limits
- Leaking secrets such as your `ANTHROPIC_API_KEY`

Out of scope:
- Vulnerabilities in third-party services Monomi queries (crt.sh, Cert Spotter,
  Shodan, Team Cymru, the Anthropic API). Report those to the service.
- Findings Monomi reports about a scanned target. Those belong to the target's
  owner.
- Using Monomi against systems you don't own or have permission to assess.
