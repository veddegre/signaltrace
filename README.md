# SignalTrace Tracking & Analysis

<p align="center"> 
  <img src="docs/images/signaltrace_transparent.png" alt="SignalTrace — Signal Trace Tracking & Analysis" width="160"> 
</p> 

<p align="center"> 
  <img src="https://img.shields.io/badge/PHP-8.1%2B-blue" alt="PHP"> 
  <img src="https://img.shields.io/badge/Database-SQLite-lightgrey" alt="SQLite"> 
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"> 
  <img src="https://img.shields.io/badge/Threat%20Intel-MISP%20%7C%20STIX%202.1-red" alt="Threat Intel">
  <img src="https://img.shields.io/badge/Splunk-Ready-black" alt="Splunk">
  <img src="https://img.shields.io/badge/Grafana-Ready-orange" alt="Grafana">
  <img src="https://github.com/veddegre/signaltrace/actions/workflows/docker-image.yml/badge.svg" alt="Docker Build">
</p>

<p align="center">
  SignalTrace Tracking & Analysis for honeypots, links, and request intelligence.
</p>

<p align="center">
  Designed for SOC workflows, phishing simulations, and real-time threat intelligence generation.
</p>

SignalTrace is a self-hosted tracking and analysis platform for honeypot deployment, link tracking, and security visibility. It logs every interaction with custom paths, scores each request for bot or human likelihood, and makes the results immediately usable for investigation, automation, or SIEM integration.

SignalTrace also supports campaigns — grouping multiple tokens into a single operational context. This allows activity across links and pixels to be correlated, filtered, and alerted on as a single scenario.

It runs on Docker or bare metal with no external services required.

Includes built-in Splunk dashboards, a Grafana dashboard, and SIEM-ready export endpoints.

**Project Website:** [www.trysignaltrace.com](https://www.trysignaltrace.com)

---

## Demo

A quick look at real-time scoring, behavioral detection, and threat feed generation:

https://github.com/user-attachments/assets/d9f85e24-fdff-4ebf-ba0a-2546e9bb3b12

---

## Live Demo

A live instance is running at [trysignaltrace.com/admin](https://trysignaltrace.com/admin) and capturing real traffic. Every scanner, bot, and automated probe that hits it is scored in real time.

* **Username:** `demo`
* **Password:** `trysignaltrace`

*Note: The demo resets every 60 minutes. All data is sample/live traffic only — no real credentials or sensitive data are present.*

---

## Why SignalTrace

Most tracking tools tell you *that* something hit an endpoint. SignalTrace tells you *what kind of thing* hit it, how confident the assessment is, and why — with enough detail to act on immediately or pipe into a SIEM.

SignalTrace provides real-time, explainable scoring — every classification is backed by named detection signals, not black-box logic.

Every hit gets a 0–100 human-likelihood score with named signal reasons. The built-in threat feed at `/feed/ips.txt` is ready to consume from a firewall or block list. The JSON and CSV export endpoints support token-based authentication for scheduled Splunk ingestion.

SignalTrace also supports campaigns, allowing multiple tokens to be grouped into a single operational context for correlation, filtering, and alerting.

**Use cases:** phishing simulations, campaign-based tracking, honeypot deployments, recon detection, link tracking, and threat feed generation.

---

## How it works (high-level)

SignalTrace processes every request in real time:

1. Request is logged and enriched (IP, ASN, GeoIP headers)
2. Detection signals are applied
3. A score (0–100) is calculated
4. Classification is assigned (bot → human)
5. Results are immediately available via dashboard, feed, or API
6. Results can be grouped and analyzed at the campaign level for correlation across multiple tokens

---

## Requirements

SignalTrace is designed to run on minimal hardware.

A 1 vCPU VM with 1 GB RAM and swap enabled is sufficient. Plan for 5–10 GB of disk depending on how much traffic you log.

**Software requirements:** PHP 8.1+, SQLite3, Apache with mod_rewrite, Composer.

---

## Quick Start with Docker

```bash
git clone https://github.com/veddegre/signaltrace.git
cd signaltrace
cp .env.example .env
# Edit .env with your settings
docker compose up -d
```

Or use the pre-built image:

```bash
cp docker-compose.prebuilt.yml docker-compose.yml
cp .env.example .env
# Edit .env with your settings
docker compose up -d
```

The admin panel will be available at `http://localhost/admin` by default. In production deployments, access it via your configured domain (e.g. `https://your-domain/admin`).

---

## Manual Installation

```bash
git clone https://github.com/veddegre/signaltrace.git
cd signaltrace
bash setup.sh
```

`setup.sh` walks through all required configuration including SMTP credentials if you want email alerting. When an existing `config.local.php` is found, the script offers Update / Overwrite / Abort so you can re-run it safely on an existing install.

---

## Configuration

All secrets and environment-specific settings live in `includes/config.local.php`. This file is never committed. See `includes/config.local.php.example` for the full list of constants.

### Environment Variables (.env for Docker)

| Variable | Required | Description |
|---|---|---|
| `ADMIN_USER` | Yes | Admin username |
| `ADMIN_PASS` | Yes | Admin password (stored as bcrypt hash) |
| `APP_NAME` | No | Display name (default: SignalTrace) |
| `BASE_URL` | No | Public base URL (e.g. https://your-domain.example) |
| `DEFAULT_REDIRECT_URL` | No | Redirect destination for unknown paths |
| `VISITOR_HASH_SALT` | Yes | Salt for visitor fingerprint hashing |
| `EXPORT_API_TOKEN` | No | Bearer token for export and feed endpoints |
| `TRUSTED_PROXY_IP` | No | Upstream proxy IP for XFF trust |
| `DEMO_MODE` | No | Set to `true` to enable demo mode |
| `DEMO_ADMIN_USERNAME` | No | Demo mode username override |
| `DEMO_ADMIN_PASSWORD` | No | Demo mode password override |
| `CF_ACCESS_ENABLED` | No | Set to `true` to enable Cloudflare Access verification |
| `CF_ACCESS_AUD` | No | Cloudflare Access Application Audience tag |
| `CF_ACCESS_TEAM_DOMAIN` | No | Cloudflare Zero Trust team domain |
| `EMAIL_SMTP_HOST` | No | SMTP server hostname |
| `EMAIL_SMTP_PORT` | No | SMTP port (default: 587) |
| `EMAIL_SMTP_ENCRYPTION` | No | `tls`, `ssl`, or `none` (default: tls) |
| `EMAIL_SMTP_USER` | No | SMTP username |
| `EMAIL_SMTP_PASS` | No | SMTP password |
| `EMAIL_SMTP_FROM` | No | From address (defaults to SMTP username) |

SMTP credentials are written by the Docker entrypoint into `config.local.php` as PHP constants. They are never stored in the database or exposed through the admin UI.

---

## Features at a Glance

* **Tracking:** custom tokens with redirect, full request logging, visitor fingerprinting, tracking pixel, GeoIP enrichment.
* **Admin dashboard:** paginated activity feed, expandable request details, per-IP summary panel with VT/Abuse/Info links and Block/Allow actions, date range filtering, classification badges with scores, bulk delete by filter, dark mode, mobile layout.
* **Campaigns:** group tokens into a single tracking scenario with aggregated stats (total hits, unique visitors, first/last hit), campaign-level activity filtering, and webhook fallback.
* **IP Reputation:** inline enrichment from Shodan InternetDB (open ports, CVEs, tags — no API key) and AbuseIPDB (abuse confidence, report history — optional free key). Cached permanently on first sight. Rescan button for on-demand refresh.
* **Signal reason labels:** confidence signals displayed as color-coded pill tags with friendly descriptions.
* **Token management:** create/edit/activate/deactivate/delete, per-token feed exclusion, force-include tokens, per-token webhook opt-in, per-token email opt-in, pixel URL generation, and campaign assignment.
* **ASN rules:** scoring penalties, feed exclusion, edit in place.
* **Country rules:** per-country score penalties by ISO code.
* **IP overrides:** pin any IP to always-block (bot) or always-allow (human), bypasses scoring entirely.
* **Behavioral flagging:** dashboard panel showing IPs that triggered burst, rapid-repeat, or multi-token signals. Configurable window, max rows, and hide-by-default.
* **Skip patterns:** exact, contains, and prefix matching to suppress known noise.
* **Threat feed:** ten endpoints covering IPv4 and IPv6 in plain text, Nginx deny, iptables, CIDR, MISP event, and STIX 2.1 bundle formats.
* **Threat webhook:** fires when an unknown-path hit meets the configured classification threshold. Platform presets for Slack, Discord, Teams, PagerDuty, and custom JSON. Inline test button. Custom payload templates with `{{placeholder}}` syntax.
* **Token webhook:** fires when a known tracked token is hit. Per-token opt-in, with campaign-level fallback when a token is not opted in but belongs to a campaign with webhook enabled.
* **Email alerting:** plain text SMTP alerts for threats and tracked token hits. Per-token opt-in. Configurable threshold and deduplication window.
* **Redirect rate limiting:** per IP per token, configurable count and window.
* **Cleanup tools:** delete by token, IP, filter, or unknown-token hits.
* **Data retention:** configurable retention window with manual trigger and automatic cleanup.
* **Wildcard DNS mode:** subdomain column, host filter, and subdomain activity panel for wildcard DNS honeypots.
* **Grafana integration:** pre-built 16-panel dashboard using the Infinity datasource with nine aggregation export endpoints.
* **Splunk integration:** scripted input with incremental fetching, two Dashboard Studio dashboards, props.conf with CIM field aliases and multivalue signal splitting.
* **MISP and STIX 2.1 export:** threat intelligence exports for consumption by TI platforms.
* **Cloudflare Access:** optional identity layer using Cloudflare Zero Trust.

---

## Export API

All export endpoints require authentication via `Authorization: Bearer YOUR_TOKEN` or `?api_key=YOUR_TOKEN`. Set `EXPORT_API_TOKEN` in `config.local.php`.

| Endpoint | Description |
|---|---|
| `/export/json` | Full event export with filters |
| `/export/csv` | CSV export with filters |
| `/export/stats` | Summary statistics |
| `/export/stats/extended` | Summary with top countries and orgs |
| `/export/by-ip` | Top IPs by hit count |
| `/export/by-country` | Hits by country |
| `/export/by-token` | Hits by token (supports `?label=` filter) |
| `/export/by-org` | Hits by ASN organisation |
| `/export/by-signal` | Detection signal hit counts |
| `/export/behavioral` | IPs with behavioral signals |
| `/export/over-time` | Hourly event counts |

All aggregation endpoints accept `?from=` and `?to=` as Unix millisecond timestamps.

---

## Threat Feed

| Endpoint | Format |
|---|---|
| `/feed/ips.txt` | Plain text IPv4, one per line |
| `/feed/ips.nginx` | Nginx deny rules |
| `/feed/ips.iptables` | iptables-restore format |
| `/feed/ips.cidr` | CIDR /32 notation |
| `/feed/ipv6.txt` | Plain text IPv6 |
| `/feed/ipv6.nginx` | Nginx deny rules (IPv6) |
| `/feed/ipv6.iptables` | iptables-restore (IPv6) |
| `/feed/ipv6.cidr` | CIDR /128 notation |
| `/feed/misp.json` | MISP event format |
| `/feed/stix.json` | STIX 2.1 bundle |

---

## Security

`config.local.php` is never committed and contains all secrets. Passwords are stored as bcrypt hashes. All SQL uses parameterised queries. URL destinations are validated against an http/https allowlist.

Admin login has rate limiting with a configurable lockout threshold and window. CSRF tokens protect all admin POST forms. Security response headers (CSP with per-request nonce, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are sent on every response. Webhooks block private and loopback IP ranges to prevent SSRF. The export API token is compared in constant time.

---

## Production Checklist

- [ ] Enable HTTPS
- [ ] Set strong admin credentials and a unique visitor hash salt
- [ ] Configure `AUTH_MAX_FAILURES` and `AUTH_LOCKOUT_SECS`
- [ ] Set `TRUSTED_PROXY_IP` if running behind a reverse proxy
- [ ] Download GeoIP databases with `geoipupdate`
- [ ] Verify only `public/` is web-accessible
- [ ] Configure skip patterns to suppress known noise
- [ ] Add ASN rules for infrastructure you own or trust
- [ ] Add country rules for high-noise regions if applicable
- [ ] Add IP overrides to permanently block known bad actors or allow your own monitoring IPs
- [ ] Set feed exclusions on tokens and ASNs that should never appear in your blocklist
- [ ] Tune the threat feed confidence threshold, time window, and minimum hit count
- [ ] Set `EXPORT_API_TOKEN` and configure your SIEM integration if applicable
- [ ] Add a weekly `geoipupdate` cron job
- [ ] Configure a threat webhook URL and threshold for real-time bot alerts
- [ ] Configure a token webhook for phishing simulation and campaign tracking if needed
- [ ] Add an AbuseIPDB API key in Settings > IP Enrichment for abuse confidence scores
- [ ] Review redirect rate limit settings
- [ ] Consider enabling Cloudflare Access for per-user identity and MFA

---

## Tech Stack

Ubuntu 24.04, PHP 8.1+, SQLite via PDO, Apache with mod_rewrite, MaxMind GeoLite2. Docker and Docker Compose supported with a guided `setup.sh` script. A pre-built Docker image is published to `ghcr.io/veddegre/signaltrace` via GitHub Actions on every push to `main`. A Splunk integration with scripted input and two Dashboard Studio dashboards is included under `splunk/`. A pre-built Grafana dashboard using the Infinity datasource is included under `grafana/`.

---

## Contributing

Contributions are welcome. Read `CONTRIBUTING.md` before opening a pull request.

Found a bug? Use the bug report issue template. Have a feature idea? Open an issue to discuss it before building. Found a security vulnerability? See `SECURITY.md` for responsible disclosure — please don't open a public issue.

If SignalTrace is useful to you, starring the repository on GitHub helps others find it.

---

## Maintainer

SignalTrace is developed and maintained by Greg Vedders. You can find more of my technical write-ups, projects, and other writing on my personal blog at [gregvedders.com](https://gregvedders.com).

---

## Disclaimer

SignalTrace is designed for security visibility and authorised testing. It will attract scanners, bots, and automated systems by design. Use it with awareness of your environment and risk tolerance.

---

## License

MIT

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

> *Most tools try to hide the noise. SignalTrace makes it visible.*
