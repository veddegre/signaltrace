# SignalTrace Tracking & Analysis

<p align="center"> 
  <img src="docs/images/signaltrace_transparent.png" alt="SignalTrace — Signal Trace Tracking & Analysis" width="160"> 
</p> 

<p align="center"> 
  <img src="https://img.shields.io/badge/PHP-8.1%2B-blue" alt="PHP"> 
  <img src="https://img.shields.io/badge/Database-SQLite-lightgrey" alt="SQLite"> 
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"> 
  <img src="https://img.shields.io/badge/Email-PHPMailer-orange" alt="PHPMailer">
  <img src="https://img.shields.io/badge/Intel-MISP%20%7C%20STIX%202.1-purple" alt="Threat Intel">
  <img src="https://github.com/veddegre/signaltrace/actions/workflows/docker-image.yml/badge.svg" alt="Docker Build">
</p>

<p align="center">
  Self-hosted honeypot, link tracker, and threat intelligence platform with real-time bot scoring, SIEM integration, and structured threat feed export.
</p>

<p align="center">
  Designed for SOC workflows, phishing simulations, and real-time threat intelligence generation.
</p>

SignalTrace is a self-hosted tracking and analysis platform for honeypot deployment, link tracking, and security visibility. It logs every interaction with custom paths, scores each request for bot or human likelihood, and makes the results immediately usable for investigation, automation, or SIEM integration.

No external services required. One PHP app, one SQLite database, one Apache vhost.

Includes built-in Splunk dashboards, a Grafana dashboard, SIEM-ready export endpoints, MISP and STIX 2.1 threat intel exports, and optional email alerting via SMTP.

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

### Running your own demo instance

Set `define('DEMO_MODE', true);` in `includes/config.local.php` to enable the demo banner. The banner is included in the repository at `includes/demo-banner.php` and is inert unless `DEMO_MODE` is explicitly enabled — it has no effect on standard installs.

When `DEMO_MODE` is true, the banner displays at the top of every admin page. If a `data/.last_reset` file exists containing a Unix timestamp, a live countdown to the next reset is shown. If the file does not exist the banner degrades gracefully and shows static text. The reset mechanism itself is not included in the repository and is left to the operator to implement.

See the [Demo Mode wiki page](https://github.com/veddegre/signaltrace/wiki/Demo-Mode) for full setup instructions including the reset script, cron configuration, and locked settings.

## Why SignalTrace

Most tracking tools tell you *that* something hit an endpoint. SignalTrace tells you *what kind of thing* hit it, how confident the assessment is, and why — with enough detail to act on immediately or pipe into a SIEM.

SignalTrace provides real-time, explainable scoring — every classification is backed by named detection signals, not black-box logic.

Every hit gets a 0–100 human-likelihood score with named signal reasons. The built-in threat feed at `/feed/ips.txt` is ready to consume from a firewall or block list. The JSON and CSV export endpoints support token-based authentication for scheduled Splunk ingestion.

**Use cases:** phishing simulations, honeypot deployments, recon detection, link tracking, and threat feed generation.

---

## How it works (high-level)

SignalTrace processes every request in real time:

1. Request is logged and enriched (IP, ASN, headers)
2. Detection signals are applied
3. A score (0–100) is calculated
4. Classification is assigned (bot → human)
5. Results are immediately available via dashboard, feed, or API

---

## Screenshots

### Dashboard

<p align="center"> 
  <img src="docs/images/dashboard-dark.webp" alt="SignalTrace dashboard — dark mode, showing activity feed with behaviorally flagged IPs panel" width="49%"> 
  <img src="docs/images/dashboard-light.webp" alt="SignalTrace dashboard — light mode" width="49%"> 
</p>

<p align="center">
  Live activity feed with classification badges, scores, and the Behaviorally Flagged IPs panel. Available in dark and light themes.
</p>

### Event Details

<p align="center"> 
  <img src="docs/images/details.webp" alt="SignalTrace event details — full request breakdown with scoring signals and actions" width="80%"> 
</p>

<p align="center">
  Expand any event to see the full request, identity, scoring signals, headers, and inline actions — including Block IP and Allow IP.
</p>

### Token & Rule Management

<p align="center"> 
  <img src="docs/images/tokens.webp" alt="SignalTrace token management — create and manage tracked tokens with feed exclusion" width="49%"> 
  <img src="docs/images/skip.webp" alt="SignalTrace skip patterns — suppress known-noise paths from logging" width="49%"> 
</p>

<p align="center">
  Create and manage tracked tokens with per-token feed exclusion, and configure skip patterns to suppress known-noise paths at the logging stage.
</p>

<p align="center"> 
  <img src="docs/images/asn.webp" alt="SignalTrace ASN rules — apply scoring penalties and feed exclusions by autonomous system" width="49%"> 
  <img src="docs/images/country.webp" alt="SignalTrace country rules — apply score penalties by country code" width="49%"> 
</p>

<p align="center">
  Apply ASN-based scoring penalties and feed exclusions for specific networks, and add per-country score penalties by 2-letter ISO code.
</p>

<p align="center"> 
  <img src="docs/images/ip.webp" alt="SignalTrace IP overrides — permanently block or allow specific IPs, bypassing scoring" width="80%"> 
</p>

<p align="center">
  IP overrides bypass scoring entirely — blocked IPs are always classified as bot and always appear in the threat feed; allowed IPs are always classified as human and excluded from the feed.
</p>

### Splunk Dashboards

<p align="center"> 
  <img src="docs/images/splunk.webp" alt="SignalTrace Splunk Overview dashboard — SOC display with stat panels, events over time, top IPs, detection signals" width="49%"> 
  <img src="docs/images/splunk2.webp" alt="SignalTrace Splunk Event Investigation dashboard — filterable event table with token, IP, country, and signal filters" width="49%"> 
</p>

<p align="center">
  The Overview dashboard provides a live 24-hour SOC display with stat panels, events over time, top IPs, countries, organisations, tokens, detection signals, and behavioral signal hits. The Event Investigation dashboard offers a filterable event table with token, IP, classification, country, and detection signal filters.
</p>

### Grafana Dashboard

<p align="center"> 
  <img src="docs/images/grafana.webp" alt="SignalTrace Grafana dashboard — stat panels, confidence label distribution, top source IPs, top countries, and recent events table" width="80%"> 
</p>

<p align="center">
  Pre-built Grafana dashboard using the Infinity datasource. Includes stat panels, confidence label distribution, top source IPs and countries, and a recent events table — all powered by server-side aggregation endpoints with no Grafana transformations required.
</p>

## Requirements

SignalTrace is designed to run on minimal hardware.

A 1 vCPU VM with 1 GB RAM and swap enabled is sufficient. Plan for 5–10 GB of disk depending on how much traffic you log.

**Software requirements:** PHP 8.1+, SQLite3, Apache with mod_rewrite, Composer.

## Quick Start with Docker

```bash
git clone https://github.com/veddegre/signaltrace.git
cd signaltrace
chmod +x setup.sh
./setup.sh
```

The script walks through all configuration and starts the container. When prompted for install type, select:
* **Option 1** — pulls the pre-built image from `ghcr.io/veddegre/signaltrace:latest`, no build step required
* **Option 2** — builds the image locally from the Dockerfile, useful if you want to modify the image or pin to a specific commit
* **Option 3** — full manual install on Ubuntu + Apache, see [Manual Installation](#manual-installation-ubuntu--apache) below

---

### Without setup.sh

Skip the guided setup and configure `.env` manually:

```bash
# Get the compose files and env template
curl -fsSL https://raw.githubusercontent.com/veddegre/signaltrace/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/veddegre/signaltrace/main/docker-compose.prebuilt.yml -o docker-compose.prebuilt.yml
curl -fsSL https://raw.githubusercontent.com/veddegre/signaltrace/main/.env.example -o .env
```

Edit `.env` and fill in the values:

| Variable | Required | Description |
|---|---|---|
| `SIGNALTRACE_ADMIN_USERNAME` | ✅ | Admin login username |
| `SIGNALTRACE_ADMIN_PASSWORD_HASH` | ✅ | Bcrypt hash of your admin password |
| `SIGNALTRACE_PORT` | ✅ | Host port to expose SignalTrace on (e.g. `80`) |
| `SIGNALTRACE_VISITOR_HASH_SALT` | ✅ | Random salt for visitor fingerprinting |
| `MAXMIND_ACCOUNT_ID` | Recommended | MaxMind account ID for GeoIP enrichment |
| `MAXMIND_LICENSE_KEY` | Recommended | MaxMind license key |
| `SIGNALTRACE_EXPORT_API_TOKEN` | Optional | Token for Splunk/automation export endpoints |
| `SIGNALTRACE_TRUSTED_PROXY_IP` | Optional | IP of your reverse proxy if running behind one |
| `AUTH_MAX_FAILURES` | Optional | Failed logins before lockout (default: 5) |
| `AUTH_LOCKOUT_SECS` | Optional | Lockout duration in seconds (default: 900) |
| `SELF_REFERER_DOMAIN` | Optional | Your domain — requests from it get a score penalty |
| `CF_ACCESS_ENABLED` | Optional | Set to `true` to enable Cloudflare Access JWT verification |
| `CF_ACCESS_AUD` | Optional | Cloudflare Access AUD token (required when CF_ACCESS_ENABLED=true) |
| `CF_ACCESS_TEAM_DOMAIN` | Optional | Cloudflare team domain (required when CF_ACCESS_ENABLED=true) |
| `DEMO_MODE` | Optional | Set to `true` to enable the demo banner and lock sensitive settings |
| `DEMO_ADMIN_USERNAME` | Optional | Display-only username shown in the demo banner |
| `DEMO_ADMIN_PASSWORD` | Optional | Display-only password shown in the demo banner |
| `EMAIL_SMTP_HOST` | Optional | SMTP server hostname — set to enable email alerting |
| `EMAIL_SMTP_PORT` | Optional | SMTP port (default: 587) |
| `EMAIL_SMTP_ENCRYPTION` | Optional | SMTP encryption: `tls`, `ssl`, or `none` (default: tls) |
| `EMAIL_SMTP_USER` | Optional | SMTP username |
| `EMAIL_SMTP_PASS` | Optional | SMTP password |
| `EMAIL_SMTP_FROM` | Optional | From address (defaults to `EMAIL_SMTP_USER` if not set) |

> **Email alerting:** The entrypoint writes `EMAIL_SMTP_*` variables as PHP constants into `config.local.php` inside the container so they are never stored in the database or exposed through the admin UI. Set the variables in `.env` and they will be configured automatically on startup. Enable alerting, set thresholds, and configure the recipient address in the Settings tab after the container starts. See the [Email Alerting wiki page](https://github.com/veddegre/signaltrace/wiki/Email-Alerting) for details.

Generate the required secrets:

```bash
# Bcrypt password hash
php -r "echo password_hash('yourpassword', PASSWORD_DEFAULT) . PHP_EOL;"

# Visitor hash salt
openssl rand -hex 64

# Export API token (if using Splunk or automation)
openssl rand -hex 32
```

Then start using the pre-built image:

```bash
docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml up -d
```

Or build from source:

```bash
docker compose up -d
```

---

### Updating

Pre-built image:

```bash
docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml pull
docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml up -d
```

Build from source:

```bash
git pull
docker compose build
docker compose up -d
```

The SQLite database and GeoIP databases are stored in named Docker volumes and persist across rebuilds.

**Notes**

The Docker image is based on Ubuntu 24.04. The MaxMind PPA is used to install `geoipupdate`. The Apache config includes the `Authorization` header fix required for Bearer token auth — you don't need to add anything manually if you're using Docker.

On Proxmox LXC containers, the `security_opt: apparmor=unconfined` setting in `docker-compose.yml` is required for the container runtime to function correctly.

## Manual Installation (Ubuntu + Apache)

The setup script handles everything — packages, cloning, configuration, database, GeoIP, and Apache. Run it on a fresh Ubuntu server:

```bash
curl -fsSL https://raw.githubusercontent.com/veddegre/signaltrace/main/setup.sh -o setup.sh
chmod +x setup.sh
sudo ./setup.sh
```

Select option 3 (Manual) when prompted. The script will:
* Install Apache, PHP, SQLite, Composer, and geoipupdate
* Clone the repository to `/var/www/signaltrace`
* Walk through all configuration options including optional email SMTP setup
* Install PHP dependencies via Composer
* Configure `/etc/GeoIP.conf` and download the MaxMind databases
* Initialise the SQLite database, with an option to load sample data
* Set hardened file ownership — `root:www-data` with `640` permissions on application files, `660` on the database, `770` on the data directory
* Configure and restart Apache
* Optionally configure HTTPS via Let's Encrypt

When the script finishes, SignalTrace is running.

If an existing `config.local.php` is found, the script will prompt before overwriting it — allowing you to preserve your current configuration or selectively update it.

> [!WARNING]
> The manual install is designed for a fresh Ubuntu server with no existing web services. It will install and configure Apache and disable the default site. Do not run it on a server already hosting other websites.

If you have already cloned the repository manually, you can run `setup.sh` from inside it instead — it will detect the existing repo and skip the clone step.

## Configuration Tuning

The setup script prompts for all configuration including optional tuning values — auth lockout threshold and duration, self-referrer domain penalty, reverse proxy IP, and export API token. You don't need to edit any files manually after running it.

If you need to change a value after the initial setup, edit `includes/config.local.php` directly (manual install) or update `.env` and restart the container (Docker). The available settings and their defaults are documented in `includes/config.local.php.example`.

## HTTPS

For manual installs, the setup script offers to configure HTTPS via Let's Encrypt at the end of the install process. Your domain must be pointed at the server before running certbot.

To add HTTPS after the initial install, or to renew manually:

```bash
sudo apt install -y certbot python3-certbot-apache
sudo certbot --apache
```

Certificates renew automatically via a systemd timer installed by certbot. To verify auto-renewal is working:

```bash
sudo certbot renew --dry-run
```

## Admin

`https://yourdomain.example/admin`

## Threat Feed

The threat feed requires admin authentication and outputs deduplicated IPs classified at or above your configured confidence threshold. IPv4 and IPv6 are served as separate feeds to avoid confusing tools that expect one address family. Intel format exports include both IPv4 and IPv6 in a single file.

**IPv4 feeds:**

| Endpoint | Format |
|---|---|
| `/feed/ips.txt` | One IP per line |
| `/feed/ips.nginx` | `deny 1.2.3.4;` blocks |
| `/feed/ips.iptables` | iptables-restore compatible filter block |
| `/feed/ips.cidr` | CIDR notation with `/32` suffix |

**IPv6 feeds:**

| Endpoint | Format |
|---|---|
| `/feed/ipv6.txt` | One IP per line (normalized) |
| `/feed/ipv6.nginx` | `deny 2001:db8::1;` blocks |
| `/feed/ipv6.iptables` | ip6tables-restore compatible filter block |
| `/feed/ipv6.cidr` | CIDR notation with `/128` suffix |

**Threat intel formats (bot and suspicious only):**

| Endpoint | Format |
|---|---|
| `/feed/misp.json` | Full MISP event with `ip-src` attributes, RFC3339 timestamps, per-IP enrichment |
| `/feed/stix.json` | STIX 2.1 bundle with `indicator` objects, UUIDv5 stable IDs, STIX pattern syntax |

All feed URLs and a live count of IPs currently in the feed are shown in the Settings tab.

Feed behaviour is configured in Settings: time window, minimum confidence threshold, minimum hit count before an IP appears. MISP and STIX exports are additionally capped at bot and suspicious regardless of the minimum confidence setting — uncertain and human IPs are excluded from these formats since they feed into platforms that act automatically. Individual tokens and ASN rules can each be flagged to suppress their hits from feed output. Tokens can also be marked "Always include in feed" — any hit on those tokens goes into the plain text feeds regardless of classification, and into the intel formats at suspicious or above. Allowed IP overrides are excluded. Blocked IP overrides always appear regardless of threshold or hit count.

See the [Threat Feed Integration wiki page](https://github.com/veddegre/signaltrace/wiki/Threat-Feed-Integration) for consuming feed endpoints with iptables, Nginx, pfSense, and fail2ban, and the [Threat Intel Export wiki page](https://github.com/veddegre/signaltrace/wiki/Threat-Intel-Export) for MISP and STIX import examples.

## SIEM and Splunk Integration

Set an export API token in `.env` (Docker) or `config.local.php` (manual install):

```bash
# Generate with
openssl rand -hex 32
```

Apache strips the `Authorization` header before it reaches PHP by default. Verify your vhost config includes this line — without it, Bearer token auth will silently fail:

```apache
SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=$1
```

If SignalTrace runs behind a reverse proxy, set `TRUSTED_PROXY_IP` in `config.local.php` so client IPs are recorded correctly. See the [Behind a Reverse Proxy wiki page](https://github.com/veddegre/signaltrace/wiki/Behind-a-Reverse-Proxy) for full details.

Then poll either export endpoint on a schedule:
* `https://yourdomain.example/export/json`
* `https://yourdomain.example/export/csv`

Authenticate with a header (recommended, not logged by Apache):

```http
Authorization: Bearer your-generated-token
```

Or with a query parameter if your tooling doesn't support custom headers (note this appears in access logs):

`https://yourdomain.example/export/csv?api_key=your-generated-token`

When polled with no filters, the export applies the configured confidence threshold, minimum score, and time window from Settings. Pass `?ip=`, `?path=`, `?date_from=`, or other filter parameters to override.

### Splunk App

A ready-to-use Splunk integration is included under `splunk/signaltrace/`. Copy the folder into your Splunk `etc/apps/` directory and restart Splunk. Configure the scripted input in `bin/signaltrace_fetch.sh` with your SignalTrace URL and API token.

The app includes two Dashboard Studio dashboards:
* **SignalTrace — Overview:** (`dashboards/signaltrace_overview.json`) Designed for SOC screen display. Always shows the last 24 hours with no inputs. Panels cover stat cards, events over time, confidence distribution, top IPs, traffic by country, top ASN organisations, top tokens, top bot tokens, top detection signals, and behavioral signal hits.
* **SignalTrace — Event Investigation:** (`dashboards/signaltrace_events.json`) Designed for hands-on investigation. Includes a time range picker, token/path filter, IP filter, classification dropdown, country filter, and detection signal/reason filter. The results table includes confidence reason signals and returns up to 200 results.

See the [Splunk Integration wiki page](https://github.com/veddegre/signaltrace/wiki/Splunk-Integration) for full setup instructions.

### Grafana Dashboard

A pre-built Grafana dashboard is included at `grafana/signaltrace-dashboard.json`. It uses the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) and requires no transformations — all aggregation is handled server-side via dedicated endpoints.

The dashboard includes 16 panels: six stat panels (Total Events, Bot Events, Bot %, Unique IPs, Unique Tokens, Avg Confidence Score), Events Over Time with adaptive time bucketing, Confidence Label Distribution donut, Top Source IPs, Traffic by Country, Top ASN Organizations, Top Tokens, Top Bot-Classified Tokens, Top Detection Signals, Behavioral Signal Hits, and Recent Events.

Configure your Infinity datasource with a Bearer token and your SignalTrace domain as an allowed host, then import the dashboard JSON. Two variables are prompted on import: the Infinity datasource and your SignalTrace base URL.

See the [Grafana Integration wiki page](https://github.com/veddegre/signaltrace/wiki/Grafana-Integration) for full setup instructions.

## Detection and Scoring

Each request is scored on arrival. The score runs from 0 (definitely a bot) to 100 (definitely human) and resolves to one of four labels: `bot`, `suspicious`, `uncertain`, or `human`. The bands are: human ≥75, uncertain ≥60, suspicious ≥25, bot <25.

Signals that reduce the score include missing `Accept-Language`, `Accept-Encoding`, and `Sec-Fetch` headers; a browser UA with no supporting browser headers (spoofed UA detection); `Accept: */*` which is what HTTP libraries send by default; known automation UA signatures; raw IP in the Host header; exploit-like query strings; and hosting/datacenter IP ranges detected via ASN org name.

The `Sec-Fetch` and `Sec-CH-UA` checks are browser-aware. Safari is not penalised for headers it never sends. The `Sec-CH-UA` (Client Hints) penalty only applies when the UA claims to be Chromium-based.

Behavioral signals layer on top: rapid repeat requests, burst activity, and multi-token scanning all reduce the score in proportion to how aggressively the behavior is occurring.

Paths associated with common probes carry their own penalties. High-risk paths like `.env`, `_environment`, `.aws/credentials`, `.git`, and webshell patterns knock 40 points off. Medium-risk paths like `wp-admin`, `phpinfo`, `phpmyadmin`, Laravel debug tools, and Spring Boot actuator endpoints knock off 25.

See the [Scoring Reference wiki page](https://github.com/veddegre/signaltrace/wiki/Scoring-Reference) for a complete signal reference including all point values and worked examples.

**ASN rules** let you add manual score penalties for specific networks via the UI, with an option to exclude the ASN from feed output entirely.

**Country rules** let you add score penalties by 2-letter ISO country code. They affect scoring only and do not suppress IPs from the feed.

**IP overrides** bypass scoring entirely. A blocked IP is always classified as bot (score 0) and always appears in the threat feed. An allowed IP is always classified as human (score 100) and is excluded from the threat feed.

See the [IP Overrides & Country Rules wiki page](https://github.com/veddegre/signaltrace/wiki/IP-Overrides-&-Country-Rules) for full details on configuration and how overrides interact with the threat feed.

## Features at a Glance

* **Tracking:** custom tokens with redirect, full request logging, visitor fingerprinting, tracking pixel, GeoIP enrichment.
* **Admin dashboard:** paginated activity feed, expandable request details, per-IP summary panel with VT/Abuse/Info links and Block/Allow actions, date range filtering, classification badges with scores, bulk delete by filter, filter state preserved across row actions, dark mode, mobile layout.
* **Signal reason labels:** confidence signals displayed as color-coded pill tags with friendly descriptions. Raw signal names preserved in tooltips for cross-referencing with exports and the wiki.
* **Token management:** create/edit/activate/deactivate/delete, per-token feed exclusion, per-token force-include in feed, per-token webhook opt-in, per-token email alert opt-in, pixel URL generation.
* **ASN rules:** scoring penalties, feed exclusion, edit in place.
* **Country rules:** per-country score penalties by ISO code, affects scoring only.
* **IP overrides:** pin any IP to always-block (bot) or always-allow (human), bypasses scoring entirely.
* **Behavioral flagging:** dashboard panel showing IPs that triggered burst, rapid-repeat, or multi-token signals within a configurable window. Configurable max rows and default visibility. Hide/show toggle. Clicking an IP forces show-all and collapses the panel.
* **Wildcard DNS mode:** when enabled, extracts the subdomain prefix from each request's Host header and shows it as a column in the activity feed and a filter in the filter bar. A subdomain activity summary panel shows hit counts, bot hits, and first/last seen per subdomain.
* **Skip patterns:** exact, contains, and prefix matching to suppress known noise. Add directly from the activity feed.
* **Threat feed:** ten endpoints covering IPv4 and IPv6 in plain text, Nginx deny, iptables, CIDR, MISP event, and STIX 2.1 formats. Minimum hit count threshold. Feed preview count in Settings.
* **MISP export:** full MISP event with `ip-src` attributes, RFC3339 timestamps, per-IP comments with classification and enrichment. Threat level derived from worst classification in the batch. Bot and suspicious only.
* **STIX 2.1 export:** bundle with `indicator` objects, UUIDv5 stable IDs, `ipv4-addr`/`ipv6-addr` pattern types, confidence values mapped to STIX convention, `valid_from`/`valid_until` in RFC3339 UTC. Bot and suspicious only.
* **Redirect rate limiting:** known token redirects are rate limited per IP per token to prevent the honeypot from being used as an HTTP flood origin. Count and window configurable in Settings. Set to 0 to disable.
* **Cleanup tools:** delete by token, by IP, by current filter, or selectively remove unknown-token hits.
* **Data retention:** configurable retention window with manual trigger and automatic probabilistic cleanup.
* **Threat webhook:** fires when an unknown-path hit meets the configured classification threshold (bot, suspicious, uncertain, or all). Deduplicates per IP per 5 minutes. Custom JSON payload templates with `{{placeholder}}` syntax. Auto-detects Slack/Discord format.
* **Token webhook:** fires when a known tracked token is hit, regardless of classification. Per-token opt-in. Deduplicates per visitor per token per 5 minutes. Separate URL and payload template from the threat webhook.
* **Email alerting:** sends plain text email alerts via SMTP when threats are detected or canary tokens are hit. Per-token opt-in. Configurable threshold and deduplication window. SMTP credentials stored in `config.local.php` only — never in the database or admin UI.
* **Cloudflare Access:** optional identity layer using Cloudflare Zero Trust. Verifies the JWT injected by Cloudflare before allowing access to the admin panel. Bypassed in demo mode. Requires `firebase/php-jwt`.

## Project Structure

```text
signaltrace/
├── .github/
│   └── workflows/
│       └── docker.yml
├── LICENSE
├── README.md
├── Dockerfile
├── docker-compose.yml
├── docker-compose.prebuilt.yml
├── .env.example
├── setup.sh
├── composer.json
├── composer.lock
├── data/
│   └── database.db
├── db/
│   ├── schema.sql
│   └── seed.sql
├── docker/
│   ├── apache.conf
│   └── entrypoint.sh
├── docs/
│   └── images/
│       ├── dashboard-dark.webp
│       ├── dashboard-light.webp
│       ├── details.webp
│       ├── tokens.webp
│       ├── skip.webp
│       ├── asn.webp
│       ├── country.webp
│       ├── ip.webp
│       ├── splunk.webp
│       ├── splunk2.webp
│       ├── grafana.webp
│       ├── signaltrace.png
│       └── signaltrace_transparent.png
├── grafana/
│   └── signaltrace-dashboard.json
├── includes/
│   ├── admin_actions.php
│   ├── admin_view.php
│   ├── auth.php
│   ├── config.local.php.example
│   ├── config.php
│   ├── db.php
│   ├── demo-banner.php
│   ├── helpers.php
│   └── router.php
├── public/
│   ├── admin.css
│   ├── index.php
│   └── signaltrace_transparent.png
├── splunk/
│   ├── README.md
│   └── signaltrace/
│       ├── app.conf
│       ├── bin/
│       │   └── signaltrace_fetch.sh
│       ├── dashboards/
│       │   ├── signaltrace_overview.json
│       │   └── signaltrace_events.json
│       ├── default/
│       │   ├── inputs.conf
│       │   └── props.conf
│       └── metadata/
│           └── default.meta
└── vendor/
```

The `public/` directory is the only thing Apache needs to serve. Everything else — includes, data, db, vendor — lives outside the document root.

## Security

`config.local.php` is never committed and contains all secrets. Passwords are stored as bcrypt hashes. All SQL uses parameterised queries. URL destinations are validated against an http/https allowlist at both write time and redirect time.

Admin login has rate limiting with a configurable lockout threshold and window. CSRF tokens protect all admin POST forms. The admin panel sends a per-request nonce-based Content Security Policy header with all inline event handlers replaced by delegated listeners. Security response headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are sent on every HTML response. The webhook fires only to validated URLs and blocks private and loopback IP ranges to prevent SSRF. The export API token is compared in constant time.

SMTP credentials for email alerting are stored exclusively in `config.local.php` as PHP constants — never in the database or the admin UI. This prevents credentials from being exposed through the settings page or a database read.

For deployments that require stronger admin authentication, Cloudflare Access can be added as an optional identity layer using Cloudflare Zero Trust. See the [Cloudflare Access wiki page](https://github.com/veddegre/signaltrace/wiki/Cloudflare-Access) for setup instructions.

## Production Checklist

- [ ] Enable HTTPS
- [ ] Set strong admin credentials and a unique visitor hash salt
- [ ] Configure `AUTH_MAX_FAILURES` and `AUTH_LOCKOUT_SECS` for your environment
- [ ] Set `TRUSTED_PROXY_IP` if running behind a reverse proxy
- [ ] Download GeoIP databases with `geoipupdate`
- [ ] Verify only `public/` is web-accessible
- [ ] Configure skip patterns to suppress known noise
- [ ] Add ASN rules for infrastructure you own or trust
- [ ] Add country rules for high-noise regions if applicable
- [ ] Add IP overrides to permanently block known bad actors or allow your own monitoring IPs
- [ ] Set feed exclusions on tokens and ASNs that should never appear in your blocklist
- [ ] Mark canary tokens with "Always include in threat feed" so any hit goes in the feed regardless of classification
- [ ] Tune the threat feed confidence threshold, time window, and minimum hit count — see the [Tuning Guide](https://github.com/veddegre/signaltrace/wiki/Tuning-Guide) for deployment scenario advice
- [ ] Set `EXPORT_API_TOKEN` and configure your SIEM integration if applicable
- [ ] Add a weekly `geoipupdate` cron job
- [ ] Configure a threat webhook URL and threshold for real-time bot alerts
- [ ] Configure a token webhook URL for phishing simulation and campaign tracking if needed
- [ ] Configure email alerting — add `EMAIL_SMTP_*` constants to `config.local.php` and enable in Settings
- [ ] Review redirect rate limit settings and adjust for your expected traffic volume
- [ ] Enable Wildcard DNS mode if using a wildcard DNS record to catch subdomain probing
- [ ] Consider enabling Cloudflare Access for per-user identity and MFA on the admin panel

## Tech Stack

Ubuntu 24.04, PHP 8.1+, SQLite via PDO, Apache with mod_rewrite, MaxMind GeoLite2. Docker and Docker Compose are supported for containerised deployments with a guided `setup.sh` script. A pre-built Docker image is published to `ghcr.io/veddegre/signaltrace` via GitHub Actions on every push to `main`. A Splunk integration with scripted input and two Dashboard Studio dashboards is included under `splunk/`. A pre-built Grafana dashboard using the Infinity datasource is included under `grafana/`. PHPMailer is used for email alerting. See the [Webhook Integration wiki page](https://github.com/veddegre/signaltrace/wiki/Webhook-Integration) and [Email Alerting wiki page](https://github.com/veddegre/signaltrace/wiki/Email-Alerting) for configuring outbound alerts.

## Contributing

Contributions are welcome. Read `CONTRIBUTING.md` before opening a pull request.

Found a bug? Use the bug report issue template. Have a feature idea? Open an issue to discuss it before building. Found a security vulnerability? See `SECURITY.md` for responsible disclosure — please don't open a public issue.

If SignalTrace is useful to you, starring the repository on GitHub helps others find it.

## Maintainer

SignalTrace is developed and maintained by Greg Vedders. You can find more of my technical write-ups, projects, and other writing on my personal blog at [gregvedders.com](https://gregvedders.com).

## Disclaimer

SignalTrace is designed for security visibility and authorised testing. It will attract scanners, bots, and automated systems by design. Use it with awareness of your environment and risk tolerance.

## License

MIT

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

> *Most tools try to hide the noise. SignalTrace makes it visible.*
