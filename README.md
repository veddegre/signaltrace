# SignalTrace Tracking & Analysis

<p align="center"> 
  <img src="docs/images/signaltrace_transparent.png" alt="SignalTrace — Signal Trace Tracking & Analysis" width="160"> 
</p> 

<p align="center"> 
  <img src="https://img.shields.io/badge/PHP-8.1%2B-blue" alt="PHP"> 
  <img src="https://img.shields.io/badge/Database-SQLite-lightgrey" alt="SQLite"> 
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"> 
  <img src="https://img.shields.io/badge/Status-Active-success" alt="Status">
  <img src="https://github.com/veddegre/signaltrace/actions/workflows/docker.yml/badge.svg" alt="Docker Build">
</p>

<p align="center">
  SignalTrace Tracking & Analysis for honeypots, links, and request intelligence.
</p>

<p align="center">
  Designed for SOC workflows, phishing simulations, and real-time threat intelligence generation.
</p>

SignalTrace is a self-hosted tracking and analysis platform for honeypot deployment, link tracking, and security visibility. It logs every interaction with custom paths, scores each request for bot or human likelihood, and makes the results immediately usable for investigation, automation, or SIEM integration.

No external services required. One PHP app, one SQLite database, one Apache vhost.

Includes built-in Splunk dashboards and SIEM-ready export endpoints.

**Project Website:** [www.trysignaltrace.com](https://www.trysignaltrace.com)

---

## Demo

A short walkthrough of the dashboard, token workflow, and event investigation:

https://github.com/user-attachments/assets/7998998e-3fb9-4f18-a37c-bd5f6cc19df2

---

## Live Demo

A live instance is running at [trysignaltrace.com/admin](https://trysignaltrace.com/admin) and capturing real traffic. Every scanner, bot, and automated probe that hits it is scored in real time.

* **Username:** `demo`
* **Password:** `trysignaltrace`

*Note: The demo resets every 60 minutes. All data is sample/live traffic only — no real credentials or sensitive data are present.*

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
  <img src="docs/images/dashboard-dark.webp" alt="SignalTrace dashboard — Signal Trace tracking & analysis (dark mode)" width="49%"> 
  <img src="docs/images/dashboard-light.webp" alt="SignalTrace dashboard — Signal Trace tracking & analysis (light mode)" width="49%"> 
</p>

<p align="center">
  Live activity view with classification, scoring, token tracking, and investigation workflow in both dark and light themes.
</p>

### Core Workflow

<p align="center"> 
  <img src="docs/images/tokens.webp" alt="SignalTrace token management — Signal Trace tracking & analysis" width="49%"> 
  <img src="docs/images/details.webp" alt="SignalTrace event details — Signal Trace tracking & analysis" width="49%"> 
</p>

<p align="center">
  Create and manage tracked tokens, then drill directly into individual events with full request, identity, scoring, and header detail.
</p>

<p align="center"> 
  <img src="docs/images/settings.webp" alt="SignalTrace settings — Signal Trace tracking & analysis" width="49%"> 
  <img src="docs/images/skip.webp" alt="SignalTrace skip patterns — Signal Trace tracking & analysis" width="49%"> 
</p>

<p align="center">
  Tune scoring behavior, retention, threat feed settings, and suppress known-noise paths with configurable skip patterns.
</p>

<p align="center"> 
  <img src="docs/images/asn.webp" alt="SignalTrace ASN rules — Signal Trace tracking & analysis" width="49%"> 
  <img src="docs/images/settings2.webp" alt="SignalTrace export and cleanup settings — Signal Trace tracking & analysis" width="49%"> 
</p>

<p align="center">
  Apply ASN-based scoring penalties, exclude trusted infrastructure from feed output, and configure exports for downstream tooling.
</p>

### Splunk Dashboards

<p align="center"> 
  <img src="docs/images/splunk.webp" alt="SignalTrace Splunk overview — Signal Trace tracking & analysis" width="49%"> 
  <img src="docs/images/splunk2.webp" alt="SignalTrace Splunk investigation — Signal Trace tracking & analysis" width="49%"> 
</p>

<p align="center">
  Included Splunk dashboards provide SOC-friendly overview panels and a filterable event investigation view.
</p>

## Requirements

SignalTrace is designed to run on minimal hardware.

A 1 vCPU VM with 1 GB RAM and swap enabled is sufficient. Plan for 5–10 GB of disk depending on how much traffic you log.

**Software requirements:** PHP 8.1+, SQLite3, Apache with mod_rewrite, Composer.

## Quick Start with Docker

Run `setup.sh` for a guided setup — it handles configuration, secret generation, and starting the container for all Docker options.

### Option A — Pre-built image (fastest)

No build step. The script pulls `ghcr.io/veddegre/signaltrace:latest` and starts the container immediately after configuration.

```bash
git clone https://github.com/veddegre/signaltrace.git
cd signaltrace
chmod +x setup.sh
./setup.sh
```

Select **option 1** when prompted. The script walks through all configuration, writes `.env`, pulls the image, and starts the container.

---

### Option B — Build from source

Builds the image locally from the Dockerfile. Useful if you want to modify the image or pin to a specific commit.

```bash
git clone https://github.com/veddegre/signaltrace.git
cd signaltrace
chmod +x setup.sh
./setup.sh
```

Select **option 2** when prompted. The script handles configuration, builds the image, and starts the container.

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

Select option 2 (Manual) when prompted. The script will:
* Install Apache, PHP, SQLite, Composer, and geoipupdate
* Clone the repository to `/var/www/signaltrace`
* Walk through all configuration options
* Install PHP dependencies via Composer
* Configure `/etc/GeoIP.conf` and download the MaxMind databases
* Initialise the SQLite database, with an option to load sample data
* Set correct `www-data` ownership on all files
* Configure and restart Apache
* Optionally configure HTTPS via Let's Encrypt

When the script finishes, SignalTrace is running.

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

The threat feed is available at `/feed/ips.txt` and requires admin authentication. It outputs a deduplicated list of IPs classified at or above your configured confidence threshold, suitable for consumption by firewalls, block lists, SIEM enrichment pipelines, or temporary deny lists.

Behaviour is configured in the Settings tab: time window, minimum confidence threshold. Individual tokens and ASN rules can each be flagged to suppress their hits from feed output, so you never accidentally block infrastructure you own.

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
* **SignalTrace — Overview:** (`dashboards/signaltrace_overview.json`) Designed for SOC screen display. It has no inputs and always shows the last 24 hours. Panels cover stat cards, events over time, confidence distribution, top IPs, traffic by country, top ASN organisations, top tokens, top bot tokens, top detection signals, and bot traffic by country.
* **SignalTrace — Event Investigation:** (`dashboards/signaltrace_events.json`) Designed for hands-on investigation. It has a time range picker, token/path text filter, IP filter, and classification dropdown. The table returns up to 200 results.

## Detection and Scoring

Each request is scored on arrival. The score runs from 0 (definitely a bot) to 100 (definitely human) and resolves to one of four labels: `bot`, `suspicious`, `likely-human`, or `human`. The bands are: human ≥75, likely-human ≥60, suspicious ≥25, bot <25.

Signals that reduce the score include missing `Accept-Language`, `Accept-Encoding`, and `Sec-Fetch` headers; a browser UA with no supporting browser headers (spoofed UA detection); `Accept: */*` which is what HTTP libraries send by default; known automation UA signatures; raw IP in the Host header; exploit-like query strings; and hosting/datacenter IP ranges detected via ASN org name.

The `Sec-Fetch` and `Sec-CH-UA` checks are browser-aware. Safari is not penalised for headers it never sends. The `Sec-CH-UA` (Client Hints) penalty only applies when the UA claims to be Chromium-based.

Behavioral signals layer on top: rapid repeat requests, burst activity, and multi-token scanning all reduce the score in proportion to how aggressively the behavior is occurring.

Paths associated with common probes carry their own penalties. High-risk paths like `.env`, `_environment`, `.aws/credentials`, `.git`, and webshell patterns knock 40 points off. Medium-risk paths like `wp-admin`, `phpinfo`, `phpmyadmin`, Laravel debug tools, and Spring Boot actuator endpoints knock off 25.

ASN rules let you add manual score penalties for specific networks via the UI.

## Features at a Glance

* **Tracking:** custom tokens with redirect, full request logging, visitor fingerprinting, tracking pixel, GeoIP enrichment.
* **Admin dashboard:** paginated activity feed, expandable request details, per-IP summary panel, date range filtering, classification badges with scores, dark mode, mobile layout.
* **Token management:** create/edit/activate/deactivate/delete, per-token feed exclusion, pixel URL generation.
* **ASN rules:** scoring penalties, feed exclusion, edit in place.
* **Skip patterns:** exact, contains, and prefix matching to suppress known noise. Add directly from the activity feed.
* **Cleanup tools:** delete by token, by IP, or selectively remove unknown-token hits.
* **Data retention:** configurable retention window with manual trigger and automatic probabilistic cleanup.
* **Webhook alerts:** fires on bot classification, deduplicates per IP per 5 minutes, auto-detects Slack/Discord format.

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
├── docker-compose.override.yml.example
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
│       ├── splunk.webp
│       ├── splunk2.webp
│       ├── asn.webp
│       ├── skip.webp
│       ├── settings2.webp
│       ├── settings.webp
│       ├── tokens.webp
│       ├── signaltrace.png
│       └── signaltrace_transparent.png
├── includes/
│   ├── admin_actions.php
│   ├── admin_view.php
│   ├── auth.php
│   ├── config.local.php.example
│   ├── config.php
│   ├── db.php
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

Admin login has rate limiting with a configurable lockout threshold and window. CSRF tokens protect all admin POST forms. Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are sent on every HTML response. The webhook fires only to validated URLs and blocks private and loopback IP ranges to prevent SSRF. The export API token is compared in constant time.

## Production Checklist

- [ ] Enable HTTPS
- [ ] Set strong admin credentials and a unique visitor hash salt
- [ ] Configure `AUTH_MAX_FAILURES` and `AUTH_LOCKOUT_SECS` for your environment
- [ ] Set `TRUSTED_PROXY_IP` if running behind a reverse proxy
- [ ] Download GeoIP databases with `geoipupdate`
- [ ] Verify only `public/` is web-accessible
- [ ] Configure skip patterns to suppress known noise
- [ ] Add ASN rules for infrastructure you own or trust
- [ ] Set feed exclusions on tokens and ASNs that should never appear in your blocklist
- [ ] Tune the threat feed confidence threshold and time window
- [ ] Set `EXPORT_API_TOKEN` and configure your SIEM integration if applicable
- [ ] Add a weekly `geoipupdate` cron job

## Tech Stack

Ubuntu 24.04, PHP 8.1+, SQLite via PDO, Apache with mod_rewrite, MaxMind GeoLite2. Docker and Docker Compose are supported for containerised deployments with a guided `setup.sh` script. A pre-built Docker image is published to `ghcr.io/veddegre/signaltrace` via GitHub Actions on every push to `main`. A Splunk integration with scripted input and two Dashboard Studio dashboards is included under `splunk/`.

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
