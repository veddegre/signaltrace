# Changelog

---

## [2.3.1] — April 12, 2026

### GitHub Actions & Pre-built Image

A GitHub Actions workflow (`docker.yml`) was added. It builds and pushes the Docker image to `ghcr.io/veddegre/signaltrace` on every push to `main` and on version tags. Pushing `v2.3.1` publishes both `ghcr.io/veddegre/signaltrace:2.3.1` and `ghcr.io/veddegre/signaltrace:latest`.

`docker-compose.prebuilt.yml` was added as a Compose override that nulls out the `build` directive and sets the image to `ghcr.io/veddegre/signaltrace:latest`. Used with:

```
docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml up -d
```

The setup script install menu was reordered and expanded to three options:
* **Option 1 — Pre-built image:** pulls `ghcr.io/veddegre/signaltrace:latest` and starts the container — no build step required
* **Option 2 — Build from source:** builds the image locally from the Dockerfile
* **Option 3 — Manual (Ubuntu + Apache):** full manual install, unchanged from 2.3.0

---

## [2.3.0] — April 9, 2026

### Setup & Demo Release

The setup script now handles the complete manual installation end to end — system packages, repository clone, PHP dependencies, GeoIP, database initialisation, Apache configuration, and optional Let's Encrypt HTTPS. A live demo is available at trysignaltrace.com with hourly resets.

### Setup Script

The manual install path was substantially reworked. Previously it assumed system packages were already installed and the repository was already cloned. The script can now be downloaded as a standalone file and run on a fresh Ubuntu server — it installs all system packages first (Apache, PHP, SQLite, Composer, geoipupdate), then clones the repository to `/var/www/signaltrace`, then proceeds with configuration. If run from inside an existing clone it detects this and skips the clone step.

The script now installs PHP dependencies via Composer automatically as part of the manual install flow.

GeoIP configuration is now fully automated. The script writes `/etc/GeoIP.conf` with the correct `DatabaseDirectory /var/lib/GeoIP` entry and runs `geoipupdate` to download the databases immediately. Previously the databases landed at `/usr/share/GeoIP/` (the geoipupdate default) rather than `/var/lib/GeoIP/` (where SignalTrace looks), causing ASN and country enrichment to silently fail on manual installs.

Database initialisation is now part of the setup script. After writing the config file the script creates the data directory, sets correct ownership, initialises the schema, and offers to load sample data. On a re-run it detects an existing database and prompts before wiping it.

Apache vhost configuration is now automated. The script prompts for a ServerName, writes `/etc/apache2/sites-available/signaltrace.conf`, enables the site, disables the default site, and restarts Apache.

Let's Encrypt HTTPS is now offered as an optional final step. The script installs certbot, requests a certificate for the configured ServerName, and enables automatic HTTP→HTTPS redirect. Certificates renew automatically via the certbot systemd timer.

Optional tuning values (auth lockout threshold, lockout duration, self-referrer domain) are now prompted during setup rather than requiring manual file edits afterward. They are written into `config.local.php` for manual installs and `.env` for Docker.

The export API token prompt was simplified to a single prompt with three clear options: press Enter to auto-generate, type a value to use your own, or type `none` to skip.

The admin password prompt now requires the password to be entered twice and loops until both entries match.

A prominent warning box is displayed before the manual install proceeds, making clear it is designed for a fresh Ubuntu server and will install and configure Apache, disable the default site, and overwrite `/etc/GeoIP.conf`.

### Bug Fixes

`sqlite3` was being called before the data directory existed and was owned by `www-data`, causing an "unable to open database file" error on fresh installs. The fix creates the directory and sets ownership before attempting to create the database file.

The seed file used hardcoded `link_id` values (1, 2, 4) that assumed specific SQLite auto-increment IDs. On a fresh install these IDs are not guaranteed, causing foreign key constraint failures. The seed now uses subquery lookups (`SELECT id FROM links WHERE token = '...'`) to resolve IDs dynamically.

The `INSERT INTO links` statement in seed.sql was changed to `INSERT OR IGNORE INTO links` to prevent UNIQUE constraint failures when the seed is run against a database that already contains the sample tokens.

`/favicon.ico` and `/favicon.png` routes were added to `public/index.php`. Both serve `signaltrace_transparent.png` publicly without requiring authentication. Both paths are added to the `$reserved` array so favicon requests are never logged as honeypot hits.

The `$buildExportUrl` closure in `admin_view.php` contained a typo — `/expor/json` instead of `/export/json`.

### Demo Infrastructure

A live demo runs at `https://trysignaltrace.com/admin` (username: `demo`, password: `trysignaltrace`). The demo resets every 60 minutes via a cron job.

### Favicons

Favicon `<link>` tags (`/favicon.png` and apple-touch-icon) were added to `admin_view.php`. The `/favicon.ico` and `/favicon.png` routes in `index.php` serve the transparent logo publicly so browsers receive the favicon before authentication.

---

## [2.2.0] — April 7, 2026

### Docker

The Docker base image was switched from `php:8.2-apache` (Debian trixie) to `ubuntu:24.04`. The Debian image did not have `geoipupdate` available in its default package repositories. Ubuntu 24.04 supports the MaxMind PPA directly, making `geoipupdate` installable without additional workarounds. `sqlite3` is now explicitly installed in the image, which was missing and caused the entrypoint to crash on first run.

The `docker-compose.yml` now includes `security_opt: apparmor=unconfined` which is required for Docker to function correctly on Proxmox LXC containers where the AppArmor kernel interface is present but not writable from inside the container.

The host port is now configurable via `SIGNALTRACE_PORT` in `.env` with a default of 80. This allows SignalTrace to coexist with other containers on the same host without port conflicts.

The entrypoint was rewritten to use `printf` with `%s` arguments for all config values instead of a heredoc. The heredoc approach caused bcrypt hashes to be truncated and corrupted because the shell interpreted `$2y$10$...` as variable expansions. The `printf` approach passes values as arguments so the shell never touches their contents.

### Setup Script

`setup.sh` is now a universal setup script supporting both Docker and manual installs. At startup it asks which install type you are doing, then branches accordingly — Docker writes `.env`, manual install writes `includes/config.local.php` directly.

Both paths share the same prompts for admin username, password, MaxMind credentials, export API token, and reverse proxy IP. The Docker path additionally prompts for a host port, auto-detecting a free port as the default.

The script auto-generates the bcrypt password hash using PHP locally if available, Python bcrypt if available, or by starting the container and running `docker exec` if neither is present on the host. The hash is written with single quotes in `.env` and `$` signs are escaped before any `sed` operations to prevent shell expansion from corrupting it.

If a container is already running when the script is re-run, it is stopped first so its port is freed for detection, the existing port is read from `.env` and offered as the default, and the container is restarted automatically at the end.

---

## [2.1.3] — April 6, 2026

### Splunk App

The single dashboard was split into two separate dashboards.

**SignalTrace — Overview** (`signaltrace_overview.json`) is designed for SOC screen display. It has no inputs and always shows the last 24 hours, hardcoded at the defaults level so it never drifts regardless of user interaction. Panels cover the six stat cards, events over time, confidence distribution, top IPs, traffic by country, top ASN organisations, top tokens, top bot tokens, top detection signals, and bot traffic by country.

**SignalTrace — Event Investigation** (`signaltrace_events.json`) is designed for hands-on investigation. It has a time range picker, token/path text filter, IP text filter, and classification dropdown. All filters default to show everything and are applied on Enter for text fields. The table returns up to 200 results.

Additional dashboard fixes in this release: bar charts trimmed to top 5 results for readability and given value labels; country and org panels converted from bar charts to tables; `splunk.fillergauge` and `splunk.markergauge` replaced with `splunk.singlevalue` for the avg confidence and bot count panels; bot percentage query rewritten to return a scalar value; the broken "High Confidence Events (>=10)" panel removed and replaced with a Bot Events sparkline panel.

---

## [2.1.2] — April 6, 2026

### Scoring

`self_referer_root` penalty increased from -8 to -15. A request arriving at `/` with your own domain as the Referer is a stronger signal of programmatic traffic than the previous penalty reflected — real browsers navigating fresh to a site don't produce this pattern.

`idc` added to the hosting provider signal list. Internet Data Center is a common suffix in Chinese carrier org names (e.g. "IDC, China Telecommunications Corporation") that was previously slipping past the datacenter keyword matching.

---

## [2.1.1] — April 6, 2026

### Scoring

Classification thresholds were tightened. The likely-human band was narrowed from 45–74 to 60–74, the suspicious band widened from 20–44 to 25–59, and the bot threshold raised from below 20 to below 25. In practice this means borderline requests that previously received a likely-human label — correct Sec-Fetch headers but missing Accept-Language or Client Hints, or coming from backbone/transit infrastructure — now score as suspicious, which is a more honest assessment of the uncertainty.

`idc` was added to the hosting provider signal keyword list. Chinese and Asian datacenter operators commonly include "IDC" (Internet Data Center) in their org names — this was previously not caught by the existing keyword set, allowing traffic from Chinese datacenter infrastructure to avoid the hosting provider penalty.

The `self_referer_root` penalty was increased from -8 to -15. A request arriving at `/` with your own domain in the Referer header is a reliable indicator of programmatically constructed traffic — a real browser navigating fresh to a page doesn't produce this pattern. The previous penalty was too light to meaningfully affect the classification of requests that otherwise had plausible browser headers.

### Splunk Dashboard

The dashboard was redesigned for 1920×1080 with no scrolling. The layout is now two tabs — Overview and Recent Events. The Overview tab fits all meaningful panels on a single screen: six stat cards across the top, an events-over-time chart with confidence distribution pie, three equal columns for top IPs/countries/orgs, a full-width row for top tokens and top bot tokens, and a bottom row with detection signals breakdown and bot traffic by country.

Removed panels: Event Type Distribution, Daily Unique IPs, Average Confidence Over Time, Request Methods, and the Likely-Human/Suspicious by Country stacked bar. All were either redundant with other panels, rarely interesting in practice, or producing misleading output.

The "High Confidence Events (>=10)" panel was removed. The query (`confidence_score>=10`) matched almost everything and the concept was wrong — it was styled in red suggesting threat volume but the threshold included most legitimate traffic. Replaced with a Bot Events single-value panel with sparkline.

The bot percentage query was rewritten to return a single scalar value instead of a timechart, which was being fed into a radial gauge that couldn't display it correctly.

The Likely-Human/Suspicious by Country panel was replaced with Bot Traffic by Country — a simple bar chart of bot-classified hits by country, which is more actionable.

`viz_avg_confidence` and `viz_high_confidence_events` were switched from `splunk.fillergauge` and `splunk.markergauge` to `splunk.singlevalue` — the gauge types have minimum size requirements that caused "too small to render content" errors at the panel dimensions used in the layout.

---

## [2.1.0] — April 6, 2026

### Detection and Scoring

The `accept_wildcard` signal was added. `Accept: */*` is the default sent by curl, wget, and most HTTP libraries — a reliable indicator the UA string may be fabricated regardless of how convincing it looks. Penalty is -15.

The `browser_ua_unsupported` signal was added. Previously a browser-looking UA received a +10 bonus unconditionally. Now the bonus only applies when at least one corroborating browser header is present (Accept-Language, Sec-Fetch-Mode, or Sec-CH-UA). A browser UA with none of those headers scores -10 instead of +10 — a 20 point swing that correctly classifies the spoofed-Chrome-UA-from-scanner pattern seen frequently in real traffic.

The high-risk path list was further expanded to include `_environment` (Symfony/Laravel env probe), `.ssh/`, `config.php`, `configuration.php`, `wp-config.php`, `laravel.log`, `shell.php`, `cmd.php`, and generic webshell patterns. The medium-risk list was expanded to include `wp-content`, `wp-includes`, `phpmyadmin`, `adminer`, `actuator/`, `/console`, `telescope`, `horizon`, and `/.well-known/security`.

Hosting and datacenter IP detection was significantly broadened. The provider list now covers HostRoyale, Hetzner, LeasWeb, Serverius, Psychz, Quadranet, M247, Combahton, Heficed, Datacamp, and others, plus generic org name keywords (`datacenter`, `data center`, `colocation`, `colo`, `dedicated server`, `server farm`) to catch providers not named explicitly. The broad keywords `hosting`, `vps`, and `cloud` were deliberately excluded to avoid penalising corporate proxy traffic.

### Security Audit Fixes

Auth lockout now uses `getClientIp()` instead of `$_SERVER['REMOTE_ADDR']` directly. Behind a trusted proxy, the two values differ — the old behaviour could lock out the proxy's IP rather than the real client's.

The `auth_failures` pruning window was corrected to match the lockout window exactly. The previous implementation pruned at `AUTH_LOCKOUT_SECS * 2`, which allowed old failures to briefly re-count toward a new lockout after the window had expired.

The export auth query parameter was renamed from `?token=` to `?api_key=` to eliminate a collision with the `?path=` export filter parameter. The old name caused filter parameters to be silently misinterpreted as authentication tokens.

Webhook SSRF protection was added. The webhook URL host is now checked against private and loopback IP ranges before any request is fired.

Webhook user agent strings are now sanitised before inclusion in Slack and JSON payloads. Control characters are stripped and the string is truncated to 300 characters.

`/admin.css` now requires admin authentication before being served. Previously it was publicly accessible.

The `?page=` parameter is now clamped to the total number of pages after the query runs, preventing large OFFSET queries from unbounded page numbers.

### Bug Fixes

The `allowedLabels` match logic in both `exportClicks()` and `getThreatFeedIps()` was corrected. The logic is "include this classification and everything worse" — selecting `bot` includes only bot hits, `suspicious` includes suspicious and bot, `likely-human` includes likely-human, suspicious, and bot, and `human` includes everything. The previous implementation had no `suspicious` arm and the default case was inconsistent between the two functions.

Apache strips the `Authorization` header before it reaches PHP unless explicitly configured otherwise. The `SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=$1` directive is now documented in the README, the Splunk integration wiki, and is included in the Docker Apache config so Docker deployments work correctly without manual configuration.

### Admin UI

Dark mode was added with OS-level preference detection and a manual toggle in the page header. The preference is persisted per browser via localStorage.

The admin layout is now fully mobile-responsive with breakpoints at 1100px, 700px, and 480px. The page header is sticky. Tables scroll horizontally within their containers. Date filter inputs show visible labels on mobile.

The SignalTrace logo now appears in the page header. Clicking the logo or the app name navigates to `/admin` and clears all active filters. The logo is hidden on the 480px breakpoint to preserve space.

### Docker

Docker and Docker Compose support was added. A `Dockerfile`, `docker-compose.yml`, `docker/entrypoint.sh`, `docker/apache.conf`, and `.env.example` are now included. The entrypoint generates `config.local.php` from environment variables, initialises the database on first run, and downloads GeoIP databases if MaxMind credentials are provided. The Docker Apache config includes the `SetEnvIf` directive so Bearer token auth works without additional configuration.

### Splunk App

A minimal Splunk app was added under `splunk/signaltrace/`. It includes a scripted input with checkpoint-based deduplication and lock file to prevent overlapping runs, `inputs.conf`, `props.conf`, and a Dashboard Studio dashboard covering total events, unique IPs and tokens, bot percentage, confidence label distribution, top source IPs, countries, ASN organisations, tokens, detection signals breakdown, and a recent events table.

### Documentation

`CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, and GitHub issue templates were added.

A wiki was created covering: Scoring Reference, Splunk Integration, Deployment: Nginx, Deployment: Behind a Reverse Proxy, GeoIP Setup and Maintenance, Tuning Guide, and Threat Feed Integration.

`README.md` was substantially rewritten with a clearer introduction, Docker quick start, full optional config documentation, updated project structure, and a production checklist.

---

## [2.0.0] — April 4, 2026

A substantial rewrite. Every file was touched. The core tracking and token model is unchanged and existing databases are automatically migrated on first boot.

### Detection and Scoring

Spoofed browser UA detection was added. Previously, any request carrying a browser-looking user agent string received a scoring bonus regardless of whether the rest of the request looked anything like a real browser. Now the bonus only applies when at least one supporting browser header is also present (Accept-Language, Sec-Fetch-Mode, or Sec-CH-UA). A browser UA with none of those headers scores negatively instead.

`Accept: */*` now carries a penalty. Real browsers send explicit content type preferences. Wildcard-only Accept is what curl, wget, and most HTTP libraries send by default and is a reliable signal that the UA string is fabricated.

Safari-aware Sec-Fetch scoring was added. Safari does not send Sec-Fetch headers consistently across versions, so their absence is no longer penalised for Safari UAs. Inconsistent values still score negatively.

The Sec-CH-UA (Client Hints) penalty now only applies when the UA claims to be Chromium-based, since Safari and Firefox never send these headers.

The high-risk path list was expanded to include `_environment`, `.aws/credentials`, `.ssh/`, `wp-config.php`, `config.php`, `configuration.php`, `laravel.log`, `shell.php`, `cmd.php`, and webshell patterns. The medium-risk list was expanded to include `wp-content`, `wp-includes`, `phpmyadmin`, `adminer`, `actuator/`, `/console`, `telescope`, and `horizon`.

Hosting and datacenter IP detection was broadened to cover significantly more providers by name, plus generic org name keywords like `datacenter`, `colocation`, and `dedicated server`.

### Token and ASN Management

A per-token **Exclude from feed** flag was added. IPs hitting an excluded token never appear in the threat feed output, which makes it practical to run tokens for internal testing alongside public-facing honeypot paths without polluting your block list.

A per-ASN **Exclude from feed** flag was added independently. The score penalty still applies when this is set — the IP is still scored down — but it is suppressed from feed output.

ASN rules can now be edited in place. Previously this required deleting and recreating the rule.

### Exports and SIEM Integration

A CSV export endpoint was added at `/export/csv`. The existing JSON endpoint was retained at `/export/json`.

Both endpoints now require authentication. Previously they were unauthenticated.

Both endpoints are now filter-aware. When no dashboard filters are active, the export applies the configured confidence threshold, minimum score, and time window from Settings — suitable for scheduled ingestion. When filter parameters are passed, they override the configured settings and return exactly the filtered view.

An export API token was added for automation. The token can be passed as an `Authorization: Bearer` header (preferred, not logged by Apache) or as an `?api_key=` query parameter (appears in access logs). The parameter was deliberately named `api_key` rather than `token` to avoid colliding with the `?path=` export filter parameter.

Export settings (confidence threshold, minimum score, time window) are now configurable from the Settings tab.

### Admin UI

Dark mode was added with OS-level preference detection and a manual toggle in the page header. The preference is persisted per browser.

The admin layout is now mobile-responsive with breakpoints at 1100px, 700px, and 480px. The page header is sticky. Tables scroll horizontally within their containers. Date filter inputs now show a visible label on mobile so they are recognisable before being tapped.

The activity feed is now paginated. Rows per page is configurable. The previous approach used a fixed 200-row cap.

A per-IP summary panel was added. When filtering the dashboard by a single exact IP, a summary card appears above the feed showing first seen, last seen, total hits, hit counts by classification, and whether an active ASN rule applies.

A configurable auto-refresh interval was added. It only fires when the dashboard tab is active.

The stylesheet was extracted from inline `<style>` blocks into a standalone `admin.css` file using IBM Plex Sans and IBM Plex Mono. The admin CSS file now requires authentication to serve.

### Security

CSRF tokens were added to all admin POST forms. The token is injected automatically via JavaScript into every form on the page.

Admin login rate limiting was added. Failed attempts are tracked in a new `auth_failures` table (auto-created on first boot). The lockout threshold and window are configurable via `AUTH_MAX_FAILURES` and `AUTH_LOCKOUT_SECS`.

Auth lockout now uses the same IP resolution (`getClientIp()`) as the rest of the application. Previously it used `REMOTE_ADDR` directly, which produced inconsistent results behind a trusted proxy.

The `auth_failures` pruning window was corrected to match the lockout window exactly. The previous implementation used double the lockout window, which allowed old failures to briefly re-count toward a new lockout after expiry.

Constant-time username comparison was added to defeat timing-based username enumeration.

X-Forwarded-For IP spoofing protection was added. The header is only trusted when `TRUSTED_PROXY_IP` is configured and the connecting IP matches. The rightmost XFF entry is used, not the leftmost, since clients control the leftmost value.

The open redirect protection was strengthened. Destination URLs are validated against an http/https allowlist at both write time and redirect time.

SQL injection in `ensureColumn()` was fixed. Table and column names are now validated against hardcoded whitelists before interpolation. The column definition comes from an internal map, never from user input.

Webhook SSRF protection was added. The webhook URL host is checked against private and loopback IP ranges before firing. User agent strings in webhook payloads are sanitised (control characters stripped, truncated to 300 characters) before inclusion in Slack or JSON output.

Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are now sent on all HTML responses.

`display_errors` is now explicitly disabled in the production entry point.

### Infrastructure

GeoIP was consolidated to a single reader in `helpers.php`. The dead `getGeoIpReader()` function (which referenced the unavailable City database) and the duplicate `getMaxMindReaders()` in `db.php` were removed. Default paths updated to `/var/lib/GeoIP/` which is where `geoipupdate` places its databases.

Sessions are now started only for `/admin` routes. Export and feed endpoints do not start a session, which prevents `Set-Cookie` headers from being sent before the endpoint's own `Content-Type` header.

A probabilistic auto-cleanup was added. When data retention is configured, roughly 1% of incoming requests trigger a cleanup pass. No cron job is needed.

`clicked_at` timestamps now use `date('c')` (local timezone) instead of `gmdate('c')` (always UTC regardless of configured timezone).

### Schema

The following were added to `schema.sql`: the `asn_rules` table, the `auth_failures` table, `exclude_from_feed` on both `links` and `asn_rules`, `clicked_at_unix_ms` and `event_type` on `clicks`, nine new indexes, and all default settings keys. `seed.sql` was updated to match the current schema with all required columns present.

### Bug Fixes

The threat feed `minimum confidence` setting had no effect due to a wrong settings key in the query.

Timestamps were stored in UTC regardless of the configured server timezone.

IP spoofing via `X-Forwarded-For` was possible when no proxy configuration was set.

`ensureColumn()` interpolated unsanitised table and column names directly into SQL.

`$path` was referenced in `index.php` before it was assigned, causing 500 errors on export routes.

Export routes returned 500 errors because a session `Set-Cookie` header was emitted before the endpoint's `Content-Type` header.

Table column headers were shifted downward into the first data row due to `position: sticky` being applied to `th` elements inside `overflow-x: auto` containers, where sticky positioning is blocked by the overflow ancestor.

---

## [1.0.0] — April 2, 2026

Custom token tracking with redirect support, full request logging, visitor fingerprinting, tracking pixel support, confidence scoring across four labels, bot signature detection, path-based risk detection, behavioral detection (rapid repeat, burst, multi-token scan), ASN-based scoring rules, skip patterns for noise filtering, admin dashboard with filtering and cleanup tools, threat feed at `/feed/ips.txt`, JSON export, GeoIP enrichment via MaxMind, SQLite backend, HTTP Basic Auth admin.
