# Changelog

---

## [v2.7.0] — April 19, 2026

### Webhook Enhancements

Platform preset templates are now available for Slack, Discord, Microsoft Teams, PagerDuty, and Custom (generic JSON) via a dropdown in the Settings tab. Selecting a preset populates the payload template textarea with a correctly formatted template for that platform. The textarea border flashes green on load to confirm the change. Teams uses the Adaptive Card format required by the Teams webhook API. PagerDuty uses the Events API v2 format with a routing_key placeholder. Custom produces a flat generic JSON object with all available placeholders as a starting point for any other endpoint.

A Test button now appears inline next to each webhook URL field (threat and token). Clicking it sends a clearly labelled dummy payload using RFC5737 IP 203.0.113.42 to the configured URL. The result is shown inline in green or red. The test uses the stored template if one is set, otherwise sends the appropriate auto-detected format. Testing is blocked in demo mode.

### IP Enrichment — Shodan InternetDB

SignalTrace now enriches IP addresses with data from Shodan InternetDB (no API key required). Enrichment data — open ports, known CVEs, tags, and hostnames — is cached permanently in a new ip_enrichment table on first sight. Private and reserved IPs are skipped. IPs that return a 404 from Shodan are stored with a not_found flag so they are never retried.

Enrichment is triggered two ways: in the background after a tracked request is logged (using fastcgi_finish_request when available so the visitor is never delayed), and on demand when a details panel is opened in the admin UI. A new IP Reputation box appears in the event details panel below the Request section. A Rescan button refreshes both Shodan and AbuseIPDB data on demand.

### IP Enrichment — AbuseIPDB

AbuseIPDB v2 enrichment is now available as an optional companion to Shodan. Configure an API key and daily lookup cap in Settings > IP Enrichment. The key is masked after saving — only the last four characters are shown, with a Change Key button to reveal the input. The daily limit resets at UTC midnight and is tracked in settings (abuseipdb_used_today, abuseipdb_reset_date). Lookups are skipped once the limit is reached. Explicit rescans bypass the daily limit.

AbuseIPDB data is shown in the same IP Reputation box as Shodan, separated by a labeled divider. The abuse confidence score is color-coded: green below 25%, yellow 25–74%, red 75% and above. Total reports, last reported date, ISP, usage type, domain, and a direct link to the AbuseIPDB page are shown. Both Shodan and AbuseIPDB show their fetched_at timestamp and whether the result is cached or freshly fetched.

### Grafana Export Endpoints

Eleven aggregation endpoints are now wired up and served from index.php (they existed as handler functions in router.php but were never routed):

/export/stats — summary statistics (total, unique IPs, unique tokens, bot/suspicious/uncertain/human counts, avg score, bot %)
/export/stats/extended — extends /export/stats with top countries and top orgs arrays
/export/by-ip — top IPs by hit count with classification breakdown
/export/by-country — hit counts grouped by country code
/export/by-token — hit counts grouped by token with optional ?label= filter
/export/by-org — hit counts grouped by ASN organisation
/export/by-signal — individual confidence_reason signal hit counts (aggregated in PHP from the comma-separated field)
/export/behavioral — IPs that triggered burst, rapid_repeat, fast_repeat, or multi_token_scan signals
/export/over-time — hourly event counts in wide format (bucket, bot, suspicious, uncertain, human)

All export endpoints are added to the reserved routes list so they are never logged as honeypot hits.

The /export/stats and /export/stats/extended responses now include dual field aliases (total + total_events, bot_count + bot_events, etc.) and a bot_pct field for compatibility with both the Splunk app and the Grafana dashboard without requiring field mapping transforms.

### Grafana Dashboard

The pre-built Grafana Infinity dashboard (signaltrace_overview_infinity.json) has been updated:

Panel 7 (Events Over Time) — switched from long format (label/hits columns with groupBy and partitionByValues transformations) to wide format (bucket, bot, suspicious, uncertain, human columns). Transformations removed.
Panel 9 (Top Source IPs) — column selectors corrected from ip_country/ip_org to country/org to match what /export/by-ip returns.
Panel 15 (Behavioral Signal Hits) — URL corrected from /export/behavioral-signals to /export/behavioral. Columns updated to match the endpoint output (ip, org, country, hits).

### Splunk Integration

props.conf updated with:

EVAL-confidence_reasons_mv = split(trim(confidence_reason), ", ") — splits the comma-separated confidence_reason string into a proper multivalue field for use with mvexpand and stats count by confidence_reasons_mv.
CIM field aliases — maps ip → src/src_ip, user_agent → http_user_agent, request_uri → url_path, request_method → http_method, query_string → uri_query, request_host → dest.
Boolean coercions — EVAL-is_bot_bool, EVAL-is_known_token, EVAL-first_hit_for_token.
Numeric type enforcement — EVAL-confidence_score_num, EVAL-prior_events_num, EVAL-clicked_at_ms.
EVAL-subdomain — extracts subdomain label from request_host field.

inputs.conf updated with a full field reference comment listing all indexed fields including new v2.6.0 fields (force_include_in_feed, include_in_email, exclude_from_feed, include_in_token_webhook).

signaltrace_fetch.sh updated with timestamp-based incremental fetching (?from= parameter), improved error handling that exits 0 on transient failures so Splunk does not mark the input as permanently failed, and JSON validation before Python processing.

signaltrace_events.json dashboard updated: classification filter dropdown corrected from likely-human to uncertain, filter syntax changed from bare field filters to | search to avoid Splunk reserved word conflicts, request_host added to the event table.

host → request_host Field Rename

The host field in /export/json and /export/csv output has been renamed to request_host to avoid collision with Splunk's built-in host metadata field, which would shadow the JSON value at index time. Internal database queries, the admin UI, and all other code paths are unchanged — the rename applies only to export output. The Splunk props.conf FIELDALIAS-dest and EVAL-subdomain have been updated to reference request_host.

### Export Field Improvements

The exportClicks and getRecentClicksAdvancedFilteredPaged queries now JOIN the links table and include force_include_in_feed, include_in_email, exclude_from_feed, and include_in_token_webhook in export rows. These fields were previously missing from JSON and CSV exports.

### Bug Fixes

Settings tab auto-opening on fresh /admin load — the tab restore was unconditionally reading localStorage. Now only restores from localStorage when navigating back from a same-origin /admin URL (post-form-submit). Fresh navigation always lands on the dashboard tab.

Grafana /export/by-ip returned ip\_country and ip\_org — renamed to country and org in the query output to match what the Grafana dashboard expects.

AbuseIPDB email_threshold null on save — the email threshold ternary could evaluate to null if the POST field was missing (e.g. when SMTP is not configured and the email section is hidden). Refactored to use a safe intermediate variable with a 'bot' default.

---

## [v2.6.1] — April 19, 2026

Fixed README Docker environment variable table — The email alerting note incorrectly stated that SMTP credentials are not stored in .env. Corrected to reflect that EMAIL_SMTP_* variables are set in .env and written by the entrypoint into config.local.php as PHP constants, where they are never stored in the database or exposed through the admin UI.

---

## [2.6.0] — April 19, 2026

### Email Alerting

SignalTrace can now send plain text email alerts via SMTP when threats are detected. SMTP credentials (`EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_ENCRYPTION`, `EMAIL_SMTP_USER`, `EMAIL_SMTP_PASS`, `EMAIL_SMTP_FROM`) are stored exclusively in `config.local.php` as PHP constants — they are never written to the database or exposed through the admin UI. The Settings tab shows a read-only status panel indicating whether credentials are configured.

Two alert types are supported:

**Threat alerts** fire when an unknown-path hit meets the configured classification threshold (bot, suspicious, uncertain, or all). Deduplicates per IP with a configurable window (default 60 minutes).

**Token alerts** fire when a known token with `include_in_email = 1` is hit, regardless of classification. Deduplicates per IP per token using the same window. Configured per-token via a new checkbox in the Create and Edit token forms, and visible as a column in the token summary table.

Email alerting is completely blocked in demo mode at the function level — no outbound email can be sent regardless of settings.

Requires `phpmailer/phpmailer ^6.9` via Composer (`composer update` after deploying).

### MISP and STIX 2.1 Threat Intel Export

Two new threat feed endpoints export enriched indicator data for consumption by threat intelligence platforms:

- `/feed/misp.json` — MISP event format with `ip-src` attributes, RFC3339 timestamps, per-IP comments including classification, score, hit count, org, and country. Threat level derived from worst classification in the batch.
- `/feed/stix.json` — STIX 2.1 bundle with `indicator` objects using UUIDv5 (stable across exports for the same IP), correct `ipv4-addr` and `ipv6-addr` pattern types, confidence values mapped to the STIX convention (85/50/15), and `valid_from`/`valid_until` in RFC3339 UTC.

Both endpoints use the same admin Basic Auth or export API token as the existing feed endpoints. Both include IPv4 and IPv6 in a single export.

**Important:** MISP and STIX exports are capped at bot and suspicious classifications regardless of the threat feed minimum confidence setting. Uncertain and human-classified IPs are excluded because these formats are consumed by platforms that act automatically on the data.

### Per-Token Force Include in Feed

Tokens now have a `force_include_in_feed` flag alongside the existing `exclude_from_feed`. When enabled, any IP that hits the token is added to the threat feed regardless of confidence classification — useful for canary tokens where any hit is inherently suspicious. Force-include overrides exclude if both are set. For MISP and STIX exports, force-include tokens are still capped at suspicious. Added to Create and Edit token forms and the token summary table.

### Wildcard DNS Mode

A new **Wildcard DNS mode** setting enables subdomain visibility across the dashboard when a wildcard DNS record is in use. When enabled:

- A **Subdomain** column appears in the activity table showing the subdomain prefix (e.g. `vpn`, `login`, `mail`) extracted from the Host header relative to the configured base URL. Hidden on mobile. Clicking a subdomain filters to all hits from that host.
- A **host** filter field appears in the filter bar for searching by subdomain or full host value.
- A **Subdomain Activity** summary panel appears above the activity feed showing hit counts, bot hits, and first/last seen per subdomain. Supports the same hide/show toggle and date range filtering as the behavioral panel.

See the [Wildcard DNS Honeypot wiki page](https://github.com/veddegre/signaltrace/wiki/Wildcard-DNS-Honeypot) for setup instructions including Apache vhost configuration and wildcard TLS certificates.

### Behavioral Flags Panel Improvements

Three new settings control the Behavioral Flagged IPs panel:

- **Behavioral Flags Window** — configurable time window in hours (default 24h, previously hardcoded)
- **Behavioral Flags Max Rows** — maximum IPs shown in the panel (default 25, previously hardcoded at 50)
- **Hide Behavioral Flags panel by default** — panel starts collapsed on every page load; can still be expanded manually

The panel heading now shows a dynamic window label (e.g. "last 12h", "last 7d"). Hide/show state is preserved across pagination. A corresponding **Hide Subdomain Activity panel by default** setting was added for the new subdomain panel.

### Infrastructure and Setup

**Docker entrypoint** — `docker/entrypoint.sh` now writes `DEMO_MODE`, `DEMO_ADMIN_USERNAME`, `DEMO_ADMIN_PASSWORD`, `CF_ACCESS_ENABLED`, `CF_ACCESS_AUD`, `CF_ACCESS_TEAM_DOMAIN`, and all `EMAIL_SMTP_*` constants into `config.local.php` at container startup. These were previously silently ignored if set in `.env`.

**`.env.example`** — All variables are now documented including Cloudflare Access (`CF_ACCESS_ENABLED`, `CF_ACCESS_AUD`, `CF_ACCESS_TEAM_DOMAIN`), demo mode (`DEMO_MODE`, `DEMO_ADMIN_USERNAME`, `DEMO_ADMIN_PASSWORD`), and email SMTP (`EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_ENCRYPTION`, `EMAIL_SMTP_USER`, `EMAIL_SMTP_PASS`, `EMAIL_SMTP_FROM`). SMTP variables are settable in `.env` — the entrypoint writes them as PHP constants into `config.local.php` so they never touch the database.

**`setup.sh`** — When an existing `config.local.php` is found, the script now offers Update / Overwrite / Abort instead of always overwriting. All prompts pre-fill current values when updating. The email alerting section now shows a security warning about SMTP credential storage before prompting, and presents a Keep / Reconfigure / Remove menu when credentials already exist.

### Bug Fixes

**Subdomain summary panel grouping** — The subdomain activity panel was grouping by raw `Host` header value, so IPs appearing under multiple Host variants created separate rows. The panel now aggregates by extracted subdomain label in PHP. Same-subdomain rows are correctly merged.

**Wildcard host filter** — The host filter in the activity feed was doing a plain `LIKE` match against the raw host column. It now correctly handles `*` (no constraint), `(root)` (exact base domain), short subdomain labels (resolves to `label.basedomain`), and external hosts.

**Demo banner countdown using wrong time reference** — The countdown now takes the minimum of `last_reset_time + 3600` and the next top-of-the-hour, so manually triggered resets show an accurate remaining time rather than a full 60 minutes.

---

## [2.5.5] — April 18, 2026

### Bug Fixes

**Token webhook per-token opt-in not saving** — The `include_in_token_webhook` checkbox was rendering correctly in both the Create Token and Edit Token forms but the value was never read from POST or written to the database. Fixed by reading the field in `handleCreateLink()` and `handleUpdateLink()` in `admin_actions.php` and passing it through to `createLink()` and `updateLink()` in `db.php`. Also added `include_in_token_webhook` to `$linksColumnDefinitions` so existing installs automatically receive the column via `ALTER TABLE` on next boot rather than throwing a 500 on any token create or update.

---

## [2.5.4] — April 18, 2026

### Security Hardening

**Strict Content-Security-Policy on admin routes** — The admin panel now sends a strict `Content-Security-Policy` header with a per-request cryptographic nonce. `script-src` is restricted to `'nonce-...'` with no `unsafe-inline`, meaning any injected script payload that bypasses output escaping will be refused by the browser. All inline `onclick`, `onsubmit`, and other event handler attributes have been replaced with `data-*` attributes handled by a single delegated event listener block. The nonce is generated in `index.php` and shared with `demo-banner.php` so both script blocks are covered. Non-admin routes (feeds, exports, honeypot paths) retain the existing policy unchanged.

**SQLite busy_timeout** — Added `PRAGMA busy_timeout = 5000` to the PDO initialization block so concurrent write attempts during bot traffic bursts queue gracefully rather than throwing immediate "database is locked" exceptions.

**Auth failure prune moved out of hot path** — `recordAuthFailure()` previously ran a `DELETE` query on every failed login attempt to prune expired lockout records. Under a brute-force attack this amplified I/O on every bad password. Pruning is now handled probabilistically via `maybeRunAutoCleanup()` alongside the existing click retention cleanup, keeping the auth path lean under load.

**Compound indexes for high-traffic queries** — Three new compound indexes added to the `clicks` table: `idx_clicks_feed` covering `(event_type, clicked_at_unix_ms, confidence_label)` for the threat feed query, `idx_clicks_export` covering `(confidence_label, clicked_at_unix_ms)` for export and aggregation endpoints, and `idx_clicks_ip_time` covering `(ip, clicked_at_unix_ms)` for IP summary, rate limiting, and behavioral flag queries.

---

## [2.5.3] — April 17, 2026

### Bug Fixes

**Behavioral Flagged IPs panel not staying hidden across pagination** — The `hide_behavioral` parameter was not being preserved in pagination links or the hide/show toggle URL, causing the panel to reappear on page changes and the toggle to reset to page 1. Fixed by capturing `$hideBehavioral` as a variable before the `$buildAdminUrl` closure is defined and including it in the closure's `use` list so all generated URLs carry the parameter consistently.

**Missing spacing below Behavioral Flagged IPs when hidden** — When the behavioral panel was hidden, the Activity heading rendered with no top margin. A consistent spacer is now rendered after the behavioral section regardless of its visibility state.

**Stray backtick parse error in `admin_view.php`** — A backtick was inserted by the GitHub web editor's markdown rendering when committing the file, causing a PHP parse error on line 1848. Fixed in the clean output file. When committing PHP files via the GitHub web interface, use raw file upload rather than the edit view to prevent markdown interpretation.

---

## [2.5.2] — April 16, 2026

### Admin View Fixes and Restore Missing Features

**Behavioral Flagged IPs panel** — The panel now collapses automatically when an IP filter is active, so clicking a flagged IP no longer buries the IP summary below a full table of results. The Hide/Show toggle is restored. Block/Allow actions are restored in the behavioral table rows. The IP link now forces `show_all=1` so all hits for that IP are visible regardless of the display minimum score setting.

**IP summary panel** — Block IP and Allow IP action buttons are restored below the summary stats when no override exists for the filtered IP. When an override is already active, the current mode badge and a Manage link are shown instead.

**Token webhook per-token opt-in** — The "Fire token webhook on hit" checkbox was missing from both the Create Token and Edit Token forms, and from the token summary table. All three are restored.

**`uncertain` label rename gaps** — Several places still referenced `likely-human` after the rename: the confidence badge class in the activity table, the IP summary "Likely-human hits" label and `likely_human_count` column, and the threat feed minimum confidence dropdown. All corrected to `uncertain`.

**`renderSignalReasons` and `signalLabel`** — These functions were dropped from `admin_view.php` during a rebuild from an uploaded server file. Both functions and the `renderSignalReasons()` call in the scoring detail panel are restored.

---

## [2.5.1] — April 16, 2026

### Bug Fixes

**Cloudflare Access blocking feed and export endpoints** — CF Access JWT verification was running on all paths that called `requireAdminAuth()`, including threat feed endpoints (`/feed/...`) and export endpoints (`/export/...`). These endpoints use token-based authentication and are accessed directly by Splunk, Grafana, firewalls, and other integrations that have no Cloudflare Access session. CF Access verification is now scoped to `/admin` paths only.

**PHP parse error in `exportOverTime()`** — The `AS INTEGER` SQL keyword inside an interpolated string caused a PHP parse error when the function was first loaded. The bucket size calculation is now pre-computed as a plain integer variable before string interpolation.

---

## [2.5.0] — April 16, 2026

### Cloudflare Access Integration

The admin panel can now be protected by Cloudflare Zero Trust as an optional first authentication layer. When `CF_ACCESS_ENABLED` is true, SignalTrace verifies the `Cf-Access-Jwt-Assertion` JWT against Cloudflare's published public keys before allowing any request to reach the admin UI. The Basic Auth prompt is bypassed once CF Access verification passes, since Cloudflare Access with MFA already provides strong identity assurance.

CF Access verification is skipped when `CF_ACCESS_ENABLED` is false (the default) or when `DEMO_MODE` is true. Existing installs are completely unaffected unless the three new constants are added to `config.local.php`. See the [Cloudflare Access wiki page](https://github.com/veddegre/signaltrace/wiki/Cloudflare-Access) for full setup instructions.

New constants in `config.local.php`:
- `CF_ACCESS_ENABLED` — set to `true` to enable verification
- `CF_ACCESS_AUD` — the AUD token from Zero Trust → Applications → Additional settings → Token
- `CF_ACCESS_TEAM_DOMAIN` — your team domain from Zero Trust → Settings → Teams tab

Requires `firebase/php-jwt ^6.0` via Composer.

### Redirect Rate Limiting

Known token redirects are now rate limited to prevent SignalTrace from being used as an unwitting HTTP flood origin. When an IP exceeds the configured number of redirects to the same token within the configured window, SignalTrace returns a 429 with a `Retry-After` header instead of redirecting. The click is still logged regardless — rate limiting only affects the redirect response.

New settings:
- **Redirect Rate Limit** — maximum redirects per IP per token within the window (default: 10). Set to 0 to disable.
- **Redirect Rate Limit Window** — time window in seconds (default: 60).

Rate limiting applies to known tokens only. Unknown path behavior (redirect or 404) is unaffected.

### Demo Mode Lockdowns

The following settings are now locked when `DEMO_MODE` is true, blocking both the UI and direct POST requests:

- App Name, Base URL, Default Redirect URL
- Threat Webhook URL and Template
- Token Webhook URL and Template
- Redirect Rate Limit settings
- Data Retention settings
- Manual Cleanup action

Locked fields render as read-only in the Settings UI with a "Not configurable in demo mode" notice. All other settings remain fully editable.

### `likely-human` Renamed to `uncertain`

The confidence label `likely-human` has been renamed to `uncertain` across the entire codebase. The name more accurately reflects what the 60–74 score band means — the system is not confident either way.

A database migration runs automatically on boot for existing installs:
```sql
UPDATE clicks SET confidence_label = 'uncertain' WHERE confidence_label = 'likely-human';
UPDATE settings SET value = 'uncertain' WHERE key IN ('export_min_confidence', 'threat_feed_min_confidence', 'webhook_threshold') AND value = 'likely-human';
```

### Grafana Time Range on All Panels

All 16 Grafana dashboard panels now respect the Grafana time range picker. Previously only the Events Over Time panel responded to time range changes — all other panels used the configured export window. All panel URLs now pass `${__from}` and `${__to}` as Unix millisecond timestamps, and `buildExportWhere()` uses `clicked_at_unix_ms` for precise filtering while keeping the confidence threshold applied.

### `setup.sh` Updates

The setup script now prompts for Cloudflare Access configuration (manual installs only), demo mode settings (App Name, Base URL, Default Redirect URL, banner credentials), and correctly writes all prompted values to `config.local.php`. A bug where `SELF_REFERER_DOMAIN` and MaxMind credentials were collected but never written to the config file has been fixed. The Composer step now uses `composer update` instead of `composer install` to handle lock file mismatches on new package additions.

---

## [2.4.1] — April 15, 2026

### Grafana Dashboard — Expanded

The Grafana dashboard was expanded from 8 to 16 panels to match the coverage of the Splunk Overview dashboard. All panels use server-side aggregation endpoints with no Grafana transformations required.

New panels added: **Unique Tokens** and **Bot %** stat panels; **Events Over Time** timeseries with per-label color coding; **Top Tokens / Paths** and **Top Bot-Classified Tokens** bar gauges; **Top ASN Organizations** table; **Top Detection Signals** and **Behavioral Signal Hits** bar gauges.

The Events Over Time panel uses adaptive time bucketing based on the Grafana time range: 15-minute buckets for ranges under 6 hours, 1-hour for 6–48 hours, 6-hour for 2–14 days, and 1-day for longer ranges. The bucket size is calculated server-side and requires no Grafana configuration.

### New Export Endpoints

Six new server-side aggregation endpoints were added, all sharing the same filter logic as `/export/json`:

**`/export/stats/extended`** — extends `/export/stats` with `unique_tokens` and `bot_pct` (bot percentage as a float).

**`/export/by-token`** — top tokens by hit count. Accepts `limit` (default 5) and optional `label` filter (e.g. `label=bot`) for the bot-classified tokens panel.

**`/export/by-org`** — top ASN organisations by hit count. Accepts `limit` (default 5).

**`/export/by-signal`** — top confidence reason signals, exploded from the comma-separated `confidence_reason` field. Excludes `country_penalty` and `ip_override` meta-reasons. Accepts `limit` (default 8).

**`/export/behavioral-signals`** — returns only behavioral signal hits: `burst_activity`, `rapid_repeat`, `fast_repeat`, and `multi_token_scan`. Server-side filtered so no Grafana transformation is needed.

**`/export/over-time`** — events bucketed by confidence label over time. Accepts `from` and `to` as Unix timestamps in milliseconds. Bucket size adapts automatically to the span.

### Webhook System Redesign

The webhook system was split into two independent webhooks serving different use cases.

**Threat webhook** (existing, enhanced): fires on unknown-path hits that meet the configured classification threshold. A new **Threat Webhook Threshold** setting was added with options: bot only (default), suspicious and above, uncertain and above, or all hits. The webhook skips known token hits — those are handled by the token webhook instead.

**Token webhook** (new): fires when a known tracked token is hit, regardless of classification. Useful for phishing simulations and campaign tracking where any interaction — including human — is significant. Configured via **Token Webhook URL** and **Token Webhook Template** in Settings. Uses the same `{{placeholder}}` template syntax as the threat webhook. Auto-detects Slack and Discord format when no template is set. Deduplicates per visitor hash per token per 5 minutes.

Per-token opt-in: each token has a new **Send token webhook on hit** checkbox. The token webhook only fires for tokens where this is enabled. The token summary table shows the current flag state for each token.

Both webhooks support the same placeholders: `{{ip}}`, `{{token}}`, `{{label}}`, `{{score}}`, `{{org}}`, `{{asn}}`, `{{country}}`, `{{ua}}`, `{{time}}`, `{{triggers}}`.

### Admin Dashboard — IP Summary Improvements

The IP summary card (shown when filtering by a single exact IP) was expanded with several additions:

**Copy / VT / Abuse / Info** links now appear inline next to the IP address for quick access to VirusTotal, AbuseIPDB, and IPInfo without opening a details row.

**ASN rule management**: the ASN field shows an Add ASN Rule button when no rule exists, or an "ASN rule active" badge with the penalty if one does. The org name is pre-filled as the rule label.

**Block / Allow buttons** were added to the IP summary card. If an override already exists the current mode is shown with a link to manage it.

### Admin Dashboard — Behaviorally Flagged IPs Improvements

A **Hide / Show** toggle was added to the Behaviorally Flagged IPs panel heading. Clicking Hide collapses the table and shows a Show (N) link with the count. The `hide_behavioral` URL parameter preserves state across pagination and filter changes.

Clicking an IP in the behavioral table now navigates to the filtered feed with `show_all=1` forced (bypassing the display minimum score setting) and `hide_behavioral=1` set (collapsing the panel so the feed is immediately visible).

### Scoring — Signal Reason Labels

The Reason field in the details panel now displays confidence signals as colored pill tags with friendly descriptions rather than raw internal signal names. Four categories: green for positive signals, red for negative signals, amber for behavioral signals, and blue for rule-based signals (path, country, ASN, IP override).

The raw signal name is preserved as a browser tooltip on hover for cross-referencing with exports and the wiki. Unknown signals fall back to displaying the raw name so no information is lost.

### Bug Fix — Root Path Logging for Admin Sessions

The browser prefetch of `/` that occurs when navigating to `/admin` was being logged as a honeypot hit. A session flag (`admin_authenticated`) is now set in `requireAdminAuth()` after successful login. In `handleTrackedRequest()`, requests to `/` are silently suppressed when this flag is present. Non-admin traffic to `/` is logged normally. Works correctly for the demo instance and shared deployments.

### Schema

`include_in_token_webhook INTEGER NOT NULL DEFAULT 0` was added to the `links` table. `webhook_threshold`, `token_webhook_url`, and `token_webhook_template` were added to the default settings. `schema.sql` and `seed.sql` were updated to reflect all changes. The `ensureColumn` migration in `db.php` handles existing databases automatically.

---

## [2.4.0] — April 14, 2026

### Grafana Integration

A pre-built Grafana dashboard was added at `grafana/signaltrace-dashboard.json`. The dashboard uses the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) and requires no Grafana transformations — all aggregation is done server-side.

Three aggregation API endpoints were added: **`/export/stats`** (summary counts), **`/export/by-ip`** (top IPs by hit count), and **`/export/by-country`** (top countries by hit count). All share the same filter logic as `/export/json`.

The initial dashboard included eight panels: Total Events, Bot Events, Unique IPs, and Avg Confidence Score (stat panels); Confidence Label Distribution (donut chart); Top Source IPs and Top Countries (bar gauge panels); and Recent Events (table).

### Export Filter Passthrough Fix

Dashboard filters were not being passed through to the CSV and JSON export links. The `handleExport()` function in `router.php` was refactored to use a shared `parseExportFilters()` helper.

### Splunk Dashboards

The **Overview** dashboard was updated with Top Detection Signals and Behavioral Signal Hits panels. The **Event Investigation** dashboard was updated with Country and Detection Signal filter inputs and the `confidence_reason` field added to the results table.

### Documentation

A Grafana Integration wiki page was added. The API Reference and Tuning Guide wiki pages were updated.

---

## [2.3.1] — April 12, 2026

### Infrastructure

A GitHub Actions workflow was added at `.github/workflows/docker-image.yml`. On every push to `main`, the workflow builds the Docker image and publishes it to `ghcr.io/veddegre/signaltrace:latest`. A pre-built image path was added to `setup.sh` as the default installation option. A `docker-compose.prebuilt.yml` override file was added.

---

## [2.3.0] — April 11, 2026

### Demo Infrastructure

A live demo instance was added at `trysignaltrace.com/admin`. An optional demo banner (`includes/demo-banner.php`) displays when `define('DEMO_MODE', true)` is set in `config.local.php`. A marketing website was added at `www.trysignaltrace.com`.

---

## [2.2.0] — April 9, 2026

### Threat Feed — Multiple Formats and IPv6

Eight feed endpoints now available across IPv4 and IPv6 in plain text, Nginx deny, iptables, and CIDR formats. IPv6 addresses are normalized to canonical compressed form. A feed preview count and all endpoint URLs were added to the Settings tab.

### Threat Feed — IP Validation and Minimum Hits

IP addresses are now validated before inclusion in feed output. A minimum hits threshold was added — an IP must be seen at least N times within the window before appearing in any feed.

### IP Overrides

A new **IP Overrides** tab was added. Overrides bypass scoring entirely and pin an IP to always-block (bot, score 0) or always-allow (human, score 100). Block/Allow buttons appear in the activity feed details row.

### Country Rules

A new **Country Rules** tab was added. Rules apply a configurable score penalty by 2-letter ISO country code. Affect scoring only — do not suppress IPs from the threat feed.

### Behaviorally Flagged IPs Panel

A panel on the Dashboard tab shows IPs that triggered burst, rapid-repeat, or multi-token-scan signals in the last 24 hours.

### Webhook Improvements

A **Webhook Payload Template** field was added with `{{placeholder}}` syntax. Templates are validated on save. `{{country}}` and `{{triggers}}` were added to default payloads.

### Dashboard — Bulk Delete by Filter

A Bulk Delete section appears when any filter is active, allowing deletion of all matching clicks in one action.

### Dashboard — Top Tokens Panel

A Show Top Tokens checkbox was added to the filter bar.

### Scoring

Sec-Fetch and Sec-CH-UA checks are now browser-aware (Safari excluded from Sec-Fetch penalties; Client Hints penalty only applies to Chromium UAs). Self-referrer penalty added. Datacenter IP detection broadened.

### Token and ASN Management

Per-token and per-ASN exclude-from-feed flags added. ASN rules can now be edited in place.

### Exports and SIEM Integration

CSV export added at `/export/csv`. Both export endpoints now require authentication and are filter-aware. Export API token added for automation. Export settings configurable from Settings tab.

### Admin UI

Dark mode added with OS preference detection and manual toggle. Mobile-responsive layout at 1100px, 700px, and 480px breakpoints. Paginated activity feed. Per-IP summary panel. Configurable auto-refresh. Stylesheet extracted to `admin.css`.

### Security

CSRF tokens on all admin POST forms. Admin login rate limiting with configurable threshold and lockout. Constant-time username comparison. XFF spoofing protection. Strengthened redirect validation. `ensureColumn()` SQL injection fix. Webhook SSRF protection. Security response headers. `display_errors` disabled.

### Schema

`asn_rules` table, `auth_failures` table, `exclude_from_feed` on links and asn_rules, `clicked_at_unix_ms` and `event_type` on clicks, nine new indexes, all default settings keys.

---

## [1.0.0] — April 2, 2026

Custom token tracking with redirect support, full request logging, visitor fingerprinting, tracking pixel support, confidence scoring across four labels, bot signature detection, path-based risk detection, behavioral detection (rapid repeat, burst, multi-token scan), ASN-based scoring rules, skip patterns for noise filtering, admin dashboard with filtering and cleanup tools, threat feed at `/feed/ips.txt`, JSON export, GeoIP enrichment via MaxMind, SQLite backend, HTTP Basic Auth admin.
