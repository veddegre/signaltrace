# Changelog

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
