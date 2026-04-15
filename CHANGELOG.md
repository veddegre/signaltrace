# Changelog

---

## [2.4.0] — April 14, 2026

### Grafana Integration

A pre-built Grafana dashboard was added at `grafana/signaltrace-dashboard.json`. The dashboard uses the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) and requires no Grafana transformations — all aggregation is done server-side.

Three new aggregation API endpoints were added:

**`/export/stats`** — returns a single JSON object with pre-aggregated summary counts: total events, bot count, suspicious count, likely-human count, human count, unique IPs, and average confidence score. Used by the stat panels and pie chart.

**`/export/by-ip`** — returns top source IPs by hit count, pre-aggregated and sorted descending. Accepts an optional `limit` parameter (default 20, max 500). Used by the Top Source IPs panel.

**`/export/by-country`** — returns top countries by hit count, pre-aggregated and sorted descending. Accepts an optional `limit` parameter (default 20, max 500). Used by the Top Countries panel.

All three endpoints share the same filter logic as `/export/json` — when `date_from` or `date_to` parameters are present the configured export settings are bypassed, otherwise the configured confidence threshold and time window apply.

The dashboard includes eight panels: Total Events, Bot Events, Unique IPs, and Avg Confidence Score (stat panels); Confidence Label Distribution (donut chart); Top Source IPs and Top Countries (bar gauge panels); and Recent Events (table). Two dashboard variables are prompted on import: the Infinity datasource and the SignalTrace base URL. Authentication is handled at the datasource level via a Bearer token — no token variable is stored in the dashboard JSON.

### Threat Feed — Multiple Formats and IPv6

The threat feed is now split into separate IPv4 and IPv6 endpoints to avoid confusing downstream tools that expect one address family. Eight endpoints are now available:

**IPv4:** `/feed/ips.txt`, `/feed/ips.nginx`, `/feed/ips.iptables`, `/feed/ips.cidr`
**IPv6:** `/feed/ipv6.txt`, `/feed/ipv6.nginx`, `/feed/ipv6.iptables`, `/feed/ipv6.cidr`

Format details: `.txt` is one IP per line; `.nginx` emits `deny <ip>;` blocks; `.iptables` emits a complete iptables-restore-compatible filter block with a header comment; `.cidr` appends `/32` (IPv4) or `/128` (IPv6) to each address.

IPv6 addresses are normalized to their canonical compressed form via an `inet_pton`/`inet_ntop` round-trip before output, so addresses are always consistent regardless of how they were stored.

The existing `/feed/ips.txt` endpoint is unchanged and remains the legacy alias for the IPv4 plain-text feed.

A feed preview now appears in the Settings tab showing the current count of IPv4 and IPv6 addresses in the feed. All eight feed URLs are listed with Copy and Open buttons grouped by address family.

### Threat Feed — IP Validation and Minimum Hits

The threat feed now validates every IP address via `filter_var(FILTER_VALIDATE_IP)` before including it in output. Values like `unknown` that may have been stored in edge cases are silently dropped.

A **Minimum hits before adding to feed** setting was added to the Threat Feed section of Settings. An IP must be seen at least this many times within the configured window before appearing in any feed. Default is 1, preserving previous behaviour.

### IP Overrides

A new **IP Overrides** tab was added between Country Rules and Settings. Overrides bypass scoring entirely and apply a fixed classification to all future requests from the specified IP:

* **Block** — always classified as bot (score 0, label `bot`, reason `ip_override:block`)
* **Allow** — always classified as human (score 100, label `human`, reason `ip_override:allow`)

Overrides apply to future requests only and do not retroactively change stored click data. Allowed IPs are also excluded from all threat feed output. Blocked IPs always appear in the threat feed regardless of confidence threshold or minimum hit count.

Quick Block and Allow buttons appear in the details row of the activity feed for any IP that does not already have an override. If an override exists, the current mode is shown with a link to manage it. The override map is preloaded once per page render rather than queried per row.

### Country Rules

A new **Country Rules** tab was added. Country rules apply a configurable score penalty to all requests from a specified country, identified by 2-letter ISO code. Rules affect scoring only — they do not exclude IPs from the threat feed.

Each rule has a country code, optional label, and penalty (1–100). Rules can be activated, deactivated, and deleted. The country penalty is applied after all other scoring signals and before the final label is assigned. The reason field records `country_penalty:XX` so the effect is visible in the activity feed details.

### Splunk Dashboards

The **Overview** dashboard (`signaltrace_overview.json`) was updated with two new panels in a bottom row: **Top Detection Signals** showing the top 8 confidence reason signals across all events (excluding `country_penalty` and `ip_override` entries); and **Behavioral Signal Hits** showing counts for burst, rapid-repeat, fast-repeat, and multi-token-scan signals specifically. The top tokens and bot tokens row was repositioned to accommodate the new bottom row. Traffic by Country and Top ASN Organizations were converted from bar charts to tables.

The **Event Investigation** dashboard (`signaltrace_events.json`) was updated with two additional filter inputs: **Country** (2-letter ISO code, applied as a post-filter `where` clause) and **Detection Signal / Reason** (matches against `confidence_reason` using regex, supporting values like `country_penalty:CN` or `ip_override:block`). The `confidence_reason` field was added to the results table. Both new filters default to `*` (show all) and apply on Enter.

### Behaviorally Flagged IPs Panel

A **Behaviorally Flagged IPs** panel now appears on the Dashboard tab when any IPs have triggered behavioral signals in the last 24 hours. The panel shows IPs that produced burst, rapid-repeat, or multi-token-scan signals, with per-signal hit counts, total hits, org, country, lowest score, and first/last seen. Each IP links directly to the filtered activity feed.

### Webhook Improvements

A **Webhook Payload Template** field was added to Settings. When set, the template is used instead of the Slack/Discord auto-detected format or generic JSON default. Templates use `{{placeholder}}` syntax. Available placeholders: `{{ip}}`, `{{token}}`, `{{label}}`, `{{score}}`, `{{org}}`, `{{asn}}`, `{{country}}`, `{{ua}}`, `{{time}}`, `{{triggers}}`.

The template is validated on save by substituting dummy values and checking that the result parses as valid JSON. Leaving the field blank preserves the existing auto-detection behaviour.

`{{country}}` and `{{triggers}}` were also added to the default Slack/Discord and generic JSON payloads, which previously omitted them.

### Dashboard — Bulk Delete by Filter

A **Bulk Delete** section now appears on the Dashboard tab whenever any filter is active. It shows the count of matching clicks and provides a single button to delete all of them. At least one filter must be active — bulk delete with no filters is rejected by the server to prevent accidental full-table wipes.

### Dashboard — Filter Preservation

Actions taken from the details row (Delete Click, Skip Token, Delete Token Hits, Block IP, Allow IP) now redirect back to the dashboard with all active filters preserved. Previously these actions always redirected to the unfiltered dashboard, discarding the current filter state.

### Documentation

A **Grafana Integration** wiki page was added covering datasource setup, dashboard import, variable configuration, all API endpoints, panel descriptions, and Nginx `Authorization` header passthrough requirements.

The **API Reference** wiki page was updated to document the three new aggregation endpoints, expand the `/export/json` filter table to include `visitor=` and `known=1`, clarify that date-filtered exports bypass the confidence threshold, move the Nginx header passthrough note into the Authentication section, and add the full feed format table.

The **Tuning Guide** wiki page was updated to add Country Rules and IP Overrides sections.

### Admin Tab Reorder

The tab order was changed to reflect a more logical progression from investigative to configuration tabs:

**Dashboard | Tokens | Skip Patterns | ASN Rules | Country Rules | IP Overrides | Settings**

### Bug Fixes

Dashboard filters (`ip`, `path`, `visitor`, `known`, `date_from`, `date_to`) were not being passed through to the CSV and JSON export links on the admin dashboard. The `handleExport()` function in `router.php` was refactored to use a shared `parseExportFilters()` helper, ensuring active dashboard filters are correctly applied to both export formats.

The threat feed query used a `HAVING hit_count >= ?` clause with a bound parameter. SQLite PDO does not reliably evaluate bound parameters in HAVING clauses when the alias references an aggregate — the query always returned empty. Fixed by interpolating the validated integer directly: `HAVING COUNT(*) >= {$minHits}`.

The threat feed time window comparison used `clicked_at >= datetime('now', '-N hours')`. Timestamps are stored with a timezone offset (e.g. `2026-04-13T20:13:06-04:00`) which SQLite compares as strings rather than datetimes, causing the comparison to fail silently. Fixed by switching to `clicked_at_unix_ms >= (strftime('%s','now') - N * 3600) * 1000`, which is timezone-independent integer arithmetic.

The webhook deduplication check in `shouldSendAlert()` was counting the click that had just been stored by `logClick()` against itself, causing `shouldSendAlert()` to always return false after the first bot hit from any IP. Fixed by finding the most recent bot click ID for the IP and excluding it from the count, so only prior hits within the 5-minute window are considered.

---

## [2.3.1] — April 12, 2026

### GitHub Actions & Pre-built Image

A GitHub Actions workflow (`docker.yml`) was added. It builds and pushes the Docker image to `ghcr.io/veddegre/signaltrace` on every push to `main` and on version tags. Pushing `v2.3.1` publishes both `ghcr.io/veddegre/signaltrace:2.3.1` and `ghcr.io/veddegre/signaltrace:latest`.

`docker-compose.prebuilt.yml` was added as a Compose override that nulls out the `build` directive and sets the image to `ghcr.io/veddegre/signaltrace:latest`. Used with:
