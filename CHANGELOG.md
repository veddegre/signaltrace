# Changelog

---

## [2.0.0] — 2026

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

## [1.0.0] — Initial Release

Custom token tracking with redirect support, full request logging, visitor fingerprinting, tracking pixel support, confidence scoring across four labels, bot signature detection, path-based risk detection, behavioral detection (rapid repeat, burst, multi-token scan), ASN-based scoring rules, skip patterns for noise filtering, admin dashboard with filtering and cleanup tools, threat feed at `/feed/ips.txt`, JSON export, GeoIP enrichment via MaxMind, SQLite backend, HTTP Basic Auth admin.
