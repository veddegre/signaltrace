-- SignalTrace Seed Data (Safe / Non-Real)
-- Uses documentation IP ranges (RFC 5737 / RFC 3849)
-- All IPs, ASNs, and orgs are fictitious.

PRAGMA foreign_keys = ON;

-- ============================================================
-- Sample Tokens
-- ============================================================
INSERT OR IGNORE INTO links (token, destination, description, active, exclude_from_feed, include_in_token_webhook, created_at) VALUES
    ('/payroll',     'https://example.com/login',    'Payroll portal simulation', 1, 0, 1, datetime('now')),
    ('/invoice',     'https://example.com/invoice',  'Invoice access link',       1, 0, 1, datetime('now')),
    ('/benefits',    'https://example.com/benefits', 'Benefits portal',           1, 0, 0, datetime('now')),
    ('/hello.world', 'https://example.com',          'Test token',                1, 0, 0, datetime('now'));

-- ============================================================
-- Sample Clicks
-- clicked_at_unix_ms = strftime('%s', clicked_at) * 1000
-- All within the last 48 hours so they appear in the threat feed
-- ============================================================
INSERT INTO clicks (
    token, link_id, clicked_at, clicked_at_unix_ms,
    ip, ip_asn, ip_org, ip_country,
    visitor_hash, request_method, host, scheme, request_uri, query_string,
    remote_port, user_agent, referer, accept, accept_language, accept_encoding,
    sec_fetch_site, sec_fetch_mode, sec_fetch_dest,
    is_bot, bot_reason, confidence_score, confidence_label, confidence_reason,
    first_for_token, prior_events_for_token
) VALUES

-- ── Human clicks ─────────────────────────────────────────────

(
    '/payroll',
    (SELECT id FROM links WHERE token = '/payroll'),
    datetime('now', '-5 minutes'),
    (strftime('%s', datetime('now', '-5 minutes')) * 1000),
    '203.0.113.10', '64500', 'Example ISP', 'US', 'visitor_demo_1',
    'GET', 'yourdomain.example', 'https', '/payroll', '',
    52344,
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    '', 'text/html,application/xhtml+xml', 'en-US,en;q=0.9', 'gzip, deflate, br',
    'none', 'navigate', 'document',
    0, '', 88, 'human', 'get_request, browser_ua, sec_fetch_navigate, accept_language_present',
    1, 0
),
(
    '/invoice',
    (SELECT id FROM links WHERE token = '/invoice'),
    datetime('now', '-12 minutes'),
    (strftime('%s', datetime('now', '-12 minutes')) * 1000),
    '203.0.113.42', '64500', 'Example ISP', 'CA', 'visitor_demo_2',
    'GET', 'yourdomain.example', 'https', '/invoice', '',
    49871,
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0 Safari/537.36',
    'https://mail.example.com/', 'text/html,application/xhtml+xml', 'en-CA,en;q=0.9', 'gzip, deflate, br',
    'cross-site', 'navigate', 'document',
    0, '', 92, 'human', 'get_request, browser_ua, sec_fetch_navigate, referer_present',
    1, 0
),
(
    '/benefits',
    (SELECT id FROM links WHERE token = '/benefits'),
    datetime('now', '-31 minutes'),
    (strftime('%s', datetime('now', '-31 minutes')) * 1000),
    '203.0.113.78', '64500', 'Example ISP', 'GB', 'visitor_demo_3',
    'GET', 'yourdomain.example', 'https', '/benefits', '',
    61022,
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
    '', 'text/html,application/xhtml+xml', 'en-GB,en;q=0.9', 'gzip, deflate, br',
    'none', 'navigate', 'document',
    0, '', 80, 'human', 'get_request, browser_ua, sec_fetch_navigate',
    1, 0
),

-- ── Suspicious clicks ─────────────────────────────────────────

(
    '/invoice',
    (SELECT id FROM links WHERE token = '/invoice'),
    datetime('now', '-18 minutes'),
    (strftime('%s', datetime('now', '-18 minutes')) * 1000),
    '198.51.100.25', '64501', 'Example Cable Provider', 'US', 'visitor_demo_4',
    'GET', 'yourdomain.example', 'https', '/invoice', '',
    50211,
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    '', 'text/html', 'en-US,en;q=0.9', 'gzip',
    '', '', '',
    0, '', 38, 'suspicious', 'get_request, browser_ua_unsupported, sec_fetch_missing, no_referer',
    1, 0
),
(
    '/payroll',
    (SELECT id FROM links WHERE token = '/payroll'),
    datetime('now', '-45 minutes'),
    (strftime('%s', datetime('now', '-45 minutes')) * 1000),
    '198.51.100.77', '64510', 'Example Hosting Co', 'NL', 'visitor_demo_5',
    'GET', 'yourdomain.example', 'http', '/payroll', '',
    38871,
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)',
    '', '*/*', '', 'gzip',
    '', '', '',
    0, '', 28, 'suspicious', 'get_request, accept_wildcard, sec_fetch_missing, no_referer, hosting_provider',
    1, 0
),

-- ── Bot clicks ────────────────────────────────────────────────

(
    '/hello.world',
    (SELECT id FROM links WHERE token = '/hello.world'),
    datetime('now', '-22 minutes'),
    (strftime('%s', datetime('now', '-22 minutes')) * 1000),
    '192.0.2.50', '64502', 'Example Hosting Provider', 'CN', 'visitor_bot_1',
    'POST', 'yourdomain.example', 'http', '/hello.world', 'allow_url_include=1',
    60178,
    'python-requests/2.28.0',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua, exploit_like_query', 0, 'bot',
    'post_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, exploit_like_query, no_referer',
    1, 0
),
(
    '.env',
    NULL,
    datetime('now', '-27 minutes'),
    (strftime('%s', datetime('now', '-27 minutes')) * 1000),
    '203.0.113.99', '64503', 'Example Scanner Network', 'DE', 'visitor_bot_2',
    'GET', '203.0.113.99', 'http', '/.env', '',
    44321,
    'Go-http-client/1.1',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua, host_raw_ip', 0, 'bot',
    'get_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, host_raw_ip, no_referer',
    1, 0
),
(
    'wp-login.php',
    NULL,
    datetime('now', '-33 minutes'),
    (strftime('%s', datetime('now', '-33 minutes')) * 1000),
    '192.0.2.101', '64504', 'Example VPS Provider', 'RU', 'visitor_bot_3',
    'POST', 'yourdomain.example', 'http', '/wp-login.php', '',
    55210,
    'Mozilla/5.0 (compatible; SemrushBot/7)',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua', 0, 'bot',
    'post_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, no_referer, path:/wp-login.php',
    1, 0
),
(
    'phpmyadmin',
    NULL,
    datetime('now', '-41 minutes'),
    (strftime('%s', datetime('now', '-41 minutes')) * 1000),
    '192.0.2.150', '64505', 'Example Cloud Provider', 'CN', 'visitor_bot_4',
    'GET', 'yourdomain.example', 'http', '/phpmyadmin', '',
    62001,
    'curl/7.68.0',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua', 0, 'bot',
    'get_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, no_referer, path:phpmyadmin',
    1, 0
),
(
    '/payroll',
    (SELECT id FROM links WHERE token = '/payroll'),
    datetime('now', '-52 minutes'),
    (strftime('%s', datetime('now', '-52 minutes')) * 1000),
    '192.0.2.200', '64506', 'Example Datacenter', 'KP', 'visitor_bot_5',
    'GET', 'yourdomain.example', 'https', '/payroll', '',
    31190,
    'python-requests/2.31.0',
    '', '*/*', '', 'gzip',
    '', '', '',
    1, 'known_automation_ua', 0, 'bot',
    'get_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, no_referer, hosting_provider, country_penalty:KP',
    1, 0
),

-- ── Behavioral signal clicks (burst / rapid repeat) ──────────

(
    '/invoice',
    (SELECT id FROM links WHERE token = '/invoice'),
    datetime('now', '-3 minutes'),
    (strftime('%s', datetime('now', '-3 minutes')) * 1000),
    '192.0.2.75', '64507', 'Example Transit Network', 'BR', 'visitor_bot_6',
    'GET', 'yourdomain.example', 'http', '/invoice', '',
    41002,
    'zgrab/0.x',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua', 0, 'bot',
    'get_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, no_referer, rapid_repeat',
    0, 3
),
(
    '/benefits',
    (SELECT id FROM links WHERE token = '/benefits'),
    datetime('now', '-3 minutes'),
    (strftime('%s', datetime('now', '-3 minutes')) * 1000),
    '192.0.2.75', '64507', 'Example Transit Network', 'BR', 'visitor_bot_6',
    'GET', 'yourdomain.example', 'http', '/benefits', '',
    41003,
    'zgrab/0.x',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua', 0, 'bot',
    'get_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, no_referer, multi_token_scan',
    0, 4
),
(
    '/payroll',
    (SELECT id FROM links WHERE token = '/payroll'),
    datetime('now', '-3 minutes'),
    (strftime('%s', datetime('now', '-3 minutes')) * 1000),
    '192.0.2.75', '64507', 'Example Transit Network', 'BR', 'visitor_bot_6',
    'GET', 'yourdomain.example', 'http', '/payroll', '',
    41004,
    'zgrab/0.x',
    '', '*/*', '', '',
    '', '', '',
    1, 'known_automation_ua', 0, 'bot',
    'get_request, known_automation_ua, accept_wildcard, accept_language_missing, sec_fetch_missing, no_referer, multi_token_scan, burst_activity',
    0, 5
);

-- ============================================================
-- Sample ASN Rules
-- ============================================================
INSERT OR IGNORE INTO asn_rules (asn, label, penalty, active, exclude_from_feed, created_at) VALUES
    ('64502', 'Example Hosting Provider', 20, 1, 0, datetime('now')),
    ('64503', 'Example Scanner Network',  30, 1, 0, datetime('now'));

-- ============================================================
-- Sample IP Overrides
-- ============================================================
INSERT OR IGNORE INTO ip_overrides (ip, mode, notes, active, created_at) VALUES
    ('192.0.2.200', 'block', 'Confirmed malicious — persistent scanner', 1, datetime('now')),
    ('203.0.113.10', 'allow', 'Internal monitoring probe',               1, datetime('now'));

-- ============================================================
-- Sample Country Rules
-- ============================================================
INSERT OR IGNORE INTO country_rules (country_code, label, penalty, active, created_at) VALUES
    ('KP', 'No legitimate traffic expected', 25, 1, datetime('now')),
    ('RU', 'High-noise region',              15, 1, datetime('now'));
