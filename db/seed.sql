-- SignalTrace Seed Data (Safe / Non-Real)
-- Uses documentation IP ranges (RFC 5737 / RFC 3849).
-- Load after schema.sql on a fresh database:
--   sqlite3 /var/www/signaltrace/data/database.db < db/seed.sql

PRAGMA foreign_keys = ON;

-- ============================================================
-- Sample Tokens
-- ============================================================
INSERT INTO links (token, destination, description, active, exclude_from_feed, created_at) VALUES
    ('/payroll',     'https://example.com/login',    'Payroll portal simulation', 1, 0, datetime('now')),
    ('/invoice',     'https://example.com/invoice',  'Invoice access link',       1, 0, datetime('now')),
    ('/benefits',    'https://example.com/benefits', 'Benefits portal',           1, 0, datetime('now')),
    ('/hello.world', 'https://example.com',          'Test token',                1, 0, datetime('now'));

-- ============================================================
-- Sample Clicks (Human / Suspicious / Bot / Scanner)
-- ============================================================
INSERT INTO clicks (
    token, link_id,
    event_type, clicked_at, clicked_at_unix_ms,
    ip, ip_asn, ip_org, ip_country,
    visitor_hash,
    request_method, host, scheme, request_uri, query_string, remote_port,
    user_agent, referer, accept, accept_language, accept_encoding,
    is_bot, bot_reason,
    confidence_score, confidence_label, confidence_reason,
    first_for_token, prior_events_for_token
) VALUES

-- Human-like interaction
(
    '/payroll', 1,
    'click', datetime('now', '-5 minutes'), strftime('%s', 'now', '-5 minutes') * 1000,
    '203.0.113.10', '64500', 'Example ISP', 'US',
    'visitor_demo_1',
    'GET', 'yourdomain.example', 'https', '/payroll', '', 52344,
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    '', 'text/html', 'en-US,en;q=0.9', 'gzip',
    0, NULL,
    90, 'human', 'get_request, browser_ua, accept_html',
    1, 0
),

-- Suspicious interaction
(
    '/invoice', 2,
    'click', datetime('now', '-10 minutes'), strftime('%s', 'now', '-10 minutes') * 1000,
    '198.51.100.25', '64501', 'Example Cable Provider', 'US',
    'visitor_demo_2',
    'GET', 'yourdomain.example', 'https', '/invoice', '', 50211,
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    '', 'text/html', 'en-US,en;q=0.9', 'gzip',
    0, NULL,
    30, 'suspicious', 'sec_fetch_missing, sec_ch_ua_missing, no_referer',
    1, 0
),

-- Bot / exploit attempt
(
    '/hello.world', 4,
    'click', datetime('now', '-15 minutes'), strftime('%s', 'now', '-15 minutes') * 1000,
    '192.0.2.50', '64502', 'Example Hosting Provider', 'FR',
    'visitor_bot_1',
    'POST', 'yourdomain.example', 'http', '/hello.world', 'allow_url_include=1', 60178,
    'libredtail-http',
    '', '*/*', '', '',
    1, 'ua:automation, method:POST_exploit_query, query:exploit_like',
    0, 'bot', 'post_request, known_automation_ua, exploit_like_query, bot_signal',
    1, 0
),

-- Scanner noise — unknown token
(
    '.env', NULL,
    'click', datetime('now', '-20 minutes'), strftime('%s', 'now', '-20 minutes') * 1000,
    '203.0.113.99', '64503', 'Example Scanner Network', 'DE',
    'visitor_bot_2',
    'GET', 'yourdomain.example', 'http', '/.env', '', 44321,
    '',
    '', '*/*', '', '',
    1, 'host:raw_ip',
    0, 'bot', 'accept_missing, accept_language_missing, sec_fetch_missing, bot_signal, path:.env',
    1, 0
);
