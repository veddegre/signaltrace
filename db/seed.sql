-- SignalTrace Seed Data (Safe / Non-Real)
-- Uses documentation IP ranges (RFC 5737 / RFC 3849)

PRAGMA foreign_keys = ON;

--------------------------------------------------
-- Sample Tokens
--------------------------------------------------

INSERT INTO links (token, destination, description, active) VALUES
('/payroll', 'https://example.com/login', 'Payroll portal simulation', 1),
('/invoice', 'https://example.com/invoice', 'Invoice access link', 1),
('/benefits', 'https://example.com/benefits', 'Benefits portal', 1),
('/hello.world', 'https://example.com', 'Test token', 1);

--------------------------------------------------
-- Sample Clicks (Human + Suspicious + Bot)
--------------------------------------------------

INSERT INTO clicks (
    token,
    link_id,
    clicked_at,
    ip,
    ip_asn,
    ip_org,
    ip_country,
    visitor_hash,
    request_method,
    host,
    scheme,
    request_uri,
    query_string,
    remote_port,
    user_agent,
    referer,
    accept,
    accept_language,
    accept_encoding,
    is_bot,
    bot_reason,
    confidence_score,
    confidence_label,
    confidence_reason,
    first_for_token,
    prior_events_for_token
) VALUES

-- Human-like interaction
(
    '/payroll',
    1,
    datetime('now', '-5 minutes'),
    '203.0.113.10',
    '64500',
    'Example ISP',
    'US',
    'visitor_demo_1',
    'GET',
    'yourdomain.example',
    'https',
    '/payroll',
    '',
    52344,
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    '',
    'text/html',
    'en-US,en;q=0.9',
    'gzip',
    0,
    '',
    90,
    'human',
    'browser_headers, accept_html, sec_fetch_present',
    1,
    0
),

-- Suspicious interaction
(
    '/invoice',
    2,
    datetime('now', '-10 minutes'),
    '198.51.100.25',
    '64501',
    'Example Cable Provider',
    'US',
    'visitor_demo_2',
    'GET',
    'yourdomain.example',
    'https',
    '/invoice',
    '',
    50211,
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    '',
    'text/html',
    'en-US,en;q=0.9',
    'gzip',
    0,
    '',
    30,
    'suspicious',
    'accept_html, minimal_headers',
    1,
    0
),

-- Obvious bot / exploit attempt
(
    '/hello.world',
    4,
    datetime('now', '-15 minutes'),
    '192.0.2.50',
    '64502',
    'Example Hosting Provider',
    'FR',
    'visitor_bot_1',
    'POST',
    'yourdomain.example',
    'http',
    '/hello.world',
    'allow_url_include=1',
    60178,
    'libredtail-http',
    '',
    '*/*',
    '',
    '',
    1,
    'suspicious_query, non_browser_ua',
    0,
    'bot',
    'ua:libredtail, exploit_pattern',
    1,
    0
),

-- Scanner noise example
(
    '.env',
    NULL,
    datetime('now', '-20 minutes'),
    '203.0.113.99',
    '64503',
    'Example Scanner Network',
    'DE',
    'visitor_bot_2',
    'GET',
    'yourdomain.example',
    'http',
    '/.env',
    '',
    44321,
    '',
    '',
    '*/*',
    '',
    '',
    1,
    'scanner',
    0,
    'bot',
    'common_probe',
    1,
    0
);
