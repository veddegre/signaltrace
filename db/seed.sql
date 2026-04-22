-- SignalTrace Seed Data (Safe / Non-Real)
-- Uses documentation IP ranges (RFC 5737 / RFC 3849)
-- All IPs, ASNs, orgs, recipients, and document names are fictitious.

PRAGMA foreign_keys = ON;

-- ============================================================
-- Sample Campaigns
-- ============================================================
INSERT OR IGNORE INTO campaigns (name, description, active, webhook_enabled, created_at) VALUES
    ('Q2 Payroll Simulation', 'Payroll-themed campaign with mixed token types', 1, 1, datetime('now')),
    ('Vendor Invoice Review', 'Invoice and procurement review workflow', 1, 0, datetime('now')),
    ('HR Document Tracking', 'Document-oriented tracking examples', 1, 1, datetime('now'));

-- ============================================================
-- Sample Tokens
-- ============================================================
INSERT OR IGNORE INTO links (
    token, destination, description, type,
    recipient_name, recipient_email, notes,
    burn_after_first_hit, expires_at,
    document_kind, document_label,
    active, exclude_from_feed, force_include_in_feed,
    include_in_token_webhook, include_in_email,
    campaign_id, created_at
) VALUES
    (
        '/payroll',
        'https://example.com/login',
        'Payroll portal simulation',
        'link',
        'Alex Morgan',
        'alex.morgan@example.edu',
        'Standard phishing-style URL token',
        0,
        datetime('now', '+30 days'),
        NULL,
        NULL,
        1, 0, 1, 1, 1,
        (SELECT id FROM campaigns WHERE name = 'Q2 Payroll Simulation'),
        datetime('now')
    ),
    (
        '/invoice',
        'https://example.com/invoice',
        'Invoice access link',
        'link',
        'Jordan Lee',
        'jordan.lee@example.edu',
        'Invoice review link token',
        0,
        datetime('now', '+30 days'),
        NULL,
        NULL,
        1, 0, 1, 1, 0,
        (SELECT id FROM campaigns WHERE name = 'Vendor Invoice Review'),
        datetime('now')
    ),
    (
        '/benefits',
        'https://example.com/benefits',
        'Benefits portal',
        'link',
        'Casey Wright',
        'casey.wright@example.edu',
        'General portal token',
        0,
        datetime('now', '+14 days'),
        NULL,
        NULL,
        1, 0, 0, 0, 0,
        NULL,
        datetime('now')
    ),
    (
        '/payroll-pixel',
        'https://example.com/login',
        'Embedded payroll image beacon',
        'pixel',
        'Alex Morgan',
        'alex.morgan@example.edu',
        'Use the pixel URL in an email or HTML snippet',
        0,
        datetime('now', '+30 days'),
        NULL,
        NULL,
        1, 0, 1, 1, 0,
        (SELECT id FROM campaigns WHERE name = 'Q2 Payroll Simulation'),
        datetime('now')
    ),
    (
        '/hr-policy-doc',
        'https://example.com/policy',
        'HR policy document beacon',
        'document',
        'Taylor Brooks',
        'taylor.brooks@example.edu',
        'Document token example with first-hit burn',
        1,
        datetime('now', '+21 days'),
        'docx',
        'HR Policy Review',
        1, 0, 1, 1, 1,
        (SELECT id FROM campaigns WHERE name = 'HR Document Tracking'),
        datetime('now')
    ),
    (
        '/procurement-sheet',
        'https://example.com/procurement',
        'Procurement spreadsheet beacon',
        'document',
        'Morgan Patel',
        'morgan.patel@example.edu',
        'Spreadsheet-style document token example',
        0,
        datetime('now', '+21 days'),
        'xlsx',
        'Procurement Vendor Comparison',
        1, 0, 1, 0, 0,
        (SELECT id FROM campaigns WHERE name = 'Vendor Invoice Review'),
        datetime('now')
    ),
    (
        '/hello.world',
        'https://example.com',
        'Test token',
        'link',
        NULL,
        NULL,
        'General testing token',
        0,
        NULL,
        NULL,
        NULL,
        1, 0, 0, 0, 0,
        NULL,
        datetime('now')
    );

-- ============================================================
-- Sample Clicks
-- clicked_at_unix_ms = strftime('%s', clicked_at) * 1000
-- All within the last 48 hours so they appear in the threat feed
-- ============================================================
INSERT INTO clicks (
    token, link_id, event_type, clicked_at, clicked_at_unix_ms,
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
    'click',
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
    'click',
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
    'pixel:/payroll-pixel',
    (SELECT id FROM links WHERE token = '/payroll-pixel'),
    'pixel_load',
    datetime('now', '-16 minutes'),
    (strftime('%s', datetime('now', '-16 minutes')) * 1000),
    '203.0.113.25', '64500', 'Example ISP', 'US', 'visitor_demo_px_1',
    'GET', 'yourdomain.example', 'https', '/pixel/payroll-pixel.gif', '',
    54400,
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'https://mail.example.com/', 'image/avif,image/webp,image/apng,*/*', 'en-US,en;q=0.9', 'gzip, deflate, br',
    'cross-site', 'no-cors', 'image',
    0, '', 84, 'human', 'pixel_load, embedded_image_request',
    1, 0
),
(
    '/hr-policy-doc',
    (SELECT id FROM links WHERE token = '/hr-policy-doc'),
    'document_open',
    datetime('now', '-31 minutes'),
    (strftime('%s', datetime('now', '-31 minutes')) * 1000),
    '203.0.113.78', '64500', 'Example ISP', 'GB', 'visitor_demo_doc_1',
    'GET', 'yourdomain.example', 'https', '/hr-policy-doc', '',
    61022,
    'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word)',
    '', '*/*', 'en-GB,en;q=0.9', 'gzip, deflate, br',
    'none', 'navigate', 'document',
    0, '', 80, 'human', 'document_open, office_user_agent',
    1, 0
),
(
    '/procurement-sheet',
    (SELECT id FROM links WHERE token = '/procurement-sheet'),
    'document_preview',
    datetime('now', '-37 minutes'),
    (strftime('%s', datetime('now', '-37 minutes')) * 1000),
    '203.0.113.91', '64500', 'Example ISP', 'US', 'visitor_demo_doc_2',
    'GET', 'yourdomain.example', 'https', '/procurement-sheet', '',
    61111,
    'Microsoft Office Excel/16.0',
    '', '*/*', 'en-US,en;q=0.9', 'gzip, deflate, br',
    'none', 'navigate', 'empty',
    0, '', 74, 'human', 'document_preview, office_user_agent',
    1, 0
),

-- ── Suspicious clicks ─────────────────────────────────────────

(
    '/invoice',
    (SELECT id FROM links WHERE token = '/invoice'),
    'click',
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
    'click',
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

-- ── Bot clicks (IPv4) ─────────────────────────────────────────

(
    '/hello.world',
    (SELECT id FROM links WHERE token = '/hello.world'),
    'click',
    datetime('now', '-22 minutes'),
    (strftime('%s', datetime('now', '-22 minutes')) * 1000),
    '192.0.2.50', '64502', 'Example Hosting Botnet', 'DE', 'visitor_bot_1',
    'GET', 'scanner.example', 'http', '/hello.world', '',
    45501,
    'curl/8.4.0',
    '', '*/*', '', 'gzip',
    '', '', '',
    1, 'cli_user_agent', 6, 'bot', 'cli_user_agent, no_accept_language, no_sec_fetch',
    1, 0
),
(
    '/payroll',
    (SELECT id FROM links WHERE token = '/payroll'),
    'click',
    datetime('now', '-58 minutes'),
    (strftime('%s', datetime('now', '-58 minutes')) * 1000),
    '192.0.2.99', '64503', 'Example Cloud Scanner', 'US', 'visitor_bot_2',
    'HEAD', 'yourdomain.example', 'https', '/payroll', '',
    39812,
    'Wget/1.21.4',
    '', '*/*', '', 'gzip',
    '', '', '',
    1, 'head_request', 4, 'bot', 'head_request, cli_user_agent, no_sec_fetch',
    1, 0
);
