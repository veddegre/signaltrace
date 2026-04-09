-- SignalTrace Database Schema
-- Initializes all required tables, indexes, and default settings.
-- Run once on a fresh database:
--   sqlite3 /var/www/signaltrace/data/database.db < db/schema.sql

PRAGMA foreign_keys = ON;

-- ============================================================
-- Settings
-- ============================================================
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- ============================================================
-- Tokens (Links)
-- ============================================================
CREATE TABLE IF NOT EXISTS links (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    token            TEXT    NOT NULL UNIQUE,
    destination      TEXT    NOT NULL,
    description      TEXT,
    active           INTEGER NOT NULL DEFAULT 1,
    exclude_from_feed INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL
);

-- ============================================================
-- Click / Activity Logs
-- ============================================================
CREATE TABLE IF NOT EXISTS clicks (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id                 INTEGER,
    token                   TEXT    NOT NULL,
    event_type              TEXT    NOT NULL DEFAULT 'click',
    clicked_at              TEXT    NOT NULL,
    clicked_at_unix_ms      INTEGER,

    -- Identity
    ip                      TEXT,
    ip_asn                  TEXT,
    ip_org                  TEXT,
    ip_country              TEXT,
    visitor_hash            TEXT,
    x_forwarded_for         TEXT,

    -- Scoring
    confidence_score        INTEGER,
    confidence_label        TEXT,
    confidence_reason       TEXT,
    first_for_token         INTEGER DEFAULT 0,
    prior_events_for_token  INTEGER DEFAULT 0,

    -- Request
    request_method          TEXT,
    host                    TEXT,
    scheme                  TEXT,
    request_uri             TEXT,
    query_string            TEXT,
    remote_port             TEXT,

    -- Headers
    user_agent              TEXT,
    referer                 TEXT,
    accept                  TEXT,
    accept_language         TEXT,
    accept_encoding         TEXT,
    sec_fetch_site          TEXT,
    sec_fetch_mode          TEXT,
    sec_fetch_dest          TEXT,
    sec_ch_ua               TEXT,
    sec_ch_ua_platform      TEXT,

    -- Bot classification
    is_bot                  INTEGER NOT NULL DEFAULT 0,
    bot_reason              TEXT,

    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE SET NULL
);

-- ============================================================
-- Skip Patterns (Noise Filtering)
-- ============================================================
CREATE TABLE IF NOT EXISTS skip_patterns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,   -- exact | contains | prefix
    pattern    TEXT    NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL
);

-- ============================================================
-- ASN Rules
-- ============================================================
CREATE TABLE IF NOT EXISTS asn_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    asn              TEXT    NOT NULL UNIQUE,
    label            TEXT,
    penalty          INTEGER NOT NULL DEFAULT 10,
    active           INTEGER NOT NULL DEFAULT 1,
    exclude_from_feed INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL
);

-- ============================================================
-- Admin Login Rate Limiting
-- ============================================================
CREATE TABLE IF NOT EXISTS auth_failures (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT    NOT NULL,
    failed_at INTEGER NOT NULL
);

-- ============================================================
-- Indexes
-- ============================================================

-- clicks
CREATE INDEX IF NOT EXISTS idx_clicks_token            ON clicks(token);
CREATE INDEX IF NOT EXISTS idx_clicks_ip               ON clicks(ip);
CREATE INDEX IF NOT EXISTS idx_clicks_visitor_hash     ON clicks(visitor_hash);
CREATE INDEX IF NOT EXISTS idx_clicks_clicked_at       ON clicks(clicked_at);
CREATE INDEX IF NOT EXISTS idx_clicks_unix_ms          ON clicks(clicked_at_unix_ms);
CREATE INDEX IF NOT EXISTS idx_clicks_link_id          ON clicks(link_id);
CREATE INDEX IF NOT EXISTS idx_clicks_event_type       ON clicks(event_type);
CREATE INDEX IF NOT EXISTS idx_clicks_confidence_label ON clicks(confidence_label);
CREATE INDEX IF NOT EXISTS idx_clicks_is_bot           ON clicks(is_bot);

-- skip_patterns
CREATE INDEX IF NOT EXISTS idx_skip_patterns_type      ON skip_patterns(type);
CREATE INDEX IF NOT EXISTS idx_skip_patterns_active    ON skip_patterns(active);

-- asn_rules
CREATE INDEX IF NOT EXISTS idx_asn_rules_active        ON asn_rules(active);

-- auth_failures
CREATE INDEX IF NOT EXISTS idx_auth_failures_ip        ON auth_failures(ip);
CREATE INDEX IF NOT EXISTS idx_auth_failures_at        ON auth_failures(failed_at);

-- links
CREATE INDEX IF NOT EXISTS idx_links_token             ON links(token);

-- ============================================================
-- Default Settings
-- ============================================================
INSERT OR IGNORE INTO settings (key, value) VALUES
    ('app_name',                 'SignalTrace - Tracking & Analysis'),
    ('base_url',                 ''),
    ('default_redirect_url',     'https://example.com/'),
    ('unknown_path_behavior',    'redirect'),
    ('pixel_enabled',            '1'),
    ('noise_filter_enabled',     '1'),
    ('threat_feed_enabled',      '1'),
    ('threat_feed_window_hours', '168'),
    ('threat_feed_min_confidence','suspicious'),
    ('data_retention_days',      '0'),
    ('display_min_score',        '20'),
    ('page_size',                '50'),
    ('webhook_url',              ''),
    ('auto_refresh_secs',        '0'),
    ('export_min_confidence',    'suspicious'),
    ('export_window_hours',      '168'),
    ('export_min_score',         '0');

-- ============================================================
-- Default Skip Patterns
-- ============================================================
INSERT OR IGNORE INTO skip_patterns (type, pattern, active, created_at) VALUES
    ('exact',    'favicon.ico',                      1, datetime('now')),
    ('exact',    'robots.txt',                       1, datetime('now')),
    ('exact',    'apple-touch-icon.png',             1, datetime('now')),
    ('exact',    'apple-touch-icon-precomposed.png', 1, datetime('now')),
    ('exact',    'ads.txt',                          1, datetime('now')),
    ('exact',    'sitemap.xml',                      1, datetime('now')),
    ('contains', '.env',                             1, datetime('now')),
    ('contains', '.git',                             1, datetime('now')),
    ('prefix',   'wp-',                              1, datetime('now')),
    ('contains', 'phpinfo',                          1, datetime('now')),
    ('contains', 'admin',                            0, datetime('now'));
