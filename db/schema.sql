-- SignalTrace Database Schema
-- Initializes all required tables

PRAGMA foreign_keys = ON;

--------------------------------------------------
-- Settings
--------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

--------------------------------------------------
-- Tokens (Links)
--------------------------------------------------
CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    destination TEXT NOT NULL,
    description TEXT,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

--------------------------------------------------
-- Click / Activity Logs
--------------------------------------------------
CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT,
    link_id INTEGER,
    clicked_at TEXT DEFAULT CURRENT_TIMESTAMP,

    -- Identity
    ip TEXT,
    ip_asn TEXT,
    ip_org TEXT,
    ip_country TEXT,
    visitor_hash TEXT,
    x_forwarded_for TEXT,

    -- Request
    request_method TEXT,
    host TEXT,
    scheme TEXT,
    request_uri TEXT,
    query_string TEXT,
    remote_port INTEGER,

    -- Headers
    user_agent TEXT,
    referer TEXT,
    accept TEXT,
    accept_language TEXT,
    accept_encoding TEXT,
    sec_fetch_site TEXT,
    sec_fetch_mode TEXT,
    sec_fetch_dest TEXT,
    sec_ch_ua TEXT,
    sec_ch_ua_platform TEXT,

    -- Classification
    is_bot INTEGER DEFAULT 0,
    bot_reason TEXT,
    confidence_score INTEGER,
    confidence_label TEXT,
    confidence_reason TEXT,

    -- Context
    event_type TEXT DEFAULT 'click',
    first_for_token INTEGER DEFAULT 0,
    prior_events_for_token INTEGER DEFAULT 0,

    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE SET NULL
);

--------------------------------------------------
-- Skip Patterns (Noise Filtering)
--------------------------------------------------
CREATE TABLE IF NOT EXISTS skip_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,          -- exact, contains, prefix
    pattern TEXT NOT NULL,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

--------------------------------------------------
-- Indexes (Performance)
--------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_clicks_token ON clicks(token);
CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(ip);
CREATE INDEX IF NOT EXISTS idx_clicks_visitor ON clicks(visitor_hash);
CREATE INDEX IF NOT EXISTS idx_clicks_time ON clicks(clicked_at);
CREATE INDEX IF NOT EXISTS idx_links_token ON links(token);

--------------------------------------------------
-- Default Settings (Safe Defaults)
--------------------------------------------------

INSERT OR IGNORE INTO settings (key, value) VALUES
('app_name', 'SignalTrace'),
('base_url', ''),
('default_redirect_url', 'https://example.com'),
('unknown_path_behavior', 'redirect'),
('pixel_enabled', '1'),
('noise_filter_enabled', '1');

--------------------------------------------------
-- Example Skip Patterns (Optional but helpful)
--------------------------------------------------

INSERT OR IGNORE INTO skip_patterns (type, pattern, active) VALUES
('contains', '.env', 1),
('contains', '.git', 1),
('prefix', 'wp-', 1),
('contains', 'phpinfo', 1),
('contains', 'admin', 0);

--------------------------------------------------
-- Threat feed defaults
--------------------------------------------------
INSERT OR IGNORE INTO settings (key, value) VALUES
('threat_feed_enabled', '1'),
('threat_feed_window_hours', '168'),
('threat_feed_min_confidence', 'suspicious');
