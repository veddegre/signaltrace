<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/../vendor/autoload.php';

function db(): PDO
{
    static $pdo = null;

    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . DB_PATH);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $pdo->exec('PRAGMA journal_mode = WAL;');
        $pdo->exec('PRAGMA foreign_keys = ON;');
        $pdo->exec('PRAGMA synchronous = NORMAL;');
        $pdo->exec('PRAGMA temp_store = MEMORY;');

        initializeDatabase($pdo);
    }

    return $pdo;
}

function initializeDatabase(PDO $pdo): void
{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            destination TEXT NOT NULL,
            description TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            exclude_from_feed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id INTEGER,
            token TEXT NOT NULL,
            event_type TEXT NOT NULL DEFAULT 'click',
            clicked_at TEXT NOT NULL,
            clicked_at_unix_ms INTEGER,
            ip TEXT,
            ip_asn TEXT,
            ip_org TEXT,
            ip_country TEXT,
            visitor_hash TEXT,
            confidence_score INTEGER,
            confidence_label TEXT,
            confidence_reason TEXT,
            first_for_token INTEGER DEFAULT 0,
            prior_events_for_token INTEGER DEFAULT 0,
            x_forwarded_for TEXT,
            user_agent TEXT,
            referer TEXT,
            accept_language TEXT,
            accept TEXT,
            accept_encoding TEXT,
            request_method TEXT,
            host TEXT,
            scheme TEXT,
            request_uri TEXT,
            query_string TEXT,
            remote_port TEXT,
            sec_fetch_site TEXT,
            sec_fetch_mode TEXT,
            sec_fetch_dest TEXT,
            sec_ch_ua TEXT,
            sec_ch_ua_platform TEXT,
            is_bot INTEGER NOT NULL DEFAULT 0,
            bot_reason TEXT,
            FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE SET NULL
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS skip_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS asn_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn TEXT NOT NULL UNIQUE,
            label TEXT,
            penalty INTEGER NOT NULL DEFAULT 10,
            active INTEGER NOT NULL DEFAULT 1,
            exclude_from_feed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS ip_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            mode TEXT NOT NULL DEFAULT 'block',
            notes TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS country_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            country_code TEXT NOT NULL UNIQUE,
            label TEXT,
            penalty INTEGER NOT NULL DEFAULT 10,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    ");

    // SECURITY: ensureColumn now validates table and column names against a strict
    // whitelist before interpolating them into SQL. The $definition argument uses
    // a predefined map instead of being passed as a free string.
    $asnColumnDefinitions = [
        'exclude_from_feed' => 'INTEGER NOT NULL DEFAULT 0',
    ];

    foreach ($asnColumnDefinitions as $column => $definition) {
        ensureColumn($pdo, 'asn_rules', $column, $definition);
    }

    $linksColumnDefinitions = [
        'exclude_from_feed'       => 'INTEGER NOT NULL DEFAULT 0',
        'include_in_token_webhook' => 'INTEGER NOT NULL DEFAULT 0',
    ];

    foreach ($linksColumnDefinitions as $column => $definition) {
        ensureColumn($pdo, 'links', $column, $definition);
    }

    $clickColumnDefinitions = [
        'event_type'             => "TEXT NOT NULL DEFAULT 'click'",
        'clicked_at_unix_ms'     => 'INTEGER',
        'ip_asn'                 => 'TEXT',
        'ip_org'                 => 'TEXT',
        'ip_country'             => 'TEXT',
        'visitor_hash'           => 'TEXT',
        'confidence_score'       => 'INTEGER',
        'confidence_label'       => 'TEXT',
        'confidence_reason'      => 'TEXT',
        'first_for_token'        => 'INTEGER DEFAULT 0',
        'prior_events_for_token' => 'INTEGER DEFAULT 0',
        'x_forwarded_for'        => 'TEXT',
        'accept'                 => 'TEXT',
        'accept_encoding'        => 'TEXT',
        'scheme'                 => 'TEXT',
        'remote_port'            => 'TEXT',
        'sec_fetch_site'         => 'TEXT',
        'sec_fetch_mode'         => 'TEXT',
        'sec_fetch_dest'         => 'TEXT',
        'sec_ch_ua'              => 'TEXT',
        'sec_ch_ua_platform'     => 'TEXT',
    ];

    foreach ($clickColumnDefinitions as $column => $definition) {
        ensureColumn($pdo, 'clicks', $column, $definition);
    }

    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_token ON clicks(token)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_clicked_at ON clicks(clicked_at)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_unix_ms ON clicks(clicked_at_unix_ms)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_event_type ON clicks(event_type)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_visitor_hash ON clicks(visitor_hash)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(ip)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_confidence_label ON clicks(confidence_label)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_clicks_is_bot ON clicks(is_bot)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_skip_patterns_type ON skip_patterns(type)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_skip_patterns_active ON skip_patterns(active)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_asn_rules_active ON asn_rules(active)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_ip_overrides_ip ON ip_overrides(ip)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_ip_overrides_active ON ip_overrides(active)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_country_rules_code ON country_rules(country_code)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_country_rules_active ON country_rules(active)");

    seedDefaultSettings($pdo);
    seedDefaultSkipPatterns($pdo);
}

/**
 * SECURITY: Table names and column names are validated against hardcoded
 * whitelists before being interpolated into SQL. The column definition is
 * sourced from an internal map — it is never derived from user input.
 */
function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void
{
    // Whitelist of tables this function is permitted to alter.
    $allowedTables = ['clicks', 'links', 'settings', 'skip_patterns', 'asn_rules', 'ip_overrides', 'country_rules'];

    // Whitelist of column name characters: alphanumeric and underscore only.
    if (!in_array($table, $allowedTables, true)) {
        throw new \InvalidArgumentException("ensureColumn: disallowed table '$table'");
    }

    if (!preg_match('/^[a-z_][a-z0-9_]*$/i', $column)) {
        throw new \InvalidArgumentException("ensureColumn: disallowed column name '$column'");
    }

    $stmt = $pdo->query("PRAGMA table_info($table)");
    $cols = $stmt->fetchAll();

    foreach ($cols as $col) {
        if (($col['name'] ?? '') === $column) {
            return;
        }
    }

    // Table and column have been validated against whitelists above.
    // $definition comes from the hardcoded $clickColumnDefinitions map, never from user input.
    $pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
}

function seedDefaultSettings(PDO $pdo): void
{
    $defaults = [
        'app_name'                   => 'SignalTrace',
        'base_url'                   => '',
        'default_redirect_url'       => 'https://example.com/',
        'unknown_path_behavior'      => 'redirect',
        'pixel_enabled'              => '1',
        'noise_filter_enabled'       => '1',
        'threat_feed_enabled'        => '1',
        'threat_feed_window_hours'   => '168',
        'threat_feed_min_confidence' => 'suspicious',
        'threat_feed_min_hits'       => '1',
        'data_retention_days'        => '0',
        'display_min_score'          => '20',
        'page_size'                  => '50',
        'webhook_url'                => '',
        'webhook_template'           => '',
        'webhook_threshold'          => 'bot',
        'token_webhook_url'          => '',
        'token_webhook_template'     => '',
        'auto_refresh_secs'          => '0',
        'export_min_confidence'      => 'suspicious',
        'export_window_hours'        => '168',
        'export_min_score'           => '0',
    ];

    $stmt = $pdo->prepare("
        INSERT OR IGNORE INTO settings (key, value)
        VALUES (:key, :value)
    ");

    foreach ($defaults as $key => $value) {
        $stmt->execute([
            ':key' => $key,
            ':value' => $value,
        ]);
    }
}

function seedDefaultSkipPatterns(PDO $pdo): void
{
    $count = (int) $pdo->query("SELECT COUNT(*) FROM skip_patterns")->fetchColumn();
    if ($count > 0) {
        return;
    }

    $defaults = [
        ['type' => 'exact', 'pattern' => 'favicon.ico'],
        ['type' => 'exact', 'pattern' => 'robots.txt'],
        ['type' => 'exact', 'pattern' => 'apple-touch-icon.png'],
        ['type' => 'exact', 'pattern' => 'apple-touch-icon-precomposed.png'],
        ['type' => 'exact', 'pattern' => 'ads.txt'],
        ['type' => 'exact', 'pattern' => 'sitemap.xml'],
    ];

    $stmt = $pdo->prepare("
        INSERT INTO skip_patterns (type, pattern, active, created_at)
        VALUES (:type, :pattern, 1, :created_at)
    ");

    foreach ($defaults as $row) {
        $stmt->execute([
            ':type' => $row['type'],
            ':pattern' => $row['pattern'],
            ':created_at' => date('c'),
        ]);
    }
}

function getAllSettings(PDO $pdo): array
{
    $rows = $pdo->query("SELECT key, value FROM settings ORDER BY key ASC")->fetchAll();
    $settings = [];

    foreach ($rows as $row) {
        $settings[$row['key']] = $row['value'];
    }

    return $settings;
}

function getSetting(PDO $pdo, string $key, ?string $default = null): ?string
{
    $stmt = $pdo->prepare("SELECT value FROM settings WHERE key = :key LIMIT 1");
    $stmt->execute([':key' => $key]);
    $value = $stmt->fetchColumn();

    return $value === false ? $default : (string) $value;
}

function setSetting(PDO $pdo, string $key, string $value): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO settings (key, value)
        VALUES (:key, :value)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    ");

    return $stmt->execute([
        ':key' => $key,
        ':value' => $value,
    ]);
}

function getSkipPatterns(PDO $pdo): array
{
    return $pdo->query("
        SELECT id, type, pattern, active, created_at
        FROM skip_patterns
        ORDER BY type ASC, pattern ASC
    ")->fetchAll();
}

function getActiveSkipPatternMap(PDO $pdo): array
{
    $rows = $pdo->query("
        SELECT type, pattern
        FROM skip_patterns
        WHERE active = 1
        ORDER BY id ASC
    ")->fetchAll();

    $map = [
        'exact' => [],
        'contains' => [],
        'prefix' => [],
    ];

    foreach ($rows as $row) {
        $type = strtolower((string) $row['type']);
        if (isset($map[$type])) {
            $map[$type][] = strtolower((string) $row['pattern']);
        }
    }

    return $map;
}

function createSkipPattern(PDO $pdo, string $type, string $pattern): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO skip_patterns (type, pattern, active, created_at)
        VALUES (:type, :pattern, 1, :created_at)
    ");

    return $stmt->execute([
        ':type' => $type,
        ':pattern' => $pattern,
        ':created_at' => date('c'),
    ]);
}

function setSkipPatternActive(PDO $pdo, int $id, bool $active): bool
{
    $stmt = $pdo->prepare("
        UPDATE skip_patterns
        SET active = :active
        WHERE id = :id
    ");

    return $stmt->execute([
        ':active' => $active ? 1 : 0,
        ':id' => $id,
    ]);
}

function deleteSkipPattern(PDO $pdo, int $id): bool
{
    $stmt = $pdo->prepare("DELETE FROM skip_patterns WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

function currentUnixMs(): int
{
    return (int) round(microtime(true) * 1000);
}

/* =========================
   Phase 2 helpers
   ========================= */

function getLastSeenForIp(PDO $pdo, string $ip): ?int
{
    if ($ip === '') {
        return null;
    }

    $stmt = $pdo->prepare("
        SELECT clicked_at_unix_ms
        FROM clicks
        WHERE ip = :ip
        ORDER BY id DESC
        LIMIT 1
    ");
    $stmt->execute([':ip' => $ip]);

    $value = $stmt->fetchColumn();
    if ($value === false || $value === null || $value === '') {
        return null;
    }

    return (int) $value;
}

function getRecentEventCountForIp(PDO $pdo, string $ip, int $windowSeconds = 10): int
{
    if ($ip === '') {
        return 0;
    }

    $cutoffMs = currentUnixMs() - ($windowSeconds * 1000);

    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM clicks
        WHERE ip = :ip
          AND clicked_at_unix_ms >= :cutoff_ms
    ");
    $stmt->execute([
        ':ip' => $ip,
        ':cutoff_ms' => $cutoffMs,
    ]);

    return (int) $stmt->fetchColumn();
}

function getDistinctTokenCountForIp(PDO $pdo, string $ip, int $windowSeconds = 30): int
{
    if ($ip === '') {
        return 0;
    }

    $cutoffMs = currentUnixMs() - ($windowSeconds * 1000);

    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT token)
        FROM clicks
        WHERE ip = :ip
          AND clicked_at_unix_ms >= :cutoff_ms
    ");
    $stmt->execute([
        ':ip' => $ip,
        ':cutoff_ms' => $cutoffMs,
    ]);

    return (int) $stmt->fetchColumn();
}

function getLinkByToken(PDO $pdo, string $token): ?array
{
    $stmt = $pdo->prepare("
        SELECT *
        FROM links
        WHERE token = :token
          AND active = 1
        LIMIT 1
    ");
    $stmt->execute([':token' => $token]);

    $row = $stmt->fetch();
    return $row ?: null;
}

function createLink(PDO $pdo, string $token, string $destination, string $description = '', bool $excludeFromFeed = false, bool $includeInTokenWebhook = false): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO links (token, destination, description, active, exclude_from_feed, include_in_token_webhook, created_at)
        VALUES (:token, :destination, :description, 1, :exclude_from_feed, :include_in_token_webhook, :created_at)
    ");

    return $stmt->execute([
        ':token'                   => $token,
        ':destination'             => $destination,
        ':description'             => $description,
        ':exclude_from_feed'       => $excludeFromFeed ? 1 : 0,
        ':include_in_token_webhook' => $includeInTokenWebhook ? 1 : 0,
        ':created_at'              => date('c'),
    ]);
}

function updateLink(PDO $pdo, int $id, string $token, string $destination, string $description = '', bool $excludeFromFeed = false, bool $includeInTokenWebhook = false): bool
{
    $stmt = $pdo->prepare("
        UPDATE links
        SET token                    = :token,
            destination              = :destination,
            description              = :description,
            exclude_from_feed        = :exclude_from_feed,
            include_in_token_webhook = :include_in_token_webhook
        WHERE id = :id
    ");

    return $stmt->execute([
        ':id'                      => $id,
        ':token'                   => $token,
        ':destination'             => $destination,
        ':description'             => $description,
        ':exclude_from_feed'       => $excludeFromFeed ? 1 : 0,
        ':include_in_token_webhook' => $includeInTokenWebhook ? 1 : 0,
    ]);
}

function deactivateLink(PDO $pdo, int $id): bool
{
    $stmt = $pdo->prepare("UPDATE links SET active = 0 WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

function activateLink(PDO $pdo, int $id): bool
{
    $stmt = $pdo->prepare("UPDATE links SET active = 1 WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

function deleteLink(PDO $pdo, int $id, bool $deleteClicks = false): bool
{
    if ($deleteClicks) {
        $stmt = $pdo->prepare("DELETE FROM clicks WHERE link_id = :id");
        $stmt->execute([':id' => $id]);
    }

    $stmt = $pdo->prepare("DELETE FROM links WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

function getPriorEventsForToken(PDO $pdo, string $token, ?string $visitorHash): int
{
    if ($visitorHash === null || $visitorHash === '') {
        return 0;
    }

    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM clicks
        WHERE token = :token
          AND visitor_hash = :visitor_hash
    ");
    $stmt->execute([
        ':token' => $token,
        ':visitor_hash' => $visitorHash,
    ]);

    return (int) $stmt->fetchColumn();
}

function logClick(PDO $pdo, array $link, array $requestData): void
{
    $ip = (string) ($requestData['ip'] ?? '');
    $token = (string) ($link['token'] ?? '');
    $visitorHash = $requestData['visitor_hash'] ?? null;
    $priorEventsForToken = getPriorEventsForToken($pdo, $token, is_string($visitorHash) ? $visitorHash : null);
    $firstForToken = $priorEventsForToken === 0 ? 1 : 0;

    $enrichment = $ip !== '' ? lookupGeoIp($ip) : [
        'ip_asn' => null,
        'ip_org' => null,
        'ip_country' => null,
    ];

    $stmt = $pdo->prepare("
        INSERT INTO clicks (
            link_id, token, event_type, clicked_at, clicked_at_unix_ms,
            ip, ip_asn, ip_org, ip_country, visitor_hash,
            confidence_score, confidence_label, confidence_reason,
            first_for_token, prior_events_for_token,
            x_forwarded_for, user_agent, referer,
            accept_language, accept, accept_encoding, request_method,
            host, scheme, request_uri, query_string, remote_port,
            sec_fetch_site, sec_fetch_mode, sec_fetch_dest,
            sec_ch_ua, sec_ch_ua_platform, is_bot, bot_reason
        ) VALUES (
            :link_id, :token, :event_type, :clicked_at, :clicked_at_unix_ms,
            :ip, :ip_asn, :ip_org, :ip_country, :visitor_hash,
            :confidence_score, :confidence_label, :confidence_reason,
            :first_for_token, :prior_events_for_token,
            :x_forwarded_for, :user_agent, :referer,
            :accept_language, :accept, :accept_encoding, :request_method,
            :host, :scheme, :request_uri, :query_string, :remote_port,
            :sec_fetch_site, :sec_fetch_mode, :sec_fetch_dest,
            :sec_ch_ua, :sec_ch_ua_platform, :is_bot, :bot_reason
        )
    ");

    $stmt->execute([
        ':link_id' => $link['id'] ?? null,
        ':token' => $token,
        ':event_type' => $requestData['event_type'] ?? 'click',
        ':clicked_at' => date('c'),
        ':clicked_at_unix_ms' => currentUnixMs(),
        ':ip' => $requestData['ip'] ?? null,
        ':ip_asn' => $requestData['ip_asn'] ?? $enrichment['ip_asn'],
        ':ip_org' => $requestData['ip_org'] ?? $enrichment['ip_org'],
        ':ip_country' => $requestData['ip_country'] ?? $enrichment['ip_country'],
        ':visitor_hash' => $requestData['visitor_hash'] ?? null,
        ':confidence_score' => $requestData['confidence_score'] ?? null,
        ':confidence_label' => $requestData['confidence_label'] ?? null,
        ':confidence_reason' => $requestData['confidence_reason'] ?? null,
        ':first_for_token' => $firstForToken,
        ':prior_events_for_token' => $priorEventsForToken,
        ':x_forwarded_for' => $requestData['x_forwarded_for'] ?? null,
        ':user_agent' => $requestData['user_agent'] ?? null,
        ':referer' => $requestData['referer'] ?? null,
        ':accept_language' => $requestData['accept_language'] ?? null,
        ':accept' => $requestData['accept'] ?? null,
        ':accept_encoding' => $requestData['accept_encoding'] ?? null,
        ':request_method' => $requestData['request_method'] ?? null,
        ':host' => $requestData['host'] ?? null,
        ':scheme' => $requestData['scheme'] ?? null,
        ':request_uri' => $requestData['request_uri'] ?? null,
        ':query_string' => $requestData['query_string'] ?? null,
        ':remote_port' => $requestData['remote_port'] ?? null,
        ':sec_fetch_site' => $requestData['sec_fetch_site'] ?? null,
        ':sec_fetch_mode' => $requestData['sec_fetch_mode'] ?? null,
        ':sec_fetch_dest' => $requestData['sec_fetch_dest'] ?? null,
        ':sec_ch_ua' => $requestData['sec_ch_ua'] ?? null,
        ':sec_ch_ua_platform' => $requestData['sec_ch_ua_platform'] ?? null,
        ':is_bot' => !empty($requestData['is_bot']) ? 1 : 0,
        ':bot_reason' => $requestData['bot_reason'] ?? null,
    ]);
}

function getRecentClicks(PDO $pdo, int $limit = 100): array
{
    $stmt = $pdo->prepare("
        SELECT
            c.*,
            l.description,
            l.destination
        FROM clicks c
        LEFT JOIN links l ON c.link_id = l.id
        ORDER BY c.id DESC
        LIMIT :limit
    ");
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

function getRecentClicksFiltered(PDO $pdo, int $limit = 100, ?string $tokenFilter = null, bool $knownOnly = false): array
{
    $sql = "
        SELECT
            c.*,
            l.description,
            l.destination
        FROM clicks c
        LEFT JOIN links l ON c.link_id = l.id
        WHERE 1 = 1
    ";

    $params = [];

    if ($tokenFilter !== null && $tokenFilter !== '') {
        $sql .= " AND c.token LIKE :tokenFilter ";
        $params[':tokenFilter'] = '%' . $tokenFilter . '%';
    }

    if ($knownOnly) {
        $sql .= " AND c.link_id IS NOT NULL ";
    }

    $sql .= " ORDER BY c.id DESC LIMIT :limit ";

    $stmt = $pdo->prepare($sql);

    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value, PDO::PARAM_STR);
    }

    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

function getClickCountsByToken(PDO $pdo, bool $knownOnly = false, ?string $dateFrom = null, ?string $dateTo = null): array
{
    $sql = "
        SELECT
            c.token,
            COUNT(*) AS hit_count,
            MAX(c.clicked_at) AS last_seen,
            MAX(CASE WHEN c.link_id IS NOT NULL THEN 1 ELSE 0 END) AS is_known
        FROM clicks c
        WHERE 1 = 1
    ";

    $params = [];

    if ($knownOnly) {
        $sql .= " AND c.link_id IS NOT NULL ";
    }

    if ($dateFrom !== null && $dateFrom !== '') {
        $sql .= " AND c.clicked_at >= :dateFrom ";
        $params[':dateFrom'] = $dateFrom;
    }

    if ($dateTo !== null && $dateTo !== '') {
        $sql .= " AND c.clicked_at <= :dateTo ";
        $params[':dateTo'] = $dateTo;
    }

    $sql .= "
        GROUP BY c.token
        ORDER BY hit_count DESC, last_seen DESC
    ";

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value, PDO::PARAM_STR);
    }
    $stmt->execute();

    return $stmt->fetchAll();
}

function getAllLinks(PDO $pdo): array
{
    $stmt = $pdo->query("
        SELECT
            l.*,
            COUNT(c.id) AS click_count
        FROM links l
        LEFT JOIN clicks c ON l.id = c.link_id
        GROUP BY l.id
        ORDER BY l.id DESC
    ");

    return $stmt->fetchAll();
}

function getRecentClicksAdvancedFiltered(
    PDO $pdo,
    int $limit = 100,
    ?string $tokenFilter = null,
    ?string $ipFilter = null,
    ?string $visitorFilter = null,
    bool $knownOnly = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
): array {
    [$rows] = getRecentClicksAdvancedFilteredPaged(
        $pdo, $limit, 0,
        $tokenFilter, $ipFilter, $visitorFilter,
        $knownOnly, $dateFrom, $dateTo,
    );
    return $rows;
}

/**
 * Paginated version — returns [rows, totalCount].
 * Used by the dashboard; the unpaged wrapper above is kept for export/feed use.
 */
function getRecentClicksAdvancedFilteredPaged(
    PDO $pdo,
    int $limit = 50,
    int $offset = 0,
    ?string $tokenFilter = null,
    ?string $ipFilter = null,
    ?string $visitorFilter = null,
    bool $knownOnly = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
): array {
    $sql = "
        SELECT
            c.*,
            l.description,
            l.destination
        FROM clicks c
        LEFT JOIN links l ON c.link_id = l.id
        WHERE 1 = 1
    ";

    $params = [];

    $showAll = isset($_GET['show_all']) && $_GET['show_all'] === '1';
    $minScore = (int) getSetting($pdo, 'display_min_score', '20');
    if (!$showAll && $minScore > 0) {
        $sql .= " AND (c.confidence_score IS NULL OR c.confidence_score >= :minScore) ";
        $params[':minScore'] = $minScore;
    }

    if ($tokenFilter !== null && $tokenFilter !== '') {
        $sql .= " AND c.token LIKE :tokenFilter ";
        $params[':tokenFilter'] = '%' . $tokenFilter . '%';
    }

    if ($ipFilter !== null && $ipFilter !== '') {
        $sql .= " AND c.ip LIKE :ipFilter ";
        $params[':ipFilter'] = '%' . $ipFilter . '%';
    }

    if ($visitorFilter !== null && $visitorFilter !== '') {
        $sql .= " AND c.visitor_hash LIKE :visitorFilter ";
        $params[':visitorFilter'] = '%' . $visitorFilter . '%';
    }

    if ($knownOnly) {
        $sql .= " AND c.link_id IS NOT NULL ";
    }

    if ($dateFrom !== null && $dateFrom !== '') {
        $sql .= " AND substr(c.clicked_at, 1, 10) >= :dateFrom ";
        $params[':dateFrom'] = $dateFrom;
    }

    if ($dateTo !== null && $dateTo !== '') {
        $sql .= " AND substr(c.clicked_at, 1, 10) <= :dateTo ";
        $params[':dateTo'] = $dateTo;
    }

    // COUNT query for pagination total
    $countSql  = "SELECT COUNT(*) FROM clicks c LEFT JOIN links l ON c.link_id = l.id WHERE 1 = 1";
    // Re-use the same WHERE fragments already appended to $sql — extract them
    $whereOnly = substr($sql, strpos($sql, 'WHERE 1 = 1') + strlen('WHERE 1 = 1'));
    $countSql .= $whereOnly;

    $countStmt = $pdo->prepare($countSql);
    foreach ($params as $key => $value) {
        $countStmt->bindValue($key, $value, PDO::PARAM_STR);
    }
    if (isset($params[':minScore'])) {
        $countStmt->bindValue(':minScore', $params[':minScore'], PDO::PARAM_INT);
    }
    $countStmt->execute();
    $totalCount = (int) $countStmt->fetchColumn();

    $sql .= " ORDER BY c.id DESC LIMIT :limit OFFSET :offset ";

    $stmt = $pdo->prepare($sql);

    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value, PDO::PARAM_STR);
    }

    $stmt->bindValue(':limit',  $limit,  PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    return [$stmt->fetchAll(), $totalCount];
}

/**
 * Shared query for threat feed — returns all qualifying rows with IP and hit count.
 * Callers filter by address family.
 */
function getThreatFeedRows(PDO $pdo): array
{
    $enabled = getSetting($pdo, 'threat_feed_enabled', '1');
    if ($enabled !== '1') {
        return [];
    }

    $windowHours   = max(1, (int) getSetting($pdo, 'threat_feed_window_hours', '168'));
    $minConfidence = strtolower((string) getSetting($pdo, 'threat_feed_min_confidence', 'suspicious'));
    $minHits       = max(1, (int) getSetting($pdo, 'threat_feed_min_hits', '1'));

    $allowedLabels = match ($minConfidence) {
        'bot'          => ['bot'],
        'likely-human' => ['likely-human', 'suspicious', 'bot'],
        'human'        => ['human', 'likely-human', 'suspicious', 'bot'],
        default        => ['suspicious', 'bot'],
    };

    $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));

    $sql = "
        SELECT c.ip, COUNT(*) AS hit_count
        FROM clicks c
        LEFT JOIN asn_rules ar
            ON ar.asn = c.ip_asn
           AND ar.active = 1
           AND ar.exclude_from_feed = 1
        LEFT JOIN links lk
            ON lk.id = c.link_id
        LEFT JOIN ip_overrides io
            ON io.ip = c.ip
           AND io.active = 1
           AND io.mode = 'allow'
        WHERE c.ip IS NOT NULL
          AND c.ip <> ''
          AND c.event_type = 'click'
          AND c.clicked_at_unix_ms >= (strftime('%s', 'now') - ? * 3600) * 1000
          AND c.confidence_label IS NOT NULL
          AND c.confidence_label <> ''
          AND c.confidence_score IS NOT NULL
          AND c.confidence_label IN ($placeholders)
          AND ar.id IS NULL
          AND io.id IS NULL
          AND (lk.id IS NULL OR lk.exclude_from_feed = 0)
        GROUP BY c.ip
        HAVING COUNT(*) >= {$minHits}

        UNION

        SELECT ip, 0 AS hit_count
        FROM ip_overrides
        WHERE active = 1
          AND mode = 'block'
          AND ip IS NOT NULL
          AND ip <> ''

        ORDER BY ip ASC
    ";

    $params = array_merge(
        [$windowHours],
        $allowedLabels,
    );

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Normalize an IPv6 address to its canonical compressed form.
 * Returns null if the input is not a valid IPv6 address.
 */
function normalizeIpv6(string $ip): ?string
{
    $packed = @inet_pton($ip);
    if ($packed === false || strlen($packed) !== 16) {
        return null;
    }
    return inet_ntop($packed) ?: null;
}

/**
 * Returns deduplicated, validated IPv4 addresses from the threat feed.
 * Backwards-compatible replacement for getThreatFeedIps().
 */
function getThreatFeedIpv4(PDO $pdo): array
{
    $ips = [];
    foreach (getThreatFeedRows($pdo) as $row) {
        $ip = trim((string) ($row['ip'] ?? ''));
        if ($ip === '') continue;
        // Must be a valid IP and must be IPv4 (packed length = 4 bytes)
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 4) continue;
        $ips[] = inet_ntop($packed); // normalize representation
    }
    return array_values(array_unique($ips));
}

/**
 * Returns deduplicated, normalized IPv6 addresses from the threat feed.
 */
function getThreatFeedIpv6(PDO $pdo): array
{
    $ips = [];
    foreach (getThreatFeedRows($pdo) as $row) {
        $ip = trim((string) ($row['ip'] ?? ''));
        if ($ip === '') continue;
        $normalized = normalizeIpv6($ip);
        if ($normalized === null) continue;
        $ips[] = $normalized;
    }
    return array_values(array_unique($ips));
}

/**
 * Returns count of IPs currently in the threat feed (IPv4 + IPv6).
 * Used for the feed preview in the admin UI.
 */
function getThreatFeedCount(PDO $pdo): array
{
    $v4 = getThreatFeedIpv4($pdo);
    $v6 = getThreatFeedIpv6($pdo);
    return [
        'ipv4'  => count($v4),
        'ipv6'  => count($v6),
        'total' => count($v4) + count($v6),
    ];
}

/**
 * Legacy alias — keeps existing callers working.
 */
function getThreatFeedIps(PDO $pdo): array
{
    return getThreatFeedIpv4($pdo);
}

/**
 * Export clicks applying the configured export settings (label threshold +
 * time window) unless manual dashboard filters are present, in which case
 * those take full precedence.
 *
 * The $manualFilters flag tells us whether the caller is passing explicit
 * filter values from the dashboard. When true, the export settings are
 * bypassed so the admin gets exactly what they filtered.
 */
function exportClicks(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $tokenFilter = null,
    ?string $ipFilter = null,
    ?string $visitorFilter = null,
    bool $knownOnly = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 5000,
): array {
    if ($manualFilters) {
        // Dashboard filters active — return exactly what they asked for.
        return getRecentClicksAdvancedFiltered(
            $pdo, $limit,
            $tokenFilter, $ipFilter, $visitorFilter,
            $knownOnly, $dateFrom, $dateTo,
        );
    }

    // No manual filters — apply the configured export threshold and window.
    $minConfidence = strtolower((string) getSetting($pdo, 'export_min_confidence', 'suspicious'));
    $windowHours   = max(1, (int) getSetting($pdo, 'export_window_hours', '168'));
    $minScore      = max(0, min(100, (int) getSetting($pdo, 'export_min_score', '0')));

    $allowedLabels = match ($minConfidence) {
        'bot'          => ['bot'],
        'likely-human' => ['likely-human', 'suspicious', 'bot'],
        'human'        => ['human', 'likely-human', 'suspicious', 'bot'],
        default        => ['suspicious', 'bot'],
    };

    $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));

    $sql = "
        SELECT c.*, l.description, l.destination
        FROM clicks c
        LEFT JOIN links l ON c.link_id = l.id
        WHERE c.clicked_at >= datetime('now', ?)
          AND c.confidence_label IN ($placeholders)
          AND (c.confidence_score IS NULL OR c.confidence_score >= ?)
        ORDER BY c.id DESC
        LIMIT ?
    ";

    $params = array_merge(
        ['-' . $windowHours . ' hours'],
        $allowedLabels,
        [$minScore, $limit],
    );

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Per-IP summary: first seen, last seen, total hits, distinct tokens,
 * highest confidence label observed, and whether any active ASN rule applies.
 */
function getIpSummary(PDO $pdo, string $ip): array
{
    $stmt = $pdo->prepare("
        SELECT
            COUNT(*)                        AS total_hits,
            MIN(clicked_at)                 AS first_seen,
            MAX(clicked_at)                 AS last_seen,
            COUNT(DISTINCT token)           AS distinct_tokens,
            MIN(confidence_score)           AS lowest_score,
            SUM(CASE WHEN confidence_label = 'bot'          THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN confidence_label = 'suspicious'   THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN confidence_label = 'likely-human' THEN 1 ELSE 0 END) AS likely_human_count,
            SUM(CASE WHEN confidence_label = 'human'        THEN 1 ELSE 0 END) AS human_count,
            MAX(ip_org)                     AS ip_org,
            MAX(ip_asn)                     AS ip_asn,
            MAX(ip_country)                 AS ip_country
        FROM clicks
        WHERE ip = :ip
    ");
    $stmt->execute([':ip' => $ip]);
    $row = $stmt->fetch();

    // Check for an active ASN rule.
    $asnRule = null;
    if (!empty($row['ip_asn'])) {
        $asnRule = getAsnRuleByAsn($pdo, (string) $row['ip_asn']);
    }

    return array_merge($row ?: [], ['asn_rule' => $asnRule]);
}

/**
 * Probabilistic auto-cleanup: called on every tracked request with a 1-in-100
 * chance of running. This means retention enforces itself without a cron job,
 * adding only ~1% overhead and only when retention is actually configured.
 */
function maybeRunAutoCleanup(PDO $pdo): void
{
    $days = (int) getSetting($pdo, 'data_retention_days', '0');
    if ($days <= 0) {
        return;
    }
    // ~1% of requests trigger cleanup.
    if (random_int(1, 100) !== 1) {
        return;
    }
    cleanupOldClicks($pdo, $days);
}

function cleanupOldClicks(PDO $pdo, int $days): int
{
    if ($days <= 0) {
        return 0;
    }

    $stmt = $pdo->prepare("
        DELETE FROM clicks
        WHERE clicked_at < datetime('now', :window)
    ");
    $stmt->execute([
        ':window' => '-' . $days . ' days',
    ]);

    return $stmt->rowCount();
}

function getAsnRules(PDO $pdo): array
{
    return $pdo->query("
        SELECT id, asn, label, penalty, active, exclude_from_feed, created_at
        FROM asn_rules
        ORDER BY asn ASC
    ")->fetchAll();
}

function getActiveAsnPenaltyMap(PDO $pdo): array
{
    $rows = $pdo->query("
        SELECT asn, penalty
        FROM asn_rules
        WHERE active = 1
    ")->fetchAll();

    $map = [];
    foreach ($rows as $row) {
        $map[(string) $row['asn']] = (int) $row['penalty'];
    }

    return $map;
}

function getAsnRuleByAsn(PDO $pdo, string $asn): ?array
{
    $stmt = $pdo->prepare("
        SELECT id, asn, label, penalty, active, created_at
        FROM asn_rules
        WHERE asn = :asn
        LIMIT 1
    ");
    $stmt->execute([':asn' => $asn]);
    $row = $stmt->fetch();

    return $row ?: null;
}

function createAsnRule(PDO $pdo, string $asn, string $label = '', int $penalty = 10, bool $excludeFromFeed = false): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO asn_rules (asn, label, penalty, active, exclude_from_feed, created_at)
        VALUES (:asn, :label, :penalty, 1, :exclude_from_feed, :created_at)
    ");

    return $stmt->execute([
        ':asn' => $asn,
        ':label' => $label,
        ':penalty' => $penalty,
        ':exclude_from_feed' => $excludeFromFeed ? 1 : 0,
        ':created_at' => date('c'),
    ]);
}

function updateAsnRule(PDO $pdo, int $id, string $asn, string $label, int $penalty, bool $excludeFromFeed): bool
{
    $stmt = $pdo->prepare("
        UPDATE asn_rules
        SET asn               = :asn,
            label             = :label,
            penalty           = :penalty,
            exclude_from_feed = :exclude_from_feed
        WHERE id = :id
    ");

    return $stmt->execute([
        ':id'               => $id,
        ':asn'              => $asn,
        ':label'            => $label,
        ':penalty'          => $penalty,
        ':exclude_from_feed' => $excludeFromFeed ? 1 : 0,
    ]);
}

function setAsnRuleActive(PDO $pdo, int $id, bool $active): bool
{
    $stmt = $pdo->prepare("
        UPDATE asn_rules
        SET active = :active
        WHERE id = :id
    ");

    return $stmt->execute([
        ':active' => $active ? 1 : 0,
        ':id' => $id,
    ]);
}

function deleteAsnRule(PDO $pdo, int $id): bool
{
    $stmt = $pdo->prepare("DELETE FROM asn_rules WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

/* ======================================================
   IP OVERRIDES
   ====================================================== */

function getIpOverrides(PDO $pdo): array
{
    return $pdo->query("
        SELECT id, ip, mode, notes, active, created_at
        FROM ip_overrides
        ORDER BY ip ASC
    ")->fetchAll();
}

function getActiveIpOverrideMap(PDO $pdo): array
{
    $rows = $pdo->query("
        SELECT ip, mode
        FROM ip_overrides
        WHERE active = 1
    ")->fetchAll();

    $map = [];
    foreach ($rows as $row) {
        $map[(string) $row['ip']] = (string) $row['mode'];
    }
    return $map;
}

function getIpOverrideByIp(PDO $pdo, string $ip): ?array
{
    $stmt = $pdo->prepare("
        SELECT id, ip, mode, notes, active, created_at
        FROM ip_overrides
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute([':ip' => $ip]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function createIpOverride(PDO $pdo, string $ip, string $mode, string $notes = ''): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO ip_overrides (ip, mode, notes, active, created_at)
        VALUES (:ip, :mode, :notes, 1, :created_at)
    ");
    return $stmt->execute([
        ':ip'         => $ip,
        ':mode'       => $mode,
        ':notes'      => $notes,
        ':created_at' => date('c'),
    ]);
}

function updateIpOverride(PDO $pdo, int $id, string $ip, string $mode, string $notes): bool
{
    $stmt = $pdo->prepare("
        UPDATE ip_overrides
        SET ip    = :ip,
            mode  = :mode,
            notes = :notes
        WHERE id = :id
    ");
    return $stmt->execute([
        ':id'    => $id,
        ':ip'    => $ip,
        ':mode'  => $mode,
        ':notes' => $notes,
    ]);
}

function setIpOverrideActive(PDO $pdo, int $id, bool $active): bool
{
    $stmt = $pdo->prepare("
        UPDATE ip_overrides SET active = :active WHERE id = :id
    ");
    return $stmt->execute([':active' => $active ? 1 : 0, ':id' => $id]);
}

function deleteIpOverride(PDO $pdo, int $id): bool
{
    $stmt = $pdo->prepare("DELETE FROM ip_overrides WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

/* ======================================================
   BEHAVIORALLY FLAGGED IPs
   Returns IPs where confidence_reason contains burst,
   rapid_repeat, or multi_token signals, with summary data.
   ====================================================== */

function getBehaviorallyFlaggedIps(PDO $pdo, int $windowHours = 24): array
{
    $cutoffMs = (int)(microtime(true) * 1000) - ($windowHours * 3600 * 1000);

    $stmt = $pdo->prepare("
        SELECT
            ip,
            COUNT(*)                                                        AS total_hits,
            MIN(clicked_at)                                                 AS first_seen,
            MAX(clicked_at)                                                 AS last_seen,
            MAX(ip_org)                                                     AS ip_org,
            MAX(ip_country)                                                 AS ip_country,
            MIN(confidence_score)                                           AS lowest_score,
            MAX(confidence_label)                                           AS worst_label,
            GROUP_CONCAT(DISTINCT confidence_reason)                        AS all_reasons,
            SUM(CASE WHEN confidence_reason LIKE '%burst%'        THEN 1 ELSE 0 END) AS burst_hits,
            SUM(CASE WHEN confidence_reason LIKE '%rapid_repeat%' THEN 1 ELSE 0 END) AS rapid_hits,
            SUM(CASE WHEN confidence_reason LIKE '%multi_token%'  THEN 1 ELSE 0 END) AS multi_hits
        FROM clicks
        WHERE clicked_at_unix_ms >= :cutoff
          AND (
              confidence_reason LIKE '%burst%'
              OR confidence_reason LIKE '%rapid_repeat%'
              OR confidence_reason LIKE '%multi_token%'
          )
          AND ip IS NOT NULL
          AND ip <> ''
        GROUP BY ip
        ORDER BY total_hits DESC
        LIMIT 50
    ");
    $stmt->execute([':cutoff' => $cutoffMs]);
    return $stmt->fetchAll();
}

/* ======================================================
   COUNTRY RULES
   ====================================================== */

function getCountryRules(PDO $pdo): array
{
    return $pdo->query("
        SELECT id, country_code, label, penalty, active, created_at
        FROM country_rules
        ORDER BY country_code ASC
    ")->fetchAll();
}

function getActiveCountryPenaltyMap(PDO $pdo): array
{
    $rows = $pdo->query("
        SELECT country_code, penalty
        FROM country_rules
        WHERE active = 1
    ")->fetchAll();

    $map = [];
    foreach ($rows as $row) {
        $map[strtoupper((string) $row['country_code'])] = (int) $row['penalty'];
    }
    return $map;
}

function getCountryRuleByCode(PDO $pdo, string $code): ?array
{
    $stmt = $pdo->prepare("
        SELECT id, country_code, label, penalty, active, created_at
        FROM country_rules
        WHERE country_code = :code
        LIMIT 1
    ");
    $stmt->execute([':code' => strtoupper($code)]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function createCountryRule(PDO $pdo, string $code, string $label, int $penalty): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO country_rules (country_code, label, penalty, active, created_at)
        VALUES (:code, :label, :penalty, 1, :created_at)
    ");
    return $stmt->execute([
        ':code'       => strtoupper($code),
        ':label'      => $label,
        ':penalty'    => $penalty,
        ':created_at' => date('c'),
    ]);
}

function updateCountryRule(PDO $pdo, int $id, string $code, string $label, int $penalty): bool
{
    $stmt = $pdo->prepare("
        UPDATE country_rules
        SET country_code = :code,
            label        = :label,
            penalty      = :penalty
        WHERE id = :id
    ");
    return $stmt->execute([
        ':id'      => $id,
        ':code'    => strtoupper($code),
        ':label'   => $label,
        ':penalty' => $penalty,
    ]);
}

function setCountryRuleActive(PDO $pdo, int $id, bool $active): bool
{
    $stmt = $pdo->prepare("
        UPDATE country_rules SET active = :active WHERE id = :id
    ");
    return $stmt->execute([':active' => $active ? 1 : 0, ':id' => $id]);
}

function deleteCountryRule(PDO $pdo, int $id): bool
{
    $stmt = $pdo->prepare("DELETE FROM country_rules WHERE id = :id");
    return $stmt->execute([':id' => $id]);
}

/**
 * ============================================================
 * ADD THESE FUNCTIONS TO THE BOTTOM OF includes/db.php
 * ============================================================
 *
 * These provide server-side aggregated endpoints for Grafana.
 * They share the same filter logic as exportClicks() so the
 * Grafana token can be scoped identically to the export.
 */

/**
 * Build the shared WHERE clause and params used by all aggregation
 * queries. Mirrors the logic in exportClicks() exactly.
 *
 * Returns [$whereSql, $params] where $whereSql begins with " AND "
 * (safe to append after "WHERE 1=1").
 */
function buildExportWhere(PDO $pdo, bool $manualFilters, ?string $dateFrom, ?string $dateTo): array
{
    $where  = '';
    $params = [];

    if ($manualFilters) {
        // Manual date filters from the admin dashboard
        if ($dateFrom !== null && $dateFrom !== '') {
            $where .= " AND substr(c.clicked_at, 1, 10) >= :dateFrom ";
            $params[':dateFrom'] = $dateFrom;
        }
        if ($dateTo !== null && $dateTo !== '') {
            $where .= " AND substr(c.clicked_at, 1, 10) <= :dateTo ";
            $params[':dateTo'] = $dateTo;
        }
    } else {
        // Use configured export window + confidence threshold
        $minConfidence = strtolower((string) getSetting($pdo, 'export_min_confidence', 'suspicious'));
        $windowHours   = max(1, (int) getSetting($pdo, 'export_window_hours', '168'));
        $minScore      = max(0, min(100, (int) getSetting($pdo, 'export_min_score', '0')));

        $allowedLabels = match ($minConfidence) {
            'bot'          => ['bot'],
            'likely-human' => ['likely-human', 'suspicious', 'bot'],
            'human'        => ['human', 'likely-human', 'suspicious', 'bot'],
            default        => ['suspicious', 'bot'],
        };

        $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));

        $where .= " AND c.clicked_at >= datetime('now', ?) ";
        $where .= " AND c.confidence_label IN ($placeholders) ";
        $where .= " AND (c.confidence_score IS NULL OR c.confidence_score >= ?) ";

        $params = array_merge(
            ['-' . $windowHours . ' hours'],
            $allowedLabels,
            [$minScore],
        );
    }

    return [$where, $params];
}

/**
 * Summary stats for the Grafana stat panels.
 * Returns total, bot_count, suspicious_count, likely_human_count,
 * human_count, unique_ips, avg_confidence_score.
 */
function exportStats(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);

    $sql = "
        SELECT
            COUNT(*)                                                              AS total,
            SUM(CASE WHEN c.confidence_label = 'bot'          THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN c.confidence_label = 'suspicious'   THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN c.confidence_label = 'likely-human' THEN 1 ELSE 0 END) AS likely_human_count,
            SUM(CASE WHEN c.confidence_label = 'human'        THEN 1 ELSE 0 END) AS human_count,
            COUNT(DISTINCT c.ip)                                                  AS unique_ips,
            ROUND(AVG(c.confidence_score), 1)                                     AS avg_confidence_score
        FROM clicks c
        WHERE 1=1
        $where
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();

    // Cast everything to the right types so JSON encodes cleanly
    return [
        'total'                => (int)   ($row['total']                ?? 0),
        'bot_count'            => (int)   ($row['bot_count']            ?? 0),
        'suspicious_count'     => (int)   ($row['suspicious_count']     ?? 0),
        'likely_human_count'   => (int)   ($row['likely_human_count']   ?? 0),
        'human_count'          => (int)   ($row['human_count']          ?? 0),
        'unique_ips'           => (int)   ($row['unique_ips']           ?? 0),
        'avg_confidence_score' => (float) ($row['avg_confidence_score'] ?? 0.0),
    ];
}

/**
 * Top IPs by hit count, pre-aggregated for Grafana bar chart.
 */
function exportByIp(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 20,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);
    $params[] = $limit;

    $sql = "
        SELECT
            c.ip,
            MAX(c.ip_org)     AS ip_org,
            MAX(c.ip_country) AS ip_country,
            COUNT(*)          AS hits
        FROM clicks c
        WHERE c.ip IS NOT NULL
          AND c.ip <> ''
          $where
        GROUP BY c.ip
        ORDER BY hits DESC
        LIMIT ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Top countries by hit count, pre-aggregated for Grafana bar chart.
 */
function exportByCountry(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 20,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);
    $params[] = $limit;

    $sql = "
        SELECT
            c.ip_country      AS country,
            COUNT(*)          AS hits
        FROM clicks c
        WHERE c.ip_country IS NOT NULL
          AND c.ip_country <> ''
          $where
        GROUP BY c.ip_country
        ORDER BY hits DESC
        LIMIT ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Update exportStats to also return unique_tokens and bot_pct.
 * This is a new wrapper — exportStats() is unchanged for compatibility.
 */
function exportStatsExtended(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);

    $sql = "
        SELECT
            COUNT(*)                                                              AS total,
            SUM(CASE WHEN c.confidence_label = 'bot'          THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN c.confidence_label = 'suspicious'   THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN c.confidence_label = 'likely-human' THEN 1 ELSE 0 END) AS likely_human_count,
            SUM(CASE WHEN c.confidence_label = 'human'        THEN 1 ELSE 0 END) AS human_count,
            COUNT(DISTINCT c.ip)                                                  AS unique_ips,
            COUNT(DISTINCT c.token)                                               AS unique_tokens,
            ROUND(AVG(c.confidence_score), 1)                                     AS avg_confidence_score
        FROM clicks c
        WHERE 1=1
        $where
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();

    $total    = (int) ($row['total'] ?? 0);
    $botCount = (int) ($row['bot_count'] ?? 0);
    $botPct   = $total > 0 ? round(($botCount / $total) * 100, 1) : 0.0;

    return [
        'total'                => $total,
        'bot_count'            => $botCount,
        'suspicious_count'     => (int)   ($row['suspicious_count']     ?? 0),
        'likely_human_count'   => (int)   ($row['likely_human_count']   ?? 0),
        'human_count'          => (int)   ($row['human_count']          ?? 0),
        'unique_ips'           => (int)   ($row['unique_ips']           ?? 0),
        'unique_tokens'        => (int)   ($row['unique_tokens']        ?? 0),
        'avg_confidence_score' => (float) ($row['avg_confidence_score'] ?? 0.0),
        'bot_pct'              => (float) $botPct,
    ];
}

/**
 * Top tokens by hit count.
 */
function exportByToken(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 5,
    ?string $labelFilter = null,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);

    if ($labelFilter !== null && $labelFilter !== '') {
        $where   .= " AND c.confidence_label = ? ";
        $params[] = $labelFilter;
    }

    $params[] = $limit;

    $sql = "
        SELECT
            c.token,
            COUNT(*) AS hits
        FROM clicks c
        WHERE c.token IS NOT NULL
          AND c.token <> ''
          $where
        GROUP BY c.token
        ORDER BY hits DESC
        LIMIT ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Top ASN organisations by hit count.
 */
function exportByOrg(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 5,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);
    $params[] = $limit;

    $sql = "
        SELECT
            c.ip_org  AS org,
            MAX(c.ip_asn) AS asn,
            COUNT(*)  AS hits
        FROM clicks c
        WHERE c.ip_org IS NOT NULL
          AND c.ip_org <> ''
          $where
        GROUP BY c.ip_org
        ORDER BY hits DESC
        LIMIT ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Top detection signals (exploded from comma-separated confidence_reason).
 * Excludes country_penalty and ip_override meta-reasons.
 */
function exportBySignal(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 8,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);

    // Pull all confidence_reason strings, explode in PHP
    $sql = "
        SELECT confidence_reason
        FROM clicks c
        WHERE c.confidence_reason IS NOT NULL
          AND c.confidence_reason <> ''
          $where
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);

    $counts = [];
    foreach ($rows as $reasonStr) {
        $signals = array_map('trim', explode(',', $reasonStr));
        foreach ($signals as $signal) {
            if ($signal === '') continue;
            // Exclude meta-reasons
            if (str_starts_with($signal, 'country_penalty') || str_starts_with($signal, 'ip_override')) continue;
            $counts[$signal] = ($counts[$signal] ?? 0) + 1;
        }
    }

    arsort($counts);
    $top = array_slice($counts, 0, $limit, true);

    $result = [];
    foreach ($top as $signal => $count) {
        $result[] = ['signal' => $signal, 'hits' => $count];
    }
    return $result;
}

/**
 * Events over time bucketed by confidence label.
 * Accepts Unix timestamps (ms) for from/to so Grafana can pass its time range directly.
 * Bucket size adapts to the span automatically.
 */
function exportOverTime(
    PDO $pdo,
    ?int $fromMs = null,
    ?int $toMs = null,
): array {
    $nowMs    = (int) round(microtime(true) * 1000);
    $fromMs   = $fromMs ?? ($nowMs - 7 * 24 * 3600 * 1000);
    $toMs     = $toMs   ?? $nowMs;
    $spanSecs = max(1, (int) (($toMs - $fromMs) / 1000));

    // Adaptive bucket size
    if ($spanSecs <= 6 * 3600) {
        $bucketSecs = 900;       // 15 min
        $format     = '%Y-%m-%d %H:%M';
    } elseif ($spanSecs <= 48 * 3600) {
        $bucketSecs = 3600;      // 1 hour
        $format     = '%Y-%m-%d %H:00';
    } elseif ($spanSecs <= 14 * 86400) {
        $bucketSecs = 6 * 3600;  // 6 hours
        $format     = '%Y-%m-%d %H:00';
    } else {
        $bucketSecs = 86400;     // 1 day
        $format     = '%Y-%m-%d';
    }

    $fromUnix = (int) ($fromMs / 1000);
    $toUnix   = (int) ($toMs   / 1000);

    $sql = "
        SELECT
            strftime('{$format}',
                datetime(CAST((clicked_at_unix_ms / 1000 / {$bucketSecs}) AS INTEGER) * {$bucketSecs}, 'unixepoch')
            )                    AS bucket,
            confidence_label     AS label,
            COUNT(*)             AS hits
        FROM clicks
        WHERE clicked_at_unix_ms >= :from_ms
          AND clicked_at_unix_ms <= :to_ms
          AND confidence_label IS NOT NULL
          AND confidence_label <> ''
        GROUP BY bucket, label
        ORDER BY bucket ASC, label ASC
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([':from_ms' => $fromMs, ':to_ms' => $toMs]);
    return $stmt->fetchAll();
}

/**
 * Behavioral signal hits only — burst_activity, rapid_repeat,
 * fast_repeat, multi_token_scan. Server-side filtered so Grafana
 * needs no transformations.
 */
function exportBehavioralSignals(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);

    $sql = "
        SELECT confidence_reason
        FROM clicks c
        WHERE c.confidence_reason IS NOT NULL
          AND c.confidence_reason <> ''
          $where
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);

    $behavioral = ['burst_activity', 'rapid_repeat', 'fast_repeat', 'multi_token_scan'];
    $counts     = array_fill_keys($behavioral, 0);

    foreach ($rows as $reasonStr) {
        $signals = array_map('trim', explode(',', $reasonStr));
        foreach ($signals as $signal) {
            if (isset($counts[$signal])) {
                $counts[$signal]++;
            }
        }
    }

    // Sort descending, exclude zeros
    arsort($counts);
    $result = [];
    foreach ($counts as $signal => $hits) {
        if ($hits > 0) {
            $result[] = ['signal' => $signal, 'hits' => $hits];
        }
    }
    return $result;
}
