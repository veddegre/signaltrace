<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/../vendor/autoload.php';

use GeoIp2\Database\Reader;

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

    ensureColumn($pdo, 'clicks', 'event_type', "TEXT NOT NULL DEFAULT 'click'");
    ensureColumn($pdo, 'clicks', 'clicked_at_unix_ms', "INTEGER");
    ensureColumn($pdo, 'clicks', 'ip_asn', "TEXT");
    ensureColumn($pdo, 'clicks', 'ip_org', "TEXT");
    ensureColumn($pdo, 'clicks', 'ip_country', "TEXT");
    ensureColumn($pdo, 'clicks', 'visitor_hash', "TEXT");
    ensureColumn($pdo, 'clicks', 'confidence_score', "INTEGER");
    ensureColumn($pdo, 'clicks', 'confidence_label', "TEXT");
    ensureColumn($pdo, 'clicks', 'confidence_reason', "TEXT");
    ensureColumn($pdo, 'clicks', 'first_for_token', "INTEGER DEFAULT 0");
    ensureColumn($pdo, 'clicks', 'prior_events_for_token', "INTEGER DEFAULT 0");
    ensureColumn($pdo, 'clicks', 'x_forwarded_for', "TEXT");
    ensureColumn($pdo, 'clicks', 'accept', "TEXT");
    ensureColumn($pdo, 'clicks', 'accept_encoding', "TEXT");
    ensureColumn($pdo, 'clicks', 'scheme', "TEXT");
    ensureColumn($pdo, 'clicks', 'remote_port', "TEXT");
    ensureColumn($pdo, 'clicks', 'sec_fetch_site', "TEXT");
    ensureColumn($pdo, 'clicks', 'sec_fetch_mode', "TEXT");
    ensureColumn($pdo, 'clicks', 'sec_fetch_dest', "TEXT");
    ensureColumn($pdo, 'clicks', 'sec_ch_ua', "TEXT");
    ensureColumn($pdo, 'clicks', 'sec_ch_ua_platform', "TEXT");

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

    seedDefaultSettings($pdo);
    seedDefaultSkipPatterns($pdo);
}

function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void
{
    $stmt = $pdo->query("PRAGMA table_info($table)");
    $cols = $stmt->fetchAll();

    foreach ($cols as $col) {
        if (($col['name'] ?? '') === $column) {
            return;
        }
    }

    $pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
}

function seedDefaultSettings(PDO $pdo): void
{
    $defaults = [
        'app_name' => 'SignalTrace',
        'base_url' => '',
        'default_redirect_url' => 'https://example.com/',
        'unknown_path_behavior' => 'redirect',
        'pixel_enabled' => '1',
        'noise_filter_enabled' => '1',
        'threat_feed_enabled' => '1',
        'threat_feed_window_hours' => '168',
        'threat_feed_min_confidence' => 'suspicious',
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
    $count = (int)$pdo->query("SELECT COUNT(*) FROM skip_patterns")->fetchColumn();
    if ($count > 0) {
        return;
    }

    $defaults = [
        ['type' => 'exact', 'pattern' => 'root'],
        ['type' => 'exact', 'pattern' => 'favicon.ico'],
        ['type' => 'exact', 'pattern' => 'favicon'],
        ['type' => 'exact', 'pattern' => 'robots.txt'],
        ['type' => 'exact', 'pattern' => 'apple-touch-icon.png'],
        ['type' => 'exact', 'pattern' => 'apple-touch-icon-precomposed.png'],
        ['type' => 'exact', 'pattern' => 'ads.txt'],
        ['type' => 'exact', 'pattern' => 'sitemap.xml'],
        ['type' => 'exact', 'pattern' => 'security.txt'],
        ['type' => 'exact', 'pattern' => '.well-known/security.txt'],

        ['type' => 'contains', 'pattern' => '.env'],
        ['type' => 'contains', 'pattern' => '.git/config'],
        ['type' => 'contains', 'pattern' => 'phpinfo.php'],
        ['type' => 'contains', 'pattern' => 'phpversion.php'],
        ['type' => 'contains', 'pattern' => 'info.php'],
        ['type' => 'contains', 'pattern' => 'php.php'],
        ['type' => 'contains', 'pattern' => 'pinfo.php'],
        ['type' => 'contains', 'pattern' => 'eval-stdin.php'],
        ['type' => 'contains', 'pattern' => '_ignition/execute-solution'],
        ['type' => 'contains', 'pattern' => 'swagger'],
        ['type' => 'contains', 'pattern' => 'graphql'],
        ['type' => 'contains', 'pattern' => 'api-docs'],
        ['type' => 'contains', 'pattern' => 'actuator/'],
        ['type' => 'contains', 'pattern' => 'autodiscover'],
        ['type' => 'contains', 'pattern' => 'wp-login'],
        ['type' => 'contains', 'pattern' => 'wordpress'],
        ['type' => 'contains', 'pattern' => 'owa/'],
        ['type' => 'contains', 'pattern' => 'hudson'],
        ['type' => 'contains', 'pattern' => 'geoserver'],
        ['type' => 'contains', 'pattern' => 'solr/'],
        ['type' => 'contains', 'pattern' => 'web.config'],
        ['type' => 'contains', 'pattern' => '.vscode/'],
        ['type' => 'contains', 'pattern' => 'docker-compose'],
        ['type' => 'contains', 'pattern' => '.aws/credentials'],
        ['type' => 'contains', 'pattern' => 'config.json'],
        ['type' => 'contains', 'pattern' => 'metadatauploader'],
        ['type' => 'contains', 'pattern' => 'logon/logonpoint'],
        ['type' => 'contains', 'pattern' => 'webroot/index.php/_environment'],
        ['type' => 'contains', 'pattern' => '_profiler/phpinfo'],
        ['type' => 'contains', 'pattern' => '.well-known/passkey-endpoints'],
        ['type' => 'contains', 'pattern' => '.openclaw/'],
        ['type' => 'contains', 'pattern' => 'vpn/index.html'],
        ['type' => 'contains', 'pattern' => 'login/login'],
        ['type' => 'contains', 'pattern' => 'debug/default/view'],
        ['type' => 'contains', 'pattern' => '@vite/env'],
        ['type' => 'contains', 'pattern' => 'trace.axd'],
        ['type' => 'contains', 'pattern' => 'telescope/requests'],
        ['type' => 'contains', 'pattern' => 'api/gql'],
        ['type' => 'contains', 'pattern' => 'ediscovery.exporttool'],
        ['type' => 'contains', 'pattern' => 'v2/_catalog'],
        ['type' => 'contains', 'pattern' => 'login.action'],
        ['type' => 'contains', 'pattern' => 'apple-touch-icon'],
        ['type' => 'contains', 'pattern' => 'ext-js/app/common/zld_product_spec.js'],
        ['type' => 'contains', 'pattern' => 'jira-webapp-dist/pom.properties'],
        ['type' => 'contains', 'pattern' => '/meta-inf/maven/com.atlassian.jira/'],
        ['type' => 'contains', 'pattern' => 'weblanguage'],

        ['type' => 'prefix', 'pattern' => '.well-known/'],
        ['type' => 'prefix', 'pattern' => '_next/'],
        ['type' => 'prefix', 'pattern' => 'api/'],
        ['type' => 'prefix', 'pattern' => 'vendor/'],
        ['type' => 'prefix', 'pattern' => 'backup/'],
        ['type' => 'prefix', 'pattern' => 'public/'],
        ['type' => 'prefix', 'pattern' => 'dev/'],
        ['type' => 'prefix', 'pattern' => 'test/'],
        ['type' => 'prefix', 'pattern' => 'server/'],
        ['type' => 'prefix', 'pattern' => 'core/'],
        ['type' => 'prefix', 'pattern' => 'config/'],
        ['type' => 'prefix', 'pattern' => 'storage/'],
        ['type' => 'prefix', 'pattern' => 'uploads/'],
        ['type' => 'prefix', 'pattern' => 'assets/'],
        ['type' => 'prefix', 'pattern' => 'media/'],
        ['type' => 'prefix', 'pattern' => 'src/'],
        ['type' => 'prefix', 'pattern' => 'cms/'],
        ['type' => 'prefix', 'pattern' => 'lab/'],
        ['type' => 'prefix', 'pattern' => 'lib/'],
        ['type' => 'prefix', 'pattern' => 'dist/'],
        ['type' => 'prefix', 'pattern' => 'frontend/'],
        ['type' => 'prefix', 'pattern' => 'backend/'],
        ['type' => 'prefix', 'pattern' => 'project/'],
        ['type' => 'prefix', 'pattern' => 'node/'],
        ['type' => 'prefix', 'pattern' => 'includes/'],
        ['type' => 'prefix', 'pattern' => 'sdk/'],
        ['type' => 'prefix', 'pattern' => 'ext-js/'],
        ['type' => 'prefix', 'pattern' => 's/'],
    ];

    $stmt = $pdo->prepare("
        INSERT INTO skip_patterns (type, pattern, active, created_at)
        VALUES (:type, :pattern, 1, :created_at)
    ");

    foreach ($defaults as $row) {
        $stmt->execute([
            ':type' => $row['type'],
            ':pattern' => $row['pattern'],
            ':created_at' => gmdate('c'),
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

    return $value === false ? $default : (string)$value;
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
        $type = strtolower((string)$row['type']);
        if (isset($map[$type])) {
            $map[$type][] = strtolower((string)$row['pattern']);
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
        ':created_at' => gmdate('c'),
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

function getMaxMindDbPaths(): array
{
    $asnPath = getenv('MAXMIND_ASN_DB') ?: '/var/lib/GeoIP/GeoLite2-ASN.mmdb';
    $countryPath = getenv('MAXMIND_COUNTRY_DB') ?: '/var/lib/GeoIP/GeoLite2-Country.mmdb';

    return [
        'asn' => $asnPath,
        'country' => $countryPath,
    ];
}

function getMaxMindReaders(): array
{
    static $readers = null;

    if ($readers !== null) {
        return $readers;
    }

    $paths = getMaxMindDbPaths();

    $asnReader = null;
    $countryReader = null;

    try {
        if (is_file($paths['asn'])) {
            $asnReader = new Reader($paths['asn']);
        }
    } catch (Throwable $e) {
        $asnReader = null;
    }

    try {
        if (is_file($paths['country'])) {
            $countryReader = new Reader($paths['country']);
        }
    } catch (Throwable $e) {
        $countryReader = null;
    }

    $readers = [
        'asn' => $asnReader,
        'country' => $countryReader,
    ];

    return $readers;
}

function lookupIpEnrichment(string $ip): array
{
    $result = [
        'ip_asn' => null,
        'ip_org' => null,
        'ip_country' => null,
    ];

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return $result;
    }

    $readers = getMaxMindReaders();

    if ($readers['asn'] instanceof Reader) {
        try {
            $asn = $readers['asn']->asn($ip);
            $result['ip_asn'] = isset($asn->autonomousSystemNumber)
                ? (string)$asn->autonomousSystemNumber
                : null;
            $result['ip_org'] = isset($asn->autonomousSystemOrganization)
                ? (string)$asn->autonomousSystemOrganization
                : null;
        } catch (Throwable $e) {
        }
    }

    if ($readers['country'] instanceof Reader) {
        try {
            $country = $readers['country']->country($ip);
            $result['ip_country'] = isset($country->country->isoCode)
                ? (string)$country->country->isoCode
                : null;
        } catch (Throwable $e) {
        }
    }

    return $result;
}

function currentUnixMs(): int
{
    return (int) round(microtime(true) * 1000);
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

function createLink(PDO $pdo, string $token, string $destination, string $description = ''): bool
{
    $stmt = $pdo->prepare("
        INSERT INTO links (token, destination, description, active, created_at)
        VALUES (:token, :destination, :description, 1, :created_at)
    ");

    return $stmt->execute([
        ':token' => $token,
        ':destination' => $destination,
        ':description' => $description,
        ':created_at' => gmdate('c'),
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

    return (int)$stmt->fetchColumn();
}

function logClick(PDO $pdo, array $link, array $requestData): void
{
    $ip = (string)($requestData['ip'] ?? '');
    $token = (string)($link['token'] ?? '');
    $visitorHash = $requestData['visitor_hash'] ?? null;
    $priorEventsForToken = getPriorEventsForToken($pdo, $token, is_string($visitorHash) ? $visitorHash : null);
    $firstForToken = $priorEventsForToken === 0 ? 1 : 0;

    $enrichment = $ip !== '' ? lookupIpEnrichment($ip) : [
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
        ':clicked_at' => gmdate('c'),
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

function getClickCountsByToken(PDO $pdo, bool $knownOnly = false): array
{
    $sql = "
        SELECT
            c.token,
            COUNT(*) AS hit_count,
            MAX(c.clicked_at) AS last_seen,
            MAX(CASE WHEN c.link_id IS NOT NULL THEN 1 ELSE 0 END) AS is_known
        FROM clicks c
    ";

    if ($knownOnly) {
        $sql .= " WHERE c.link_id IS NOT NULL ";
    }

    $sql .= "
        GROUP BY c.token
        ORDER BY hit_count DESC, last_seen DESC
    ";

    $stmt = $pdo->query($sql);
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
    bool $knownOnly = false
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

    $sql .= " ORDER BY c.id DESC LIMIT :limit ";

    $stmt = $pdo->prepare($sql);

    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value, PDO::PARAM_STR);
    }

    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

function getThreatFeedIps(PDO $pdo): array
{
    $enabled = getSetting($pdo, 'threat_feed_enabled', '1');
    if ($enabled !== '1') {
        return [];
    }

    $windowHours = max(1, (int) getSetting($pdo, 'threat_feed_window_hours', '168'));
    $minConfidence = strtolower((string) getSetting($pdo, 'threat_feed_min_confidence', 'suspicious'));

    $allowedLabels = match ($minConfidence) {
        'bot' => ['bot'],
        'likely-human' => ['likely-human', 'suspicious', 'bot'],
        'human' => ['human', 'likely-human', 'suspicious', 'bot'],
        default => ['suspicious', 'bot'],
    };

    $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));

    $sql = "
        SELECT DISTINCT ip
        FROM clicks
        WHERE ip IS NOT NULL
          AND ip <> ''
          AND event_type = 'click'
          AND clicked_at >= datetime('now', ?)
          AND confidence_label IS NOT NULL
          AND confidence_label <> ''
          AND confidence_score IS NOT NULL
          AND confidence_label IN ($placeholders)
        ORDER BY ip ASC
    ";

    $params = array_merge(
        ['-' . $windowHours . ' hours'],
        $allowedLabels
    );

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $ips = [];
    foreach ($stmt->fetchAll() as $row) {
        $ip = trim((string) ($row['ip'] ?? ''));
        if ($ip === '') {
            continue;
        }
        $ips[] = $ip;
    }

    return array_values(array_unique($ips));
}
