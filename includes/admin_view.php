<?php
declare(strict_types=1);

/**
 * Maps raw confidence_reason signal names to human-readable labels.
 * Returns the friendly label, or null if the signal is unknown (caller
 * should fall back to displaying the raw name).
 */
function signalLabel(string $signal): ?string
{
    if (str_starts_with($signal, 'path:'))             return 'High-risk path (' . substr($signal, 5) . ')';
    if (str_starts_with($signal, 'country_penalty:'))  return 'Country penalty (' . substr($signal, 16) . ')';
    if (str_starts_with($signal, 'asn_rule:'))         return 'ASN rule match (' . substr($signal, 9) . ')';
    if (str_starts_with($signal, 'ip_override:'))      return 'IP override (' . substr($signal, 12) . ')';
    if (str_starts_with($signal, 'ua:'))               return 'User-agent signal (' . substr($signal, 3) . ')';

    static $map = [
        'get_request'              => 'GET request',
        'browser_ua'               => 'Browser-like user-agent',
        'sec_fetch_navigate'       => 'Sec-Fetch navigation headers present',
        'accept_language_present'  => 'Accept-Language header present',
        'referer_present'          => 'Referer header present',
        'accept_missing'           => 'Missing Accept header',
        'accept_language_missing'  => 'Missing Accept-Language header',
        'accept_encoding_missing'  => 'Missing Accept-Encoding header',
        'accept_wildcard'          => 'Accept: */* (no content preference)',
        'sec_fetch_missing'        => 'Missing Sec-Fetch headers',
        'sec_fetch_incomplete'     => 'Incomplete Sec-Fetch headers',
        'sec_fetch_inconsistent'   => 'Contradictory Sec-Fetch headers',
        'sec_ch_ua_missing'        => 'Missing Sec-CH-UA (Client Hints)',
        'browser_ua_unsupported'   => 'Browser UA with no supporting headers (likely spoofed)',
        'known_automation_ua'      => 'Known automation user-agent',
        'post_request'             => 'POST request',
        'no_referer'               => 'No Referer header',
        'host_raw_ip'              => 'Raw IP address in Host header',
        'bot_signal'               => 'Bot-like request pattern',
        'exploit_like_query'       => 'Exploit-like query string',
        'hosting_provider_ip'      => 'Hosting / datacenter IP range',
        'hosting_provider'         => 'Hosting / datacenter IP range',
        'backbone_network'         => 'Backbone / transit network',
        'burst_activity'           => 'Burst activity (many requests in short window)',
        'rapid_repeat'             => 'Rapid repeat requests',
        'fast_repeat'              => 'Fast repeat requests',
        'multi_token_scan'         => 'Multi-token scan (hit multiple paths)',
        'self_referer_root'        => 'Request from own domain (self-referrer)',
        'self_referer'             => 'Request from own domain (self-referrer)',
        'admin_path_without_access'              => 'Admin access without CF',
        'admin_path_invalid_cf_access_token'     => 'Invalid CF Access token',
        'admin_path_cf_access_audience_mismatch' => 'CF Access audience mismatch',
    ];

    return $map[$signal] ?? null;
}

/**
 * Extracts the subdomain prefix from a host value given the configured base URL.
 * e.g. host='vpn.example.com', baseUrl='https://example.com' → 'vpn'
 * Returns empty string if host matches the base domain or cannot be parsed.
 */
function extractSubdomain(string $host, string $baseUrl): string
{
    if ($host === '' || $baseUrl === '') {
        return '';
    }

    // Strip scheme and trailing slash from base URL to get bare domain.
    $baseDomain = strtolower(preg_replace('#^https?://#', '', rtrim($baseUrl, '/')));

    // Strip port from host if present.
    $host = strtolower(preg_replace('/:\d+$/', '', $host));

    // If host matches base domain exactly, no subdomain.
    if ($host === $baseDomain) {
        return '';
    }

    // If host ends with .baseDomain, the prefix is the subdomain.
    $suffix = '.' . $baseDomain;
    if (str_ends_with($host, $suffix)) {
        return substr($host, 0, strlen($host) - strlen($suffix));
    }

    // Host doesn't relate to base domain — show full host.
    return $host;
}

/**
 * Renders a confidence_reason string as compact signal tags.
 * Friendly label is shown; raw signal name appears as a tooltip on hover.
 */
function renderSignalReasons(string $reasons): string
{
    if ($reasons === '') return '<span class="muted">—</span>';

    $signals = array_map('trim', explode(',', $reasons));
    $parts   = [];

    foreach ($signals as $signal) {
        if ($signal === '') continue;
        $label = signalLabel($signal);

        if (in_array($signal, ['get_request', 'browser_ua', 'sec_fetch_navigate', 'accept_language_present', 'referer_present'], true)) {
            $class = 'signal-tag signal-tag--positive';
        } elseif (in_array($signal, ['burst_activity', 'rapid_repeat', 'fast_repeat', 'multi_token_scan'], true)) {
            $class = 'signal-tag signal-tag--behavioral';
        } elseif (str_starts_with($signal, 'path:') || str_starts_with($signal, 'country_penalty:') || str_starts_with($signal, 'asn_rule:') || str_starts_with($signal, 'ip_override:')) {
            $class = 'signal-tag signal-tag--rule';
        } else {
            $class = 'signal-tag signal-tag--negative';
        }

        $display = $label ?? $signal;
        $title   = $label !== null ? h($signal) : '';

        $parts[] = '<span class="' . $class . '"'
            . ($title !== '' ? ' title="' . $title . '"' : '')
            . '>' . h($display) . '</span>';
    }

    return '<div class="signal-tag-list">' . implode('', $parts) . '</div>';
}


function normalizeTokenPath(string $token): string
{
    $token = trim($token);
    if ($token === '') {
        return '';
    }
    return '/' . ltrim($token, '/');
}

function resolvePublicBaseUrl(string $baseUrl = ''): string
{
    $configuredBaseUrl = '';

    if (defined('BASE_URL') && trim((string) BASE_URL) !== '') {
        $configuredBaseUrl = rtrim((string) BASE_URL, '/');
    } else {
        $envBaseUrl = trim((string) getenv('BASE_URL'));
        if ($envBaseUrl !== '') {
            $configuredBaseUrl = rtrim($envBaseUrl, '/');
        }
    }

    $candidate = trim($baseUrl);
    if ($candidate !== '') {
        $candidate = rtrim($candidate, '/');
    }

    $candidateHost = $candidate !== '' ? (string) parse_url($candidate, PHP_URL_HOST) : '';

    if ($configuredBaseUrl !== '') {
        if ($candidateHost !== '' && preg_match('/^admin\./i', $candidateHost)) {
            return $configuredBaseUrl;
        }
        return $configuredBaseUrl;
    }

    if ($candidate !== '') {
        return $candidate;
    }

    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    if ($host !== '') {
        if (preg_match('/^admin\.(.+)$/i', $host, $m)) {
            $host = $m[1];
        }
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return $scheme . '://' . $host;
    }

    return '';
}

function buildTokenPublicUrl(string $baseUrl, string $token): string
{
    $path = normalizeTokenPath($token);
    $effectiveBaseUrl = resolvePublicBaseUrl($baseUrl);
    if ($effectiveBaseUrl === '' || $path === '') {
        return '';
    }
    return $effectiveBaseUrl . $path;
}

function buildPixelPublicUrl(string $baseUrl, string $token): string
{
    $path = trim($token, '/');
    $effectiveBaseUrl = resolvePublicBaseUrl($baseUrl);
    if ($effectiveBaseUrl === '' || $path === '') {
        return '';
    }
    return $effectiveBaseUrl . '/pixel/' . $path . '.gif';
}

function renderSnippetBox(string $title, string $content, string $copyLabel = 'Copy'): string
{
    return '<div class="snippet-box">'
        . '<div class="snippet-header"><strong>' . h($title) . '</strong>'
        . '<button type="button" class="copy-button" data-copy="' . h($content) . '">' . h($copyLabel) . '</button></div>'
        . '<pre class="snippet-code">' . h($content) . '</pre>'
        . '</div>';
}

function renderActionMenuTrigger(string $ariaLabel): string
{
    return '<button type="button" class="action-menu-trigger" aria-expanded="false" aria-haspopup="true" aria-label="'
        . h($ariaLabel)
        . '">⋯</button>';
}

function reportCountryCentroids(): array
{
    return [
        'US' => [39.8, -98.6], 'CA' => [56.1, -106.3], 'MX' => [23.6, -102.5], 'BR' => [-10.8, -52.9], 'AR' => [-34.0, -64.0], 'CL' => [-30.0, -71.0], 'CO' => [4.5, -74.0], 'PE' => [-9.1, -75.0],
        'GB' => [55.3, -3.4], 'IE' => [53.4, -8.0], 'FR' => [46.2, 2.2], 'DE' => [51.2, 10.4], 'ES' => [40.3, -3.7], 'PT' => [39.5, -8.0], 'IT' => [41.9, 12.5], 'NL' => [52.1, 5.3], 'BE' => [50.5, 4.5],
        'CH' => [46.8, 8.2], 'AT' => [47.6, 14.1], 'SE' => [60.1, 18.6], 'NO' => [60.5, 8.4], 'FI' => [64.5, 26.0], 'DK' => [56.0, 9.5], 'PL' => [52.1, 19.1], 'CZ' => [49.8, 15.5], 'RO' => [45.9, 24.9], 'UA' => [49.0, 31.4], 'RU' => [61.5, 105.3], 'TR' => [39.1, 35.2],
        'SA' => [23.9, 45.1], 'AE' => [24.3, 54.3], 'IL' => [31.4, 35.0], 'IR' => [32.4, 53.7], 'IQ' => [33.2, 43.7], 'EG' => [26.8, 30.8], 'ZA' => [-30.6, 22.9], 'NG' => [9.1, 8.7], 'KE' => [0.0, 37.9], 'MA' => [31.8, -7.1], 'DZ' => [28.0, 1.6],
        'IN' => [22.6, 79.0], 'PK' => [30.3, 69.3], 'BD' => [23.7, 90.4], 'CN' => [35.9, 104.2], 'JP' => [36.2, 138.3], 'KR' => [36.5, 127.9], 'TW' => [23.7, 121.0], 'HK' => [22.3, 114.2], 'SG' => [1.35, 103.8], 'ID' => [-2.5, 118.0], 'MY' => [4.2, 102.0], 'TH' => [15.9, 100.9], 'VN' => [14.1, 108.3], 'PH' => [12.9, 121.8],
        'AU' => [-25.3, 133.8], 'NZ' => [-41.3, 174.8],
    ];
}

function renderReportCountryHeatmapSvg(array $rows, string $metric = 'total_events'): string
{
    $metric = $metric === 'risky_hits' ? 'risky_hits' : 'total_events';
    $width = 920.0;
    $height = 420.0;
    $centroids = reportCountryCentroids();
    $maxValue = 1.0;
    foreach ($rows as $row) {
        $maxValue = max($maxValue, (float) ($row[$metric] ?? 0));
    }

    $svg = [];
    $svg[] = '<svg viewBox="0 0 920 420" role="img" aria-label="Country heatmap overlay">';
    $svg[] = '<rect x="0" y="0" width="920" height="420" fill="var(--surface-alt)"></rect>';
    $svg[] = '<g class="report-map-graticule">';
    for ($lon = -150; $lon <= 150; $lon += 30) {
        $x = (($lon + 180) / 360) * $width;
        $svg[] = '<line x1="' . number_format($x, 2, '.', '') . '" y1="0" x2="' . number_format($x, 2, '.', '') . '" y2="420"></line>';
    }
    for ($lat = -60; $lat <= 60; $lat += 30) {
        $y = ((90 - $lat) / 180) * $height;
        $svg[] = '<line x1="0" y1="' . number_format($y, 2, '.', '') . '" x2="920" y2="' . number_format($y, 2, '.', '') . '"></line>';
    }
    $svg[] = '</g>';
    $svg[] = '<g class="report-map-land">'
        . '<ellipse cx="185" cy="168" rx="125" ry="88"></ellipse>'
        . '<ellipse cx="285" cy="305" rx="72" ry="104"></ellipse>'
        . '<ellipse cx="470" cy="150" rx="118" ry="74"></ellipse>'
        . '<ellipse cx="510" cy="258" rx="92" ry="112"></ellipse>'
        . '<ellipse cx="706" cy="176" rx="178" ry="96"></ellipse>'
        . '<ellipse cx="804" cy="328" rx="72" ry="40"></ellipse>'
        . '</g>';
    $svg[] = '<g class="report-map-points">';
    foreach ($rows as $row) {
        $code = strtoupper((string) ($row['country_code'] ?? ''));
        if (!isset($centroids[$code])) {
            continue;
        }
        [$lat, $lon] = $centroids[$code];
        $value = max(0.0, (float) ($row[$metric] ?? 0));
        $intensity = max(0.15, $value / $maxValue);
        $radius = 4.0 + sqrt($value) * 1.8;
        $x = (($lon + 180) / 360) * $width;
        $y = ((90 - $lat) / 180) * $height;
        $alpha = min(0.88, 0.2 + $intensity * 0.68);
        $label = $metric === 'risky_hits' ? 'risky hits' : 'events';

        $svg[] = '<g>'
            . '<title>' . h($code . ' - ' . (string) ((int) $value) . ' ' . $label) . '</title>'
            . '<circle cx="' . number_format($x, 2, '.', '') . '" cy="' . number_format($y, 2, '.', '') . '" r="' . number_format($radius, 2, '.', '') . '" fill="rgba(248, 113, 113, ' . number_format($alpha, 2, '.', '') . ')" stroke="rgba(248, 113, 113, 0.92)" stroke-width="1.2"></circle>'
            . '</g>';
    }
    $svg[] = '</g>';
    $svg[] = '</svg>';
    return implode('', $svg);
}

function buildTokenDeploymentSnippets(string $baseUrl, array $link): array
{
    $token = (string) ($link['token'] ?? '');
    $description = trim((string) ($link['description'] ?? 'Tracked link'));
    $href = buildTokenPublicUrl($baseUrl, $token);
    $pixel = buildPixelPublicUrl($baseUrl, $token);
    $safeText = $description !== '' ? $description : 'Tracked link';

    return [
        'Tracked URL' => $href,
        'Markdown Link' => '[' . $safeText . '](' . $href . ')',
        'HTML Link' => '<a href="' . $href . '">' . $safeText . '</a>',
        'Tracking Pixel HTML' => '<img src="' . $pixel . '" alt="" width="1" height="1" style="display:none;" />',
        'Email-safe Button HTML' => '<a href="' . $href . '" style="display:inline-block;padding:10px 16px;background:#4f78f1;color:#ffffff;text-decoration:none;border-radius:6px;">' . $safeText . '</a>',
    ];
}

function renderAdminPage(
    string $appName,
    string $baseUrl,
    string $defaultRedirectUrl,
    string $unknownPathBehavior,
    bool $pixelEnabled,
    bool $noiseFilterEnabled,
    string $tokenFilter,
    string $ipFilter,
    string $visitorFilter,
    bool $knownOnly,
    array $clicks,
    int $totalCount,
    int $totalPages,
    int $currentPage,
    int $pageSize,
    array $links,
    array $tokenCounts,
    array $skipPatterns,
    array $asnRules,
    string $refreshUrl,
    ?array $ipSummary = null,
    string $hostFilter = '',
    array $campaignStats = [],
    array $campaigns = [],
    ?array $selectedCampaign = null,
): void {
    $pdo       = db();
    $csrfToken = generateCsrfToken();
    $isDemo    = defined('DEMO_MODE') && DEMO_MODE;
    $flash     = $_SESSION['admin_flash'] ?? null;
    if (isset($_SESSION['admin_flash'])) {
        unset($_SESSION['admin_flash']);
    }

    $autoRefreshSecs  = max(0, (int) getSetting($pdo, 'auto_refresh_secs', '0'));
    $webhookUrl       = (string) getSetting($pdo, 'webhook_url', '');
    $webhookTemplate  = (string) getSetting($pdo, 'webhook_template', '');
    $tokenWebhookUrl      = (string) getSetting($pdo, 'token_webhook_url', '');
    $tokenWebhookTemplate = (string) getSetting($pdo, 'token_webhook_template', '');
    $pageSizeSetting  = (string) getSetting($pdo, 'page_size', '50');
    $exportMinConf    = (string) getSetting($pdo, 'export_min_confidence', 'suspicious');
    $exportWinHours   = (string) getSetting($pdo, 'export_window_hours', '168');
    $exportMinScore   = (string) getSetting($pdo, 'export_min_score', '0');
    $wildcardMode     = getSetting($pdo, 'wildcard_mode', '0') === '1';

    $dateFrom       = trim((string) ($_GET['date_from'] ?? ''));
    $dateTo         = trim((string) ($_GET['date_to']   ?? ''));
    $campaignFilter = max(0, (int) ($_GET['campaign'] ?? '0'));
    $showAll        = isset($_GET['show_all'])        && $_GET['show_all']        === '1';
    $hideBehavioral = isset($_GET['hide_behavioral']) && $_GET['hide_behavioral'] === '1';
    $hostFilter     = trim((string) ($_GET['host']    ?? ''));
    $hideSubdomains = isset($_GET['hide_subdomains']) && $_GET['hide_subdomains'] === '1';
    $showHidden     = isset($_GET['show_hidden'])     && $_GET['show_hidden']     === '1';
    $showTopTokens  = isset($_GET['show_top_tokens']) && $_GET['show_top_tokens'] === '1';

    $activeTab  = trim((string) ($_GET['tab'] ?? ''));
    $editLinkId = (int) ($_GET['edit_link_id'] ?? 0);

    $editLink = null;
    if ($editLinkId > 0) {
        foreach ($links as $candidateLink) {
            if ((int) $candidateLink['id'] === $editLinkId) {
                $editLink = $candidateLink;
                break;
            }
        }
    }

    $linksByCampaign = [];
    foreach ($links as $campaignLink) {
        $cid = (int) ($campaignLink['campaign_id'] ?? 0);
        if ($cid > 0) {
            $linksByCampaign[$cid][] = $campaignLink;
        }
    }


    $editAsnRuleId = (int) ($_GET['edit_asn_rule_id'] ?? 0);
    $editAsnRule = null;
    if ($editAsnRuleId > 0) {
        foreach ($asnRules as $candidateRule) {
            if ((int) $candidateRule['id'] === $editAsnRuleId) {
                $editAsnRule = $candidateRule;
                break;
            }
        }
    }

    $hasActiveFilter = (
        $tokenFilter !== ''
        || $ipFilter !== ''
        || $visitorFilter !== ''
        || $campaignFilter > 0
        || $hostFilter !== ''
        || $knownOnly
        || $showAll
        || $dateFrom !== ''
        || $dateTo !== ''
    );
    $exportUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . '/export/json';

    $secondaryFilterCount = (int) ($visitorFilter !== '')
        + (int) ($campaignFilter > 0)
        + (int) ($hostFilter !== '')
        + (int) ($dateFrom !== '')
        + (int) ($dateTo !== '')
        + (int) $knownOnly
        + (int) $showAll
        + (int) $showHidden
        + (int) $showTopTokens;

    $filterDrawerOpen = $secondaryFilterCount > 0;

    $threatFeedEnabled = getSetting($pdo, 'threat_feed_enabled', '1') === '1';
    $threatFeedWindowHours = (string) (getSetting($pdo, 'threat_feed_window_hours', '168') ?? '168');
    $threatFeedMinConfidence = (string) (getSetting($pdo, 'threat_feed_min_confidence', 'suspicious') ?? 'suspicious');
    $threatFeedMinHits = (string) (getSetting($pdo, 'threat_feed_min_hits', '1') ?? '1');
    $dataRetentionDays = (string) (getSetting($pdo, 'data_retention_days', '0') ?? '0');
    $authRetentionDays = (string) (getSetting($pdo, 'auth_retention_days', '30') ?? '30');
    $enrichmentRetentionDays = (string) (getSetting($pdo, 'enrichment_retention_days', '90') ?? '90');
    $archiveBeforeCleanup = getSetting($pdo, 'archive_before_cleanup', '0') === '1';
    $sqliteMaintenanceEnabled = getSetting($pdo, 'sqlite_maintenance_enabled', '1') === '1';
    $sqliteMaintenanceIntervalMins = (string) (getSetting($pdo, 'sqlite_maintenance_interval_mins', '360') ?? '360');
    $sqliteVacuumEnabled = getSetting($pdo, 'sqlite_vacuum_enabled', '0') === '1';
    $sqliteVacuumIntervalHours = (string) (getSetting($pdo, 'sqlite_vacuum_min_interval_hours', '24') ?? '24');
    $sqliteMaintenanceLastRunTs = max(0, (int) getSetting($pdo, 'sqlite_maintenance_last_run_ts', '0'));
    $sqliteVacuumLastRunTs = max(0, (int) getSetting($pdo, 'sqlite_vacuum_last_run_ts', '0'));
    $sqliteMaintenanceLastRun = $sqliteMaintenanceLastRunTs > 0 ? date('Y-m-d H:i:s T', $sqliteMaintenanceLastRunTs) : 'Never';
    $sqliteVacuumLastRun = $sqliteVacuumLastRunTs > 0 ? date('Y-m-d H:i:s T', $sqliteVacuumLastRunTs) : 'Never';
    $adaptiveDeceptionEnabled = getSetting($pdo, 'adaptive_deception_enabled', '0') === '1';
    $staleTokenDays = max(0, (int) getSetting($pdo, 'stale_token_days', '30'));
    $dbStats = getSqliteDatabaseStats($pdo);
    $reportWindowHours = max(24, min(24 * 90, (int) ($_GET['report_window_hours'] ?? 168)));
    $reportKpis = getExecutiveReportKpis($pdo, $reportWindowHours);
    $reportCountries = getExecutiveCountryDensity($pdo, $reportWindowHours, 20);
    $reportTopTokens = getExecutiveTopTokens($pdo, $reportWindowHours, 10);

    $behavioralWindowHours = max(1, (int) getSetting($pdo, 'behavioral_window_hours', '24'));
    $behavioralMaxRows     = max(1, (int) getSetting($pdo, 'behavioral_max_rows', '25'));
    $behavioralHidden      = getSetting($pdo, 'behavioral_hidden', '0') === '1';
    $subdomainsHidden      = getSetting($pdo, 'subdomains_hidden', '0') === '1';

    $ipOverrides       = getIpOverrides($pdo);
    $behavioralFlags   = getBehaviorallyFlaggedIps($pdo, $behavioralWindowHours, $behavioralMaxRows);
    $ipOverrideMap     = getActiveIpOverrideMap($pdo);
    $countryRules      = getCountryRules($pdo);

    $subdomainSummary  = $wildcardMode
        ? getSubdomainSummary($pdo, $baseUrl, $dateFrom !== '' ? $dateFrom : null, $dateTo !== '' ? $dateTo : null)
        : [];

    $editOverrideId = (int) ($_GET['edit_override_id'] ?? 0);
    $editOverride   = null;
    if ($editOverrideId > 0) {
        foreach ($ipOverrides as $candidate) {
            if ((int) $candidate['id'] === $editOverrideId) {
                $editOverride = $candidate;
                break;
            }
        }
    }

    $editCountryId   = (int) ($_GET['edit_country_id'] ?? 0);
    $editCountryRule = null;
    if ($editCountryId > 0) {
        foreach ($countryRules as $candidate) {
            if ((int) $candidate['id'] === $editCountryId) {
                $editCountryRule = $candidate;
                break;
            }
        }
    }

    $buildAdminUrl = function (array $overrides = []) use ($tokenFilter, $ipFilter, $visitorFilter, $campaignFilter, $knownOnly, $dateFrom, $dateTo, $showAll, $hideBehavioral, $hostFilter, $hideSubdomains, $showHidden, $showTopTokens, $activeTab): string {
        $params = [];

        if ($tokenFilter !== '') {
            $params['token'] = $tokenFilter;
        }
        if ($ipFilter !== '') {
            $params['ip'] = $ipFilter;
        }
        if ($visitorFilter !== '') {
            $params['visitor'] = $visitorFilter;
        }
        if ($campaignFilter > 0) {
            $params['campaign'] = (string) $campaignFilter;
        }
        if ($knownOnly) {
            $params['known'] = '1';
        }
        if ($dateFrom !== '') {
            $params['date_from'] = $dateFrom;
        }
        if ($dateTo !== '') {
            $params['date_to'] = $dateTo;
        }
        if ($showAll) {
            $params['show_all'] = '1';
        }
        if ($hideBehavioral) {
            $params['hide_behavioral'] = '1';
        }
        if ($hideSubdomains) {
            $params['hide_subdomains'] = '1';
        }
        if ($showHidden) {
            $params['show_hidden'] = '1';
        }
        if ($showTopTokens) {
            $params['show_top_tokens'] = '1';
        }
        if ($hostFilter !== '') {
            $params['host'] = $hostFilter;
        }

        if ($activeTab !== '') {
            $params['tab'] = $activeTab;
        }

        foreach ($overrides as $key => $value) {
            if ($value === null || $value === '') {
                unset($params[$key]);
            } else {
                $params[$key] = $value;
            }
        }

        return '/admin' . (!empty($params) ? '?' . http_build_query($params) : '');
    };

    $buildDashboardUrl = function (array $overrides = []) use ($buildAdminUrl): string {
        return $buildAdminUrl(array_merge(['tab' => 'dashboard'], $overrides));
    };

    $buildReportsUrl = function (array $overrides = []) use ($buildAdminUrl): string {
        return $buildAdminUrl(array_merge(['tab' => 'reports'], $overrides));
    };

    $buildExportUrl = function () use ($tokenFilter, $ipFilter, $visitorFilter, $knownOnly, $dateFrom, $dateTo, $showAll, $activeTab): string {
        $params = [];

        if ($tokenFilter !== '') {
            $params['token'] = $tokenFilter;
        }
        if ($ipFilter !== '') {
            $params['ip'] = $ipFilter;
        }
        if ($visitorFilter !== '') {
            $params['visitor'] = $visitorFilter;
        }
        if ($campaignFilter > 0) {
            $params['campaign'] = (string) $campaignFilter;
        }
        if ($knownOnly) {
            $params['known'] = '1';
        }
        if ($dateFrom !== '') {
            $params['date_from'] = $dateFrom;
        }
        if ($dateTo !== '') {
            $params['date_to'] = $dateTo;
        }

        return '/export/json' . (!empty($params) ? '?' . http_build_query($params) : '');
    };

    // Use the per-request CSP nonce generated in index.php.
    // The CSP header itself is sent there so it covers the full response
    // including demo-banner.php which renders before this function runs.
    $cspNonce = $GLOBALS['cspNonce'] ?? base64_encode(random_bytes(16));

    $threatFeedUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . '/feed/ips.txt';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title><?= h($appName) ?></title>
	<link rel="stylesheet" href="/admin.css?v=<?= (string) @filemtime(__DIR__ . '/../public/admin.css') ?>">
        <link rel="icon" type="image/png" href="/signaltrace_transparent.png">
        <link rel="apple-touch-icon" href="/signaltrace_transparent.png">
    </head>
    <body>
        <header class="page-header">
            <div class="page-header-left">
                <a href="/admin" class="header-home-link">
                    <img src="/signaltrace_transparent.png" alt="SignalTrace" class="header-logo">
                    <h1><?= h($appName) ?></h1>
                </a>
                <span class="header-tag">Admin</span>
            </div>
            <button type="button" class="theme-toggle" id="theme-toggle" title="Toggle theme">
                <span class="theme-icon" id="theme-icon">☀️</span>
                <span id="theme-label">Light</span>
            </button>
        </header>
        <div class="page-body">
        <?php if (is_array($flash) && !empty($flash['message'])): ?>
            <div class="admin-flash admin-flash--<?= h((string) ($flash['type'] ?? 'success')) ?>">
                <?= h((string) $flash['message']) ?>
            </div>
        <?php endif; ?>

        <div class="tabs">
            <div class="tab" id="tab-dashboard" data-tab="dashboard">Dashboard</div>
            <div class="tab" id="tab-reports" data-tab="reports">Reports</div>
            <div class="tab" id="tab-links" data-tab="links">Tokens</div>
	    <div class="tab" id="tab-skip" data-tab="skip">Skip Patterns</div>
            <div class="tab" id="tab-asn" data-tab="asn">ASN Rules</div>
            <div class="tab" id="tab-countries" data-tab="countries">Country Rules</div>
            <div class="tab" id="tab-overrides" data-tab="overrides">IP Overrides</div>
            <div class="tab" id="tab-settings" data-tab="settings">Settings</div>
        </div>

        <div class="tab-content" id="content-dashboard">
            <form method="get" action="/admin" class="inline-form">
                <input type="hidden" name="tab" value="dashboard">
                <?php if ($hideBehavioral): ?><input type="hidden" name="hide_behavioral" value="1"><?php endif; ?>
                <?php if ($hideSubdomains): ?><input type="hidden" name="hide_subdomains" value="1"><?php endif; ?>
		<h2>Filter activity</h2>
		<div class="filter-container">
                    <div class="filter-bar-primary">
	                <input type="text" name="token" value="<?= h($tokenFilter) ?>" placeholder="Token or path" autocomplete="off">
	                <input type="text" name="ip" value="<?= h($ipFilter) ?>" placeholder="IP address" autocomplete="off">
                        <div class="filter-bar-primary-actions filter-actions">
                    <button type="submit">Apply filters</button>
                    <a class="button-link" href="<?= h($buildDashboardUrl(['token' => null, 'ip' => null, 'visitor' => null, 'campaign' => null, 'host' => null, 'known' => null, 'show_top_tokens' => null, 'show_all' => null, 'show_hidden' => null, 'date_from' => null, 'date_to' => null, 'page' => null])) ?>">Clear filters</a>
                    <a class="button-link" href="<?= h($refreshUrl) ?>">Refresh</a>
                    <?php
                    $exportParams = [];
                    if ($tokenFilter   !== '') $exportParams['token']    = $tokenFilter;
                    if ($ipFilter      !== '') $exportParams['ip']       = $ipFilter;
                    if ($visitorFilter !== '') $exportParams['visitor']  = $visitorFilter;
                    if ($campaignFilter > 0)   $exportParams['campaign'] = (string) $campaignFilter;
                    if ($hostFilter    !== '') $exportParams['host']     = $hostFilter;
                    if ($knownOnly)            $exportParams['known']    = '1';
                    if ($dateFrom      !== '') $exportParams['date_from'] = $dateFrom;
                    if ($dateTo        !== '') $exportParams['date_to']   = $dateTo;
                    $exportHref = '/export/json' . (!empty($exportParams) ? '?' . http_build_query($exportParams) : '');
                    ?>
                    <a class="button-link" href="<?= h($exportHref) ?>" target="_blank" rel="noopener">Export JSON</a>
                    <a class="button-link" href="<?= h(str_replace('/export/json', '/export/csv', $exportHref)) ?>" target="_blank" rel="noopener">Export CSV</a>
                        </div>
                    </div>

                    <div class="filter-quick-row">
                        <div class="filter-quick-dates">
                            <span class="small">Quick range:</span>
                            <a class="button-link btn-small" href="<?= h($buildDashboardUrl(['date_from' => date('Y-m-d', strtotime('-1 day')), 'date_to' => date('Y-m-d'), 'page' => null])) ?>">24h</a>
                            <a class="button-link btn-small" href="<?= h($buildDashboardUrl(['date_from' => date('Y-m-d', strtotime('-7 days')), 'date_to' => date('Y-m-d'), 'page' => null])) ?>">7d</a>
                            <a class="button-link btn-small" href="<?= h($buildDashboardUrl(['date_from' => date('Y-m-d', strtotime('-30 days')), 'date_to' => date('Y-m-d'), 'page' => null])) ?>">30d</a>
                        </div>
                        <div class="filter-presets">
                            <select id="filter-preset-select" style="margin-bottom:0;">
                                <option value="">Saved presets</option>
                            </select>
                            <button type="button" class="btn-small" id="filter-preset-save">Save current</button>
                            <button type="button" class="btn-small" id="filter-preset-delete">Delete</button>
                            <button type="button" class="btn-small" id="density-toggle">Density: comfy</button>
                        </div>
                    </div>

                    <div class="filter-quick-row" style="margin-top:4px;">
                        <div class="filter-presets">
                            <span class="small">Triage views:</span>
                            <a class="button-link btn-small" href="<?= h($buildDashboardUrl(['known' => null, 'show_all' => '1', 'date_from' => date('Y-m-d', strtotime('-1 day')), 'date_to' => date('Y-m-d'), 'page' => null])) ?>">Suspicious now</a>
                            <a class="button-link btn-small" href="<?= h($buildDashboardUrl(['known' => null, 'token' => null, 'show_all' => '1', 'page' => null])) ?>">Unknown paths</a>
                            <a class="button-link btn-small" href="<?= h($buildAdminUrl(['tab' => 'links'])) ?>">Failing links</a>
                        </div>
                    </div>


                    <details class="filter-more" <?= $filterDrawerOpen ? 'open' : '' ?>>
                        <summary class="filter-more-summary">
                            More filters
                            <?php if ($secondaryFilterCount > 0): ?>
                                <span class="filter-more-badge"><?= (int) $secondaryFilterCount ?></span>
                            <?php endif; ?>
                        </summary>
                        <div class="filter-more-body">
                            <div class="filter-inputs">
                                <input type="text" name="visitor" value="<?= h($visitorFilter) ?>" placeholder="Visitor hash" autocomplete="off">
                                <select name="campaign">
                                    <option value="">All campaigns</option>
                                    <?php foreach ($campaigns as $campaignOption): ?>
                                    <option value="<?= (int) $campaignOption['id'] ?>" <?= $campaignFilter === (int) $campaignOption['id'] ? 'selected' : '' ?>>
                                        <?= h((string) $campaignOption['name']) ?>
                                    </option>
                                    <?php endforeach; ?>
                                </select>
                                <?php if ($wildcardMode): ?>
                                <input type="text" name="host" value="<?= h($hostFilter) ?>" placeholder="Subdomain or host" class="hide-mobile" autocomplete="off">
                                <?php endif; ?>
                                <label class="date-filter-label">
                                    <span class="date-filter-hint">From</span>
                                    <input type="date" name="date_from" value="<?= h($dateFrom) ?>">
                                </label>
                                <label class="date-filter-label">
                                    <span class="date-filter-hint">To</span>
                                    <input type="date" name="date_to" value="<?= h($dateTo) ?>">
                                </label>
                            </div>
                            <div class="filter-toggles">
                                <label>
                                    <input type="checkbox" name="known" value="1" <?= $knownOnly ? 'checked' : '' ?>>
                                    Known tokens only
                                </label>
                                <label>
                                    <input type="checkbox" name="show_top_tokens" value="1" <?= $showTopTokens ? 'checked' : '' ?>>
                                    Show top tokens
                                </label>
                                <label>
                                    <input type="checkbox" name="show_all" value="1" <?= $showAll ? 'checked' : '' ?>>
                                    Show all scores
                                </label>
                                <label>
                                    <input type="checkbox" name="show_hidden" value="1" <?= $showHidden ? 'checked' : '' ?>>
                                    Show hidden IPs
                                </label>
                            </div>
                        </div>
                    </details>
		</div>
            </form>

            <?php if ($hasActiveFilter): ?>
                <div class="active-filters">
                    <?php if ($tokenFilter !== ''): ?>
                        <span class="filter-pill">
                            token: <?= h($tokenFilter) ?>
                            <a href="<?= h($buildDashboardUrl(['token' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($ipFilter !== ''): ?>
                        <span class="filter-pill">
                            ip: <?= h($ipFilter) ?>
                            <a href="<?= h($buildDashboardUrl(['ip' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($visitorFilter !== ''): ?>
                        <span class="filter-pill">
                            visitor: <?= h($visitorFilter) ?>
                            <a href="<?= h($buildDashboardUrl(['visitor' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($campaignFilter > 0): ?>
                        <span class="filter-pill">
                            campaign: <?= h((string) ($selectedCampaign['name'] ?? ('#' . $campaignFilter))) ?>
                            <a href="<?= h($buildDashboardUrl(['campaign' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($hostFilter !== ''): ?>
                        <span class="filter-pill">
                            host: <?= h($hostFilter) ?>
                            <a href="<?= h($buildDashboardUrl(['host' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($dateFrom !== ''): ?>
                        <span class="filter-pill">
                            from: <?= h($dateFrom) ?>
                            <a href="<?= h($buildDashboardUrl(['date_from' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($dateTo !== ''): ?>
                        <span class="filter-pill">
                            to: <?= h($dateTo) ?>
                            <a href="<?= h($buildDashboardUrl(['date_to' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($knownOnly): ?>
                        <span class="filter-pill">
                            known only
                            <a href="<?= h($buildDashboardUrl(['known' => null])) ?>">×</a>
                        </span>
		    <?php endif; ?>

		    <?php if ($showAll): ?>
			<span class="filter-pill">
		            show all
		            <a href="<?= h($buildDashboardUrl(['show_all' => null])) ?>">×</a>
		       </span>
		    <?php endif; ?>

                    <?php if ($showHidden): ?>
                        <span class="filter-pill">
                            hidden IPs
                            <a href="<?= h($buildDashboardUrl(['show_hidden' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($showTopTokens): ?>
                        <span class="filter-pill">
                            top tokens
                            <a href="<?= h($buildDashboardUrl(['show_top_tokens' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>



<?php if ($tokenFilter !== '' && !$knownOnly && $ipFilter === '' && $visitorFilter === '' && $dateFrom === '' && $dateTo === ''): ?>
    <details class="admin-maintenance-block">
        <summary>Token maintenance — delete clicks for this path</summary>
        <form method="post" action="/admin/delete-token-clicks" class="inline-form">
            <input type="hidden" name="token" value="<?= h($tokenFilter) ?>">
            <div class="filter-actions" style="margin-left: 0;">
                <button type="submit"
                        name="mode"
                        value="unknown_only"
                        class="warning-button"
                        data-confirm="Delete unknown-only clicks for this token/path?">
                    Delete unknown token hits
                </button>
                <button type="submit"
                        name="mode"
                        value="all"
                        class="danger-button"
                        data-confirm="Delete ALL clicks for this token/path?">
                    Delete all clicks for token
                </button>
            </div>
        </form>
    </details>
<?php endif; ?>

<?php if ($ipFilter !== '' && !$knownOnly && $tokenFilter === '' && $visitorFilter === '' && $dateFrom === '' && $dateTo === ''): ?>
    <details class="admin-maintenance-block">
        <summary>IP maintenance — delete clicks for this address</summary>
        <form method="post" action="/admin/delete-ip-clicks" class="inline-form">
            <input type="hidden" name="ip" value="<?= h($ipFilter) ?>">
            <div class="filter-actions" style="margin-left: 0;">
                <button type="submit"
                        name="mode"
                        value="unknown_only"
                        class="warning-button"
                        data-confirm="Delete unknown-only clicks for this IP?">
                    Delete unknown IP hits
                </button>
                <button type="submit"
                        name="mode"
                        value="all"
                        class="danger-button"
                        data-confirm="Delete ALL clicks for this IP?">
                    Delete all clicks for IP
                </button>
            </div>
        </form>
    </details>
<?php endif; ?>

<?php if ($hasActiveFilter): ?>
    <details class="admin-maintenance-block admin-danger-zone">
        <summary>Bulk delete — all clicks matching current filters</summary>
        <form method="post" action="/admin/delete-filtered-clicks" class="inline-form">
            <p class="muted">Deletes <?= number_format($totalCount) ?> click<?= $totalCount !== 1 ? 's' : '' ?> matching the active filter. Cannot be undone.</p>
            <?php if ($tokenFilter   !== ''): ?><input type="hidden" name="token"     value="<?= h($tokenFilter) ?>"><?php endif; ?>
            <?php if ($ipFilter      !== ''): ?><input type="hidden" name="ip"        value="<?= h($ipFilter) ?>"><?php endif; ?>
            <?php if ($visitorFilter !== ''): ?><input type="hidden" name="visitor"   value="<?= h($visitorFilter) ?>"><?php endif; ?>
            <?php if ($knownOnly):            ?><input type="hidden" name="known"     value="1"><?php endif; ?>
            <?php if ($dateFrom      !== ''): ?><input type="hidden" name="date_from" value="<?= h($dateFrom) ?>"><?php endif; ?>
            <?php if ($dateTo        !== ''): ?><input type="hidden" name="date_to"   value="<?= h($dateTo) ?>"><?php endif; ?>
            <div class="filter-actions" style="margin-left: 0;">
                <button type="submit"
                        class="danger-button"
                        data-confirm="Delete ALL <?= number_format($totalCount) ?> click<?= $totalCount !== 1 ? 's' : '' ?> matching the current filter? This cannot be undone.">
                    Delete all matching clicks
                </button>
            </div>
        </form>
    </details>
<?php endif; ?>



            <?php if ($showTopTokens): ?>
            <h2>Top tokens</h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>Token</th>
                        <th>Hits</th>
                        <th>Last Seen</th>
                        <th>Known?</th>
                    </tr>
                    <?php foreach ($tokenCounts as $row): ?>
                        <tr>
                            <td class="mono">
                                <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['token' => (string) $row['token']])) ?>">
                                    <?= h((string) $row['token']) ?>
                                </a>
                            </td>
                            <td><?= (int) $row['hit_count'] ?></td>
                            <td><?= h((string) $row['last_seen']) ?></td>
                            <td><?= ((int) $row['is_known'] === 1) ? 'Yes' : 'No' ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
	    </div>
            <?php endif; ?>

            <?php
            $tokenWatchlist = [];
            $staleMs = $staleTokenDays > 0 ? ($staleTokenDays * 86400000) : 0;
            foreach ($links as $watchLink) {
                $lastHitMs = (int) ($watchLink['last_clicked_at_unix_ms'] ?? 0);
                $isStale = $staleMs > 0 && $lastHitMs > 0 && ((currentUnixMs() - $lastHitMs) > $staleMs);
                $healthCode = (int) ($watchLink['last_health_http_code'] ?? 0);
                $healthFailing = $healthCode >= 400;
                if ($isStale || $healthFailing) {
                    $watchLink['_is_stale'] = $isStale;
                    $watchLink['_health_failing'] = $healthFailing;
                    $tokenWatchlist[] = $watchLink;
                }
            }
            ?>
            <?php if ($ipFilter === ''): ?>
            <h2>Token watchlist</h2>
            <p class="muted">Shows stale tokens and links with failing health checks for quick triage.</p>
            <?php if (!empty($tokenWatchlist)): ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>Token</th>
                        <th>State</th>
                        <th>Last hit</th>
                        <th>Health</th>
                        <th>Issues</th>
                        <th>Actions</th>
                    </tr>
                    <?php foreach ($tokenWatchlist as $watch): ?>
                        <tr>
                            <td class="mono">
                                <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['token' => (string) $watch['token'], 'show_all' => '1'])) ?>">
                                    <?= h((string) $watch['token']) ?>
                                </a>
                            </td>
                            <td><?= h((string) ($watch['token_state'] ?? 'active')) ?></td>
                            <td><?= !empty($watch['last_clicked_at_unix_ms']) ? h(date('Y-m-d H:i:s', (int) ($watch['last_clicked_at_unix_ms'] / 1000))) : '—' ?></td>
                            <td>
                                <?php $hc = (int) ($watch['last_health_http_code'] ?? 0); ?>
                                <?= $hc > 0 ? h((string) $hc) : '—' ?>
                            </td>
                            <td>
                                <?php if (!empty($watch['_is_stale'])): ?><span class="badge badge-suspicious">stale</span><?php endif; ?>
                                <?php if (!empty($watch['_health_failing'])): ?><span class="badge badge-bot">health fail</span><?php endif; ?>
                            </td>
                            <td>
                                <a class="button-link btn-small" href="<?= h($buildAdminUrl(['tab' => 'links', 'edit_link_id' => (string) ((int) $watch['id'])])) ?>">Edit token</a>
                                <?php if (!$isDemo): ?>
                                <form method="post" action="/admin/check-link-health" class="inline-action-form">
                                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                    <input type="hidden" name="id" value="<?= (int) $watch['id'] ?>">
                                    <button type="submit" class="btn-small">↻ Recheck health</button>
                                </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php else: ?>
            <div class="empty-state">
                No stale or failing tokens right now. This panel auto-populates when tokens cross the stale threshold or health checks return HTTP 4xx/5xx.
            </div>
            <?php endif; ?>
            <?php endif; ?>

            <?php if (!empty($behavioralFlags) && $ipFilter === ''): ?>
            <?php
            // Hidden state: URL param overrides the settings default.
            // ?hide_behavioral=1 forces hidden; ?hide_behavioral=0 forces shown.
            // If neither is set, fall back to the settings default.
            if (isset($_GET['hide_behavioral'])) {
                $showBehavioralPanel = $_GET['hide_behavioral'] !== '1';
            } else {
                $showBehavioralPanel = !$behavioralHidden;
            }
            $windowLabel = $behavioralWindowHours >= 24
                ? ($behavioralWindowHours / 24 === 1 ? 'last 24h' : 'last ' . (int)($behavioralWindowHours / 24) . 'd')
                : 'last ' . $behavioralWindowHours . 'h';
            ?>
            <div style="display:flex;align-items:center;gap:1rem;margin-bottom:0.5rem;">
                <h2 style="margin:0;">Behaviorally Flagged IPs <span class="muted" style="font-size:0.8rem;font-weight:400;">(<?= h($windowLabel) ?>)</span></h2>
                <a class="copy-button" href="<?= h($buildDashboardUrl(['hide_behavioral' => $showBehavioralPanel ? '1' : '0'])) ?>">
                    <?= $showBehavioralPanel ? 'Hide' : 'Show' ?>
                </a>
            </div>
            <?php if ($showBehavioralPanel): ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>IP</th>
                        <th>Org</th>
                        <th>Country</th>
                        <th>Hits</th>
                        <th>Burst</th>
                        <th>Rapid</th>
                        <th>Multi-token</th>
                        <th>Lowest Score</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>Actions</th>
                    </tr>
                    <?php foreach ($behavioralFlags as $flag): ?>
                        <?php
                        $flagIp = (string) ($flag['ip'] ?? '');
                        ?>
                        <tr>
                            <td class="mono ip-col">
                                <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['ip' => $flagIp, 'show_all' => '1'])) ?>">
                                    <?= h($flagIp) ?>
                                </a>
                            </td>
                            <td><?= h((string) ($flag['ip_org'] ?? '')) ?></td>
                            <td><?= h((string) ($flag['ip_country'] ?? '')) ?></td>
                            <td><?= (int) ($flag['total_hits'] ?? 0) ?></td>
                            <td><?= (int) ($flag['burst_hits'] ?? 0) > 0 ? '<span class="badge badge-bot">' . (int)$flag['burst_hits'] . '</span>' : '—' ?></td>
                            <td><?= (int) ($flag['rapid_hits'] ?? 0) > 0 ? '<span class="badge badge-suspicious">' . (int)$flag['rapid_hits'] . '</span>' : '—' ?></td>
                            <td><?= (int) ($flag['multi_hits'] ?? 0) > 0 ? '<span class="badge badge-suspicious">' . (int)$flag['multi_hits'] . '</span>' : '—' ?></td>
                            <td><?= h((string) ($flag['lowest_score'] ?? '')) ?></td>
                            <td><?= h((string) ($flag['first_seen'] ?? '')) ?></td>
                            <td><?= h((string) ($flag['last_seen'] ?? '')) ?></td>
                            <td class="actions-col actions-col--menu">
                                <?php
                                $existingOverride = $ipOverrideMap[$flagIp] ?? null;
                                $existingMode     = $existingOverride['mode'] ?? null;
                                ?>
                                <?php if ($existingOverride !== null): ?>
                                    <span class="badge <?= $existingMode === 'block' ? 'badge-bot' : ($existingMode === 'allow' ? 'badge-human' : 'badge-muted') ?>"><?= h((string) $existingMode) ?></span>
                                    <?php if ((int) ($existingOverride['hide_from_dashboard'] ?? 0) === 1): ?>
                                        <span class="badge badge-muted">hidden</span>
                                    <?php endif; ?>
                                <?php endif; ?>
                                <div class="action-menu" data-action-menu>
                                    <?= renderActionMenuTrigger('Override actions for IP') ?>
                                    <div class="action-menu-panel" hidden>
                                        <div class="action-menu-inner">
                                            <?php if ($existingOverride === null): ?>
                                                <form method="post" action="/admin/create-ip-override" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="ip" value="<?= h($flagIp) ?>">
                                                    <input type="hidden" name="mode" value="block">
                                                    <input type="hidden" name="notes" value="Added from behavioral flags">
                                                    <button type="submit" class="danger-button action-menu-submit">Block IP</button>
                                                </form>
                                                <form method="post" action="/admin/create-ip-override" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="ip" value="<?= h($flagIp) ?>">
                                                    <input type="hidden" name="mode" value="allow">
                                                    <input type="hidden" name="notes" value="Added from behavioral flags">
                                                    <button type="submit" class="warning-button action-menu-submit">Allow IP</button>
                                                </form>
                                                <form method="post" action="/admin/create-ip-override" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="ip" value="<?= h($flagIp) ?>">
                                                    <input type="hidden" name="mode" value="block">
                                                    <input type="hidden" name="hide_from_dashboard" value="1">
                                                    <input type="hidden" name="notes" value="Added from behavioral flags">
                                                    <button type="submit" class="action-menu-submit">Hide from dashboard</button>
                                                </form>
                                            <?php else: ?>
                                                <a class="action-menu-link copy-button" href="/admin?tab=overrides" style="margin-left:0;">Manage overrides</a>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>
            <?php endif; ?>
            <div style="margin-bottom: 1.25rem;"></div>

            <?php if ($wildcardMode && !empty($subdomainSummary) && $ipFilter === ''): ?>
            <?php
            if (isset($_GET['hide_subdomains'])) {
                $showSubdomainsPanel = $_GET['hide_subdomains'] !== '1';
            } else {
                $showSubdomainsPanel = !$subdomainsHidden;
            }
            ?>
            <div style="display:flex;align-items:center;gap:1rem;margin-bottom:0.5rem;">
                <h2 style="margin:0;">Subdomain Activity <?php if ($dateFrom !== '' || $dateTo !== ''): ?><span class="muted" style="font-size:0.8rem;font-weight:400;">(filtered range)</span><?php else: ?><span class="muted" style="font-size:0.8rem;font-weight:400;">(all time)</span><?php endif; ?></h2>
                <a class="copy-button" href="<?= h($buildDashboardUrl(['hide_subdomains' => $showSubdomainsPanel ? '1' : '0'])) ?>">
                    <?= $showSubdomainsPanel ? 'Hide' : 'Show' ?>
                </a>
            </div>
            <?php if ($showSubdomainsPanel): ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>Subdomain</th>
                        <th>Hits</th>
                        <th>Bot Hits</th>
                        <th class="hide-mobile">First Seen</th>
                        <th class="hide-mobile">Last Seen</th>
                    </tr>
                    <?php foreach ($subdomainSummary as $sub): ?>
                        <tr>
                            <td class="mono">
                                <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['host' => $sub['subdomain']])) ?>">
                                    <?= h($sub['subdomain']) ?>
                                </a>
                            </td>
                            <td><?= (int) $sub['total_hits'] ?></td>
                            <td>
                                <?php if ($sub['bot_hits'] > 0): ?>
                                    <span class="badge badge-bot"><?= (int) $sub['bot_hits'] ?></span>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                            <td class="hide-mobile"><?= h((string) $sub['first_seen']) ?></td>
                            <td class="hide-mobile"><?= h((string) $sub['last_seen']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>
            <div style="margin-bottom: 1.25rem;"></div>
            <?php endif; ?>

            <?php if ($ipSummary !== null && (int) ($ipSummary['total_hits'] ?? 0) > 0): ?>
            <div class="ip-summary">
                <strong>IP Summary: <?= h($ipFilter) ?></strong>
                <div class="details-grid" style="margin-top: 8px;">
                    <div>
                        <div><span class="mono">First seen:</span> <?= h((string) ($ipSummary['first_seen'] ?? '—')) ?></div>
                        <div><span class="mono">Last seen:</span>  <?= h((string) ($ipSummary['last_seen']  ?? '—')) ?></div>
                        <div><span class="mono">Total hits:</span> <?= (int) ($ipSummary['total_hits'] ?? 0) ?></div>
                        <div><span class="mono">Distinct tokens:</span> <?= (int) ($ipSummary['distinct_tokens'] ?? 0) ?></div>
                    </div>
                    <div>
                        <div><span class="mono">Bot hits:</span>        <?= (int) ($ipSummary['bot_count']        ?? 0) ?></div>
                        <div><span class="mono">Suspicious hits:</span> <?= (int) ($ipSummary['suspicious_count']   ?? 0) ?></div>
                        <div><span class="mono">Uncertain hits:</span>  <?= (int) ($ipSummary['uncertain_count']    ?? 0) ?></div>
                        <div><span class="mono">Human hits:</span>      <?= (int) ($ipSummary['human_count']        ?? 0) ?></div>
                    </div>
                    <div>
                        <div><span class="mono">Org:</span>     <?= h((string) ($ipSummary['ip_org']     ?? '—')) ?></div>
                        <div><span class="mono">ASN:</span>     <?= h((string) ($ipSummary['ip_asn']     ?? '—')) ?></div>
                        <div><span class="mono">Country:</span> <?= h((string) ($ipSummary['ip_country'] ?? '—')) ?></div>
                        <?php if (!empty($ipSummary['asn_rule'])): ?>
                            <div><span class="badge badge-suspicious">ASN rule active — penalty <?= (int) $ipSummary['asn_rule']['penalty'] ?></span></div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php
                $summaryOverride = $ipOverrideMap[$ipFilter] ?? null;
                $summaryOverrideMode = $summaryOverride['mode'] ?? null;
                ?>
                <div style="margin-top: 0.75rem; display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
                    <?php if ($summaryOverride === null): ?>
                        <form method="post" action="/admin/create-ip-override" class="inline-action-form">
                            <input type="hidden" name="ip" value="<?= h($ipFilter) ?>">
                            <input type="hidden" name="mode" value="block">
                            <input type="hidden" name="notes" value="Added from IP summary">
                            <button type="submit" class="danger-button">Block IP</button>
                        </form>
                        <form method="post" action="/admin/create-ip-override" class="inline-action-form">
                            <input type="hidden" name="ip" value="<?= h($ipFilter) ?>">
                            <input type="hidden" name="mode" value="allow">
                            <input type="hidden" name="notes" value="Added from IP summary">
                            <button type="submit" class="warning-button">Allow IP</button>
                        </form>
                        <form method="post" action="/admin/create-ip-override" class="inline-action-form">
                            <input type="hidden" name="ip" value="<?= h($ipFilter) ?>">
                            <input type="hidden" name="mode" value="block">
                            <input type="hidden" name="hide_from_dashboard" value="1">
                            <input type="hidden" name="notes" value="Added from IP summary">
                            <button type="submit">Hide IP</button>
                        </form>
                    <?php else: ?>
                        <span class="badge <?= $summaryOverrideMode === 'block' ? 'badge-bot' : ($summaryOverrideMode === 'allow' ? 'badge-human' : 'badge-muted') ?>">
                            IP override: <?= h($summaryOverrideMode) ?>
                        </span>
                        <?php if ((int) ($summaryOverride['hide_from_dashboard'] ?? 0) === 1): ?>
                            <span class="badge badge-muted">hidden from dashboard</span>
                        <?php endif; ?>
                        <a class="copy-button" href="/admin?tab=overrides">Manage →</a>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <h2>Activity</h2>
            <p class="muted">
                <?= $knownOnly ? 'Showing only known tokens.' : 'Showing all clicks that were not suppressed as noise.' ?>
                <?php if ($totalCount > 0): ?>
                    <span style="margin-left: 8px;"><?= number_format($totalCount) ?> total &mdash; page <?= $currentPage ?> of <?= $totalPages ?></span>
                <?php endif; ?>
            </p>

            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th class="time-col">Time</th>
                        <th class="type-col">Type</th>
                        <th class="token-col">Token / Path</th>
                        <?php if ($wildcardMode): ?><th class="hide-mobile">Subdomain</th><?php endif; ?>
                        <th class="ip-col">IP</th>
                        <th>Org</th>
                        <th class="classification-col">Classification</th>
                        <th class="details-col">Details</th>
                    </tr>
                    <?php foreach ($clicks as $i => $c): ?>
                        <?php
                        $confidenceLabel = (string) ($c['confidence_label'] ?? '');
                        $badgeClass = match ($confidenceLabel) {
                            'human'      => 'badge badge-human',
                            'uncertain'  => 'badge badge-uncertain',
                            'suspicious' => 'badge badge-suspicious',
                            'bot'        => 'badge badge-bot',
                            default      => 'badge',
                        };
                        $detailsId    = 'details-' . $i;
                        $rowToken     = (string) ($c['token'] ?? '');
                        $displayToken = ($rowToken === 'root') ? '/' : $rowToken;
                        $rowIp        = (string) ($c['ip'] ?? '');
                        $rowVisitor   = (string) ($c['visitor_hash'] ?? '');
                        $rowUa        = (string) ($c['user_agent'] ?? '');
                        $rowHost      = (string) ($c['host'] ?? '');
                        $subdomain    = $wildcardMode ? extractSubdomain($rowHost, $baseUrl) : '';

                        // Display timestamp from unix_ms if available, fall back to clicked_at string.
                        $tsMs      = $c['clicked_at_unix_ms'] ?? null;
                        $tsDisplay = $tsMs !== null
                            ? date('Y-m-d H:i:s', (int) ($tsMs / 1000))
                            : (string) ($c['clicked_at'] ?? '');
                        ?>
                        <tr class="<?= $confidenceLabel === 'bot' ? 'bot' : '' ?>">
                            <td class="time-col" title="<?= h((string) ($c['clicked_at'] ?? '')) ?>"><?= h($tsDisplay) ?></td>
                            <td class="type-col"><?= h((string) ($c['event_type'] ?? 'click')) ?></td>
                            <td class="mono token-col">
                                <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['token' => $rowToken])) ?>">
                                    <?= h($rowToken) ?>
                                </a>
                            </td>
                            <?php if ($wildcardMode): ?>
                            <td class="mono hide-mobile">
                                <?php if ($subdomain !== ''): ?>
                                    <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['host' => $rowHost])) ?>"><?= h($subdomain) ?></a>
                                <?php else: ?>
                                    <span class="muted">—</span>
                                <?php endif; ?>
                            </td>
                            <?php endif; ?>
                            <td class="mono ip-col">
                                <a class="table-link mono-link" href="<?= h($buildDashboardUrl(['ip' => $rowIp])) ?>">
                                    <?= h($rowIp) ?>
                                </a>
                            </td>
			    <td><?= h((string) ($c['ip_org'] ?? '')) ?></td>
			    <?php $rowScore = (int) ($c['confidence_score'] ?? 0); ?>
                            <td class="classification-col">
			        <span class="<?= h($badgeClass) ?>">
			            <?= h($confidenceLabel) ?>
			        </span>
			        <span class="score-pill"><?= $rowScore ?></span>
			    </td>
			    <td class="details-col">
                                <button type="button" class="details-button" data-details="<?= h($detailsId) ?>">Details ▾</button>
                            </td>
                        </tr>
                        <tr id="<?= h($detailsId) ?>" class="details-row">
                            <td colspan="<?= $wildcardMode ? 8 : 7 ?>" class="details-cell">
                                <div class="details-grid">
                                    <div class="detail-box">
                                        <strong>Identity</strong>
                                        <div>
                                            <span class="mono">Click ID:</span> <?= h((string) ($c['id'] ?? '')) ?>
                                        </div>
					<div>
					    <span class="mono">IP:</span>
					    <a class="pill-link mono" href="<?= h($buildDashboardUrl(['ip' => $rowIp])) ?>"><?= h($rowIp) ?></a>
					    <button type="button" class="copy-button" data-copy="<?= h($rowIp) ?>" title="Copy IP">Copy</button>
					    <a class="copy-button" href="https://www.virustotal.com/gui/ip-address/<?= h($rowIp) ?>" target="_blank" rel="noopener" title="Open in VirusTotal">VT</a>
					    <a class="copy-button" href="https://www.abuseipdb.com/check/<?= h($rowIp) ?>" target="_blank" rel="noopener" title="Open in AbuseIPDB">Abuse</a>
					    <a class="copy-button" href="https://ipinfo.io/<?= h($rowIp) ?>" target="_blank" rel="noopener" title="Open in IPinfo">Info</a>
					</div>
					<?php
                        $rowAsn = (string) ($c['ip_asn'] ?? '');
                        $asnRule = $rowAsn !== '' ? getAsnRuleByAsn($pdo, $rowAsn) : null;
                        ?>
					<div>
					    <span class="mono">ASN:</span> <?= h($rowAsn) ?>

					    <?php if ($rowAsn !== '' && $asnRule === null): ?>
					        <form method="post" action="/admin/create-asn-rule" class="inline-action-form" style="display:inline-block;">
					            <input type="hidden" name="asn" value="<?= h($rowAsn) ?>">
					            <input type="hidden" name="label" value="<?= h((string) ($c['ip_org'] ?? '')) ?>">
					            <input type="hidden" name="penalty" value="10">
					            <button type="submit" class="copy-button">Add ASN Rule</button>
					        </form>
					    <?php elseif ($asnRule !== null): ?>
					        <span class="badge badge-suspicious">ASN rule active</span>
					    <?php endif; ?>
					</div>
                                        <div><span class="mono">Org:</span> <?= h((string) ($c['ip_org'] ?? '')) ?></div>
                                        <div><span class="mono">Country:</span> <?= h((string) ($c['ip_country'] ?? '')) ?></div>
                                        <div>
                                            <span class="mono">Visitor:</span>
                                            <a class="pill-link mono" href="<?= h($buildDashboardUrl(['visitor' => $rowVisitor])) ?>"><?= h($rowVisitor) ?></a>
                                            <button type="button" class="copy-button" data-copy="<?= h($rowVisitor) ?>">Copy</button>
                                        </div>
                                        <div><span class="mono">XFF:</span> <?= h((string) ($c['x_forwarded_for'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box">
					<strong>Scoring</strong>
					<?php
                                                $score = (int) ($c['confidence_score'] ?? 0);
                        if ($score <= 10) {
                            $confidenceLevel = 'high';
                        } elseif ($score <= 30) {
                            $confidenceLevel = 'medium';
                        } elseif ($score <= 60) {
                            $confidenceLevel = 'low';
                        } else {
                            $confidenceLevel = 'very low';
                        }
                        ?>
					<div><span class="mono">Classification:</span> <?= h((string) ($c['confidence_label'] ?? '')) ?> (<?= h((string) ($c['confidence_score'] ?? '')) ?>)</div>
                                        <div><span class="mono">Reason:</span> <?= renderSignalReasons((string) ($c['confidence_reason'] ?? '')) ?></div>
                                        <div><span class="mono">First for token:</span> <?= !empty($c['first_for_token']) ? 'Yes' : 'No' ?></div>
                                        <div><span class="mono">Prior events for token:</span> <?= h((string) ($c['prior_events_for_token'] ?? '0')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Request</strong>
                                        <div>
                                            <span class="mono">Token / Path:</span>
                                            <a class="pill-link mono" href="<?= h($buildDashboardUrl(['token' => $rowToken])) ?>"><?= h($rowToken) ?></a>
                                            <button type="button" class="copy-button" data-copy="<?= h($rowToken) ?>">Copy</button>
                                        </div>
                                        <div><span class="mono">Method:</span> <?= h((string) ($c['request_method'] ?? '')) ?></div>
                                        <div><span class="mono">Host:</span> <?= h((string) ($c['host'] ?? '')) ?></div>
                                        <div><span class="mono">Scheme:</span> <?= h((string) ($c['scheme'] ?? '')) ?></div>
                                        <div><span class="mono">URI:</span> <span class="wrap"><?= h((string) ($c['request_uri'] ?? '')) ?></span></div>
                                        <div><span class="mono">Query:</span> <span class="wrap"><?= h((string) ($c['query_string'] ?? '')) ?></span></div>
                                        <div><span class="mono">Remote port:</span> <?= h((string) ($c['remote_port'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box shodan-box" data-ip="<?= h($rowIp) ?>">
                                        <strong>IP Reputation</strong>
                                        <div class="shodan-loading muted" style="font-size:0.8125rem;">Loading…</div>
                                        <div class="shodan-content" style="display:none;"></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Headers</strong>
                                        <div><span class="mono">Referer:</span> <span class="wrap"><?= h((string) ($c['referer'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept:</span> <span class="wrap"><?= h((string) ($c['accept'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept-Language:</span> <span class="wrap"><?= h((string) ($c['accept_language'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept-Encoding:</span> <span class="wrap"><?= h((string) ($c['accept_encoding'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Site:</span> <span class="wrap"><?= h((string) ($c['sec_fetch_site'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Mode:</span> <span class="wrap"><?= h((string) ($c['sec_fetch_mode'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Dest:</span> <span class="wrap"><?= h((string) ($c['sec_fetch_dest'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-CH-UA:</span> <span class="wrap"><?= h((string) ($c['sec_ch_ua'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-CH-UA-Platform:</span> <span class="wrap"><?= h((string) ($c['sec_ch_ua_platform'] ?? '')) ?></span></div>
                                    </div>

                                    <div class="detail-box" style="grid-column: 1 / -1;">
                                        <strong>User-Agent</strong>
                                        <div class="wrap">
                                            <?= h($rowUa) ?>
                                            <button type="button" class="copy-button" data-copy="<?= h($rowUa) ?>">Copy</button>
                                        </div>
                                    </div>

                                    <div class="detail-box" style="grid-column: 1 / -1;">
                                        <strong>Actions</strong>
                                        <?php
                                        // Hidden filter fields included in every action form so the
                                        // handler can redirect back to the current filtered view.
                                        $filterHiddens = '';
                                        if ($tokenFilter   !== '') $filterHiddens .= '<input type="hidden" name="_filter_token"     value="' . h($tokenFilter)   . '">';
                                        if ($ipFilter      !== '') $filterHiddens .= '<input type="hidden" name="_filter_ip"        value="' . h($ipFilter)      . '">';
                                        if ($visitorFilter !== '') $filterHiddens .= '<input type="hidden" name="_filter_visitor"   value="' . h($visitorFilter) . '">';
                                        if ($campaignFilter > 0)   $filterHiddens .= '<input type="hidden" name="_filter_campaign"  value="' . (int) $campaignFilter . '">';
                                        if ($knownOnly)            $filterHiddens .= '<input type="hidden" name="_filter_known"     value="1">';
                                        if ($dateFrom      !== '') $filterHiddens .= '<input type="hidden" name="_filter_date_from" value="' . h($dateFrom)      . '">';
                                        if ($dateTo        !== '') $filterHiddens .= '<input type="hidden" name="_filter_date_to"   value="' . h($dateTo)        . '">';
                                        $existingOverride     = $ipOverrideMap[$rowIp] ?? null;
                                        $existingOverrideMode = $existingOverride['mode'] ?? null;
                                        ?>
                                        <div class="action-menu" data-action-menu>
                                            <?= renderActionMenuTrigger('Event row actions') ?>
                                            <div class="action-menu-panel" hidden>
                                                <div class="action-menu-inner">
                                                    <form method="post" action="/admin/delete-click" class="inline-action-form action-menu-form" data-confirm="Delete this click?">
                                                        <?= $filterHiddens ?>
                                                        <input type="hidden" name="id" value="<?= h((string) ($c['id'] ?? '')) ?>">
                                                        <button type="submit" class="danger-button action-menu-submit">Delete this click</button>
                                                    </form>

                                                    <form method="post" action="/admin/add-token-to-skip" class="inline-action-form action-menu-form" data-confirm="Add this token/path to skip patterns?">
                                                        <?= $filterHiddens ?>
                                                        <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                                        <button type="submit" class="warning-button action-menu-submit">Skip exact token</button>
                                                    </form>

                                                    <?php if (empty($c['link_id'])): ?>
                                                        <form method="post" action="/admin/delete-token-clicks" class="inline-action-form action-menu-form" data-confirm="Delete unknown-only clicks for this token/path?">
                                                            <?= $filterHiddens ?>
                                                            <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                                            <input type="hidden" name="mode" value="unknown_only">
                                                            <button type="submit" class="warning-button action-menu-submit">Delete unknown token hits</button>
                                                        </form>
                                                    <?php endif; ?>

                                                    <form method="post" action="/admin/delete-token-clicks" class="inline-action-form action-menu-form" data-confirm="Delete ALL clicks for this token/path?">
                                                        <?= $filterHiddens ?>
                                                        <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                                        <input type="hidden" name="mode" value="all">
                                                        <button type="submit" class="danger-button action-menu-submit">Delete all token clicks</button>
                                                    </form>

                                                    <?php if ($existingOverride === null): ?>
                                                        <form method="post" action="/admin/create-ip-override" class="inline-action-form action-menu-form">
                                                            <?= $filterHiddens ?>
                                                            <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
                                                            <input type="hidden" name="mode" value="block">
                                                            <input type="hidden" name="notes" value="Added from activity feed">
                                                            <button type="submit" class="danger-button action-menu-submit">Block IP</button>
                                                        </form>
                                                        <form method="post" action="/admin/create-ip-override" class="inline-action-form action-menu-form">
                                                            <?= $filterHiddens ?>
                                                            <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
                                                            <input type="hidden" name="mode" value="allow">
                                                            <input type="hidden" name="notes" value="Added from activity feed">
                                                            <button type="submit" class="warning-button action-menu-submit">Allow IP</button>
                                                        </form>
                                                        <form method="post" action="/admin/create-ip-override" class="inline-action-form action-menu-form">
                                                            <?= $filterHiddens ?>
                                                            <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
                                                            <input type="hidden" name="mode" value="block">
                                                            <input type="hidden" name="hide_from_dashboard" value="1">
                                                            <input type="hidden" name="notes" value="Added from activity feed">
                                                            <button type="submit" class="action-menu-submit">Hide IP from dashboard</button>
                                                        </form>
                                                    <?php else: ?>
                                                        <a class="action-menu-link copy-button" href="/admin?tab=overrides" style="margin-left:0;">Manage IP override</a>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>
                                        <?php if ($existingOverride !== null): ?>
                                            <span class="badge <?= $existingOverrideMode === 'block' ? 'badge-bot' : ($existingOverrideMode === 'allow' ? 'badge-human' : 'badge-muted') ?>">
                                                IP override: <?= h((string) $existingOverrideMode) ?>
                                            </span>
                                            <?php if ((int) ($existingOverride['hide_from_dashboard'] ?? 0) === 1): ?>
                                                <span class="badge badge-muted">hidden</span>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>

            <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($currentPage > 1): ?>
                    <a class="button-link" href="<?= h($buildDashboardUrl(['page' => (string) ($currentPage - 1)])) ?>">&larr; Previous</a>
                <?php endif; ?>

                <?php
                $start = max(1, $currentPage - 2);
                $end   = min($totalPages, $currentPage + 2);
                for ($p = $start; $p <= $end; $p++):
                ?>
                    <?php if ($p === $currentPage): ?>
                        <span class="page-current"><?= $p ?></span>
                    <?php else: ?>
                        <a class="button-link" href="<?= h($buildDashboardUrl(['page' => (string) $p])) ?>"><?= $p ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($currentPage < $totalPages): ?>
                    <a class="button-link" href="<?= h($buildDashboardUrl(['page' => (string) ($currentPage + 1)])) ?>">Next &rarr;</a>
                <?php endif; ?>

                <span class="muted">
                    <?= number_format($totalCount) ?> total &mdash; page <?= $currentPage ?> of <?= $totalPages ?>
                </span>
            </div>
            <?php endif; ?>

        </div>

        <div class="tab-content" id="content-reports">
            <h2>Executive reports</h2>
            <p class="muted">Snapshot for the selected window with period-over-period deltas and exportable country density for map tooling.</p>

            <form method="get" action="/admin" class="inline-form" style="margin-bottom:1rem;">
                <input type="hidden" name="tab" value="reports">
                <label for="report-window-hours">Window</label>
                <select id="report-window-hours" name="report_window_hours" style="width:auto;margin-bottom:0;">
                    <option value="24" <?= $reportWindowHours === 24 ? 'selected' : '' ?>>24h</option>
                    <option value="72" <?= $reportWindowHours === 72 ? 'selected' : '' ?>>72h</option>
                    <option value="168" <?= $reportWindowHours === 168 ? 'selected' : '' ?>>7d</option>
                    <option value="720" <?= $reportWindowHours === 720 ? 'selected' : '' ?>>30d</option>
                </select>
                <button type="submit">Refresh report</button>
                <a class="button-link" href="<?= h('/export/executive-summary?window_hours=' . $reportWindowHours) ?>" target="_blank" rel="noopener">Export report JSON</a>
                <a class="button-link" href="<?= h('/export/reports/country-density?window_hours=' . $reportWindowHours . '&limit=200') ?>" target="_blank" rel="noopener">Country density JSON</a>
                <a class="button-link" href="<?= h('/export/reports/country-density.csv?window_hours=' . $reportWindowHours . '&limit=200') ?>" target="_blank" rel="noopener">Country density CSV</a>
                <a class="button-link" href="<?= h($buildReportsUrl(['report_window_hours' => null])) ?>">Reset</a>
            </form>

            <div class="reports-grid reports-kpi-grid">
                <article class="report-card report-kpi-card">
                    <div class="small muted">Events</div>
                    <div class="report-value"><?= number_format((int) ($reportKpis['current']['total_events'] ?? 0)) ?></div>
                    <div class="small">Δ <?= h((string) ($reportKpis['deltas']['total_events'] ?? 0)) ?>%</div>
                </article>
                <article class="report-card report-kpi-card">
                    <div class="small muted">Unique IPs</div>
                    <div class="report-value"><?= number_format((int) ($reportKpis['current']['unique_ips'] ?? 0)) ?></div>
                    <div class="small">Δ <?= h((string) ($reportKpis['deltas']['unique_ips'] ?? 0)) ?>%</div>
                </article>
                <article class="report-card report-kpi-card">
                    <div class="small muted">Known token hits</div>
                    <div class="report-value"><?= number_format((int) ($reportKpis['current']['known_hits'] ?? 0)) ?></div>
                    <div class="small">Δ <?= h((string) ($reportKpis['deltas']['known_hits'] ?? 0)) ?>%</div>
                </article>
                <article class="report-card report-kpi-card">
                    <div class="small muted">Feed candidates</div>
                    <div class="report-value"><?= number_format((int) ($reportKpis['current']['feed_candidates'] ?? 0)) ?></div>
                    <div class="small">Δ <?= h((string) ($reportKpis['deltas']['feed_candidates'] ?? 0)) ?>%</div>
                </article>
                <article class="report-card report-kpi-card">
                    <div class="small muted">Risky hit rate</div>
                    <div class="report-value"><?= h((string) ($reportKpis['current']['risky_rate_pct'] ?? 0)) ?>%</div>
                    <div class="small">Δ <?= h((string) ($reportKpis['deltas']['risky_rate_pct'] ?? 0)) ?> pts</div>
                </article>
            </div>

            <h3 style="margin-top:1rem;">Country overlay heatmap</h3>
            <div class="report-map-card">
                <div class="report-map-toolbar">
                    <label for="report-map-metric" class="small">Metric</label>
                    <select id="report-map-metric" style="width:auto;margin-bottom:0;">
                        <option value="total_events" selected>Total events</option>
                        <option value="risky_hits">Risky hits</option>
                    </select>
                    <div class="report-map-legend" aria-hidden="true">
                        <span class="small muted">Low</span>
                        <span class="report-map-legend-bar"></span>
                        <span class="small muted">High</span>
                    </div>
                </div>
                <div class="report-map" aria-label="Country activity map">
                    <div id="report-map-total" data-map-panel="total_events"><?= renderReportCountryHeatmapSvg($reportCountries, 'total_events') ?></div>
                    <div id="report-map-risky" data-map-panel="risky_hits" hidden><?= renderReportCountryHeatmapSvg($reportCountries, 'risky_hits') ?></div>
                </div>
                <p class="muted small" style="margin-top:0.5rem;">
                    Bubble intensity and size reflect the selected metric for each country in the selected window.
                </p>
            </div>

            <h3 style="margin-top:1rem;">Country density</h3>
            <div class="table-wrap">
                <table class="compact-table">
                    <thead>
                        <tr>
                            <th>Country</th>
                            <th>Total events</th>
                            <th>Unique IPs</th>
                            <th>Risky hits</th>
                            <th>Risky rate</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if (!empty($reportCountries)): ?>
                        <?php foreach ($reportCountries as $countryRow): ?>
                            <tr>
                                <td><span class="mono-link"><?= h((string) ($countryRow['country_code'] ?? '??')) ?></span></td>
                                <td><?= number_format((int) ($countryRow['total_events'] ?? 0)) ?></td>
                                <td><?= number_format((int) ($countryRow['unique_ips'] ?? 0)) ?></td>
                                <td><?= number_format((int) ($countryRow['risky_hits'] ?? 0)) ?></td>
                                <td><?= h((string) ($countryRow['risky_rate_pct'] ?? 0)) ?>%</td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr><td colspan="5" class="muted">No country-level activity in this window.</td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <h3 style="margin-top:1rem;">Top tokens</h3>
            <div class="table-wrap">
                <table class="compact-table">
                    <thead>
                        <tr>
                            <th>Token/path</th>
                            <th>Total hits</th>
                            <th>Unique IPs</th>
                            <th>Risky hits</th>
                            <th>Last seen</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if (!empty($reportTopTokens)): ?>
                        <?php foreach ($reportTopTokens as $tokenRow): ?>
                            <tr>
                                <td><a class="table-link mono-link" href="<?= h($buildDashboardUrl(['token' => (string) ($tokenRow['token'] ?? ''), 'show_all' => '1'])) ?>"><?= h((string) ($tokenRow['token'] ?? '')) ?></a></td>
                                <td><?= number_format((int) ($tokenRow['total_hits'] ?? 0)) ?></td>
                                <td><?= number_format((int) ($tokenRow['unique_ips'] ?? 0)) ?></td>
                                <td><?= number_format((int) ($tokenRow['risky_hits'] ?? 0)) ?></td>
                                <td><?= h((string) ($tokenRow['last_seen'] ?? '')) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr><td colspan="5" class="muted">No token activity in this window.</td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

	<div class="tab-content" id="content-links">

        <?php if (!empty($campaignStats)): ?>
        <h2>Campaigns</h2>
        <div class="table-wrap" style="margin-bottom: 1.5rem;">
            <table class="compact-table">
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Tokens</th>
                    <th>Total Hits</th>
                    <th>Unique IPs</th>
                    <th>First Hit</th>
                    <th>Last Hit</th>
                    <th>Webhook</th>
                    <th>Active</th>
                    <th class="actions-col">Actions</th>
                </tr>
                <?php foreach ($campaignStats as $campaign): ?>
                <tr>
                    <td><strong><a class="table-link" href="<?= h($buildDashboardUrl(['campaign' => (string) $campaign['id'], 'hide_behavioral' => '1', 'hide_subdomains' => '1'])) ?>"><?= h((string) $campaign['name']) ?></a></strong></td>
                    <td class="muted"><?= h((string) ($campaign['description'] ?? '')) ?></td>
                    <td><?= (int) $campaign['token_count'] ?></td>
                    <td><?= (int) $campaign['total_hits'] ?></td>
                    <td><?= (int) $campaign['unique_ips'] ?></td>
                    <td class="muted"><?= $campaign['first_hit'] !== null ? h((string) $campaign['first_hit']) : '—' ?></td>
                    <td class="muted"><?= $campaign['last_hit']  !== null ? h((string) $campaign['last_hit'])  : '—' ?></td>
                    <td><?= ((int) ($campaign['webhook_enabled'] ?? 0) === 1) ? 'Fallback' : '—' ?></td>
                    <td><?= ((int) $campaign['active'] === 1) ? 'Yes' : 'No' ?></td>
                    <td class="actions-col actions-col--menu campaign-actions-cell">
                        <div class="action-menu" data-action-menu>
                            <?= renderActionMenuTrigger('Campaign actions') ?>
                            <div class="action-menu-panel" hidden>
                                <div class="action-menu-inner">
                                    <a class="action-menu-link button-link" href="<?= h($buildDashboardUrl(['campaign' => (string) $campaign['id'], 'hide_behavioral' => '1', 'hide_subdomains' => '1'])) ?>">View activity</a>
                                    <button type="button" class="action-menu-item" data-edit-campaign="<?= (int) $campaign['id'] ?>">Edit campaign</button>
                                    <form method="post" action="/admin/delete-campaign" class="inline-action-form action-menu-form"
                                          data-confirm="Delete this campaign? Tokens will not be deleted but will be unassigned.">
                                        <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                        <input type="hidden" name="campaign_id" value="<?= (int) $campaign['id'] ?>">
                                        <button type="submit" class="danger-button action-menu-submit">Delete campaign</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </td>
                </tr>

                <tr id="edit-campaign-<?= (int) $campaign['id'] ?>" style="display:none;" class="edit-row">
                    <td colspan="10" class="edit-row-cell">
                        <div class="inline-edit-panel campaign-edit-panel">
                            <div class="panel-title">Edit Campaign</div>
                            <form method="post" action="/admin/update-campaign" class="campaign-edit-form">
                                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                <input type="hidden" name="campaign_id" value="<?= (int) $campaign['id'] ?>">

                                <div class="campaign-edit-grid">
                                    <div class="form-field">
                                        <label for="campaign_name_<?= (int) $campaign['id'] ?>">Name</label>
                                        <input id="campaign_name_<?= (int) $campaign['id'] ?>" type="text" name="campaign_name" required value="<?= h((string) $campaign['name']) ?>">
                                    </div>

                                    <div class="form-field">
                                        <label for="campaign_description_<?= (int) $campaign['id'] ?>">Description</label>
                                        <input id="campaign_description_<?= (int) $campaign['id'] ?>" type="text" name="campaign_description" value="<?= h((string) ($campaign['description'] ?? '')) ?>">
                                    </div>
                                </div>

                                <div class="campaign-edit-actions-row">
                                    <div class="campaign-edit-options">
                                        <label class="checkbox-inline">
                                            <input type="checkbox" name="campaign_active" value="1" <?= ((int) $campaign['active'] === 1) ? 'checked' : '' ?>>
                                            <span>Active</span>
                                        </label>

                                        <label class="checkbox-inline">
                                            <input type="checkbox" name="webhook_enabled" value="1" <?= ((int) ($campaign['webhook_enabled'] ?? 0) === 1) ? 'checked' : '' ?>>
                                            <span>Fallback to token webhook</span>
                                        </label>
                                    </div>

                                    <div class="campaign-edit-buttons">
                                        <button type="submit">Save campaign</button>
                                        <button type="button" class="primary-button" data-cancel-campaign-edit="<?= (int) $campaign['id'] ?>">
                                            Cancel
                                        </button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </table>
        </div>
        <?php endif; ?>

        <form method="post" action="/admin/create-campaign" style="margin-bottom:2rem;">
            <h2>Create campaign</h2>
            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
            <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
                <div>
                    <label for="campaign_name" style="font-size:0.8125rem;">Name</label>
                    <input id="campaign_name" type="text" name="campaign_name" required placeholder="Q2 Phishing Simulation" style="width:220px;">
                </div>
                <div>
                    <label for="campaign_description" style="font-size:0.8125rem;">Description</label>
                    <input id="campaign_description" type="text" name="campaign_description" placeholder="Optional description" style="width:280px;">
                </div>
                <div style="display:flex;align-items:center;gap:6px;padding-bottom:1rem;">
                    <input id="campaign_webhook_enabled" type="checkbox" name="webhook_enabled" value="1">
                    <label for="campaign_webhook_enabled" style="font-size:0.8125rem;margin:0;">Fallback to token webhook</label>
                </div>
                <div class="campaign-form-action" style="display:flex;align-items:flex-end;padding-bottom:1rem;">
                    <button type="submit" style="align-self:flex-end;">Create campaign</button>
                </div>
            </div>
        </form>

	    <?php if ($editLink !== null): ?>
	    <form method="post" action="/admin/update-link">
	        <h2>Edit token</h2>

	        <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
	        <input type="hidden" name="id" value="<?= (int) $editLink['id'] ?>">

	        <label for="edit_token">Token / Path</label>
	        <input id="edit_token" type="text" name="token" required value="<?= h((string) $editLink['token']) ?>">

	        <label for="edit_destination">Destination URL</label>
	        <input id="edit_destination" type="url" name="destination" required value="<?= h((string) $editLink['destination']) ?>">

	        <label for="edit_description">Description</label>
	        <input id="edit_description" type="text" name="description" value="<?= h((string) ($editLink['description'] ?? '')) ?>">

            <label for="edit_token_state">Lifecycle state</label>
            <select id="edit_token_state" name="token_state">
                <?php $editState = (string) ($editLink['token_state'] ?? 'active'); ?>
                <?php foreach (['draft', 'active', 'paused', 'expired', 'archived'] as $state): ?>
                    <option value="<?= h($state) ?>" <?= $editState === $state ? 'selected' : '' ?>><?= h(ucfirst($state)) ?></option>
                <?php endforeach; ?>
            </select>

            <label for="edit_activates_at">Activate at (optional)</label>
            <input id="edit_activates_at" type="datetime-local" name="activates_at" value="<?= h((string) (!empty($editLink['activates_at']) ? str_replace(' ', 'T', substr((string) $editLink['activates_at'], 0, 16)) : '')) ?>">

            <label for="edit_expires_at">Expire at (optional)</label>
            <input id="edit_expires_at" type="datetime-local" name="expires_at" value="<?= h((string) (!empty($editLink['expires_at']) ? str_replace(' ', 'T', substr((string) $editLink['expires_at'], 0, 16)) : '')) ?>">

            <label for="edit_owner">Owner</label>
            <input id="edit_owner" type="text" name="owner" value="<?= h((string) ($editLink['owner'] ?? '')) ?>" placeholder="SOC / Team / Operator">
            <label for="edit_source">Source</label>
            <input id="edit_source" type="text" name="source" value="<?= h((string) ($editLink['source'] ?? '')) ?>" placeholder="Email campaign / web form / integration">
            <label for="edit_objective">Objective</label>
            <input id="edit_objective" type="text" name="objective" value="<?= h((string) ($editLink['objective'] ?? '')) ?>" placeholder="Detection / validation / monitoring">
            <label for="edit_channel">Channel</label>
            <input id="edit_channel" type="text" name="channel" value="<?= h((string) ($editLink['channel'] ?? '')) ?>" placeholder="Email / SMS / web / API">

            <label for="edit_redirect_strategy">Redirect strategy</label>
            <select id="edit_redirect_strategy" name="redirect_strategy">
                <?php $editRedirectStrategy = (string) ($editLink['redirect_strategy'] ?? 'single'); ?>
                <option value="single" <?= $editRedirectStrategy === 'single' ? 'selected' : '' ?>>Single destination</option>
                <option value="weighted" <?= $editRedirectStrategy === 'weighted' ? 'selected' : '' ?>>Weighted pool</option>
            </select>
            <label for="edit_redirect_pool">Weighted redirect pool (one per line: URL|weight)</label>
            <textarea id="edit_redirect_pool" name="redirect_pool" rows="4" placeholder="https://a.example.com|3&#10;https://b.example.com|1"><?= h((string) implode("\n", array_map(
                static fn(array $row): string => (string) ($row['url'] ?? '') . '|' . (int) ($row['weight'] ?? 1),
                is_array(json_decode((string) ($editLink['redirect_pool_json'] ?? ''), true)) ? json_decode((string) ($editLink['redirect_pool_json'] ?? ''), true) : []
            ))) ?></textarea>

            <?php if (!empty($campaigns)): ?>
            <label for="edit_campaign_id">Campaign</label>
            <select id="edit_campaign_id" name="campaign_id">
                <option value="">— None —</option>
                <?php foreach ($campaigns as $c): ?>
                <option value="<?= (int) $c['id'] ?>" <?= ((int) ($editLink['campaign_id'] ?? 0) === (int) $c['id']) ? 'selected' : '' ?>>
                    <?= h((string) $c['name']) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <?php endif; ?>

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="exclude_from_feed" value="1" <?= ((int) ($editLink['exclude_from_feed'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Exclude from threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">IPs that hit this token will never appear in the feed, even if classified as suspicious or bot.</p>
	        </div>

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="force_include_in_feed" value="1" <?= ((int) ($editLink['force_include_in_feed'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Always include in threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">Any IP that hits this token is added to the threat feed regardless of classification. Useful for canary tokens where any hit is inherently suspicious. Overrides exclude if both are set.</p>
	        </div>

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="include_in_token_webhook" value="1" <?= ((int) ($editLink['include_in_token_webhook'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Fire token webhook on hit</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">When enabled, a webhook fires each time this token is hit (deduped per visitor per 5 minutes). Requires a Token Webhook URL in Settings.</p>
	        </div>

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="include_in_email" value="1" <?= ((int) ($editLink['include_in_email'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Send email alert on hit</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">When enabled, an email fires each time this token is hit regardless of classification (deduped per IP per the configured window). Requires Email Alerting configured in Settings.</p>
	        </div>

            <div style="margin-bottom: 12px;">
                <label style="display: inline-flex; align-items: center; gap: 6px;">
                    <input type="checkbox" name="alert_on_first_hit" value="1" <?= ((int) ($editLink['alert_on_first_hit'] ?? 0) === 1) ? 'checked' : '' ?>>
                    <span>Flag first-hit alert context</span>
                </label>
                <p class="muted" style="margin: 4px 0 0 0;">Adds `token_first_hit` marker to webhook payload reasons on the first observed hit.</p>
            </div>
            <label for="edit_dormancy_alert_hours">Dormancy reactivation threshold (hours)</label>
            <input id="edit_dormancy_alert_hours" type="number" min="0" name="dormancy_alert_hours" value="<?= (int) ($editLink['dormancy_alert_hours'] ?? 0) ?>">
            <p class="muted" style="margin: 4px 0 12px 0;">When set, emits `token_dormant_reactivation` marker after this inactivity window.</p>

	        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
	            <button type="submit">Save token</button>
	            <form method="get" action="/admin" class="inline-action-form">
	                <input type="hidden" name="tab" value="links">
	                <button type="submit">Cancel</button>
	            </form>
	        </div>
	    </form>

            <?php
                $editTemplates = buildTokenDeploymentSnippets($baseUrl, $editLink);
            ?>
            <div class="deployment-panel" style="margin-bottom:2rem;">
                <h2>Deployment templates</h2>
                <p class="muted" style="margin-bottom:1rem;">Copy ready-to-use snippets for email, HTML, Markdown, and tracking pixel deployments.</p>
                <div class="snippet-grid">
                    <?php foreach ($editTemplates as $snippetTitle => $snippetBody): ?>
                        <?= renderSnippetBox($snippetTitle, $snippetBody) ?>
                    <?php endforeach; ?>
                </div>
            </div>
	<?php endif; ?>
            <form method="post" action="/admin/create-link">
                <h2>Create token</h2>
                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                <label for="token">Token / Path</label>
                <input id="token" type="text" name="token" required placeholder="payroll or abc123">

                <label for="destination">Destination URL</label>
                <input id="destination" type="url" name="destination" required placeholder="https://www.example.com/">

                <label for="description">Description</label>
                <input id="description" type="text" name="description" placeholder="Optional description">

                <label for="token_state">Lifecycle state</label>
                <select id="token_state" name="token_state">
                    <option value="active" selected>Active</option>
                    <option value="draft">Draft</option>
                    <option value="paused">Paused</option>
                    <option value="archived">Archived</option>
                </select>

                <label for="activates_at">Activate at (optional)</label>
                <input id="activates_at" type="datetime-local" name="activates_at">

                <label for="expires_at">Expire at (optional)</label>
                <input id="expires_at" type="datetime-local" name="expires_at">

                <label for="owner">Owner</label>
                <input id="owner" type="text" name="owner" placeholder="SOC / Team / Operator">
                <label for="source">Source</label>
                <input id="source" type="text" name="source" placeholder="Email campaign / web form / integration">
                <label for="objective">Objective</label>
                <input id="objective" type="text" name="objective" placeholder="Detection / validation / monitoring">
                <label for="channel">Channel</label>
                <input id="channel" type="text" name="channel" placeholder="Email / SMS / web / API">

                <label for="redirect_strategy">Redirect strategy</label>
                <select id="redirect_strategy" name="redirect_strategy">
                    <option value="single" selected>Single destination</option>
                    <option value="weighted">Weighted pool</option>
                </select>
                <label for="redirect_pool">Weighted redirect pool (one per line: URL|weight)</label>
                <textarea id="redirect_pool" name="redirect_pool" rows="4" placeholder="https://a.example.com|3&#10;https://b.example.com|1"></textarea>

                <?php if (!empty($campaigns)): ?>
                <label for="campaign_id">Campaign</label>
                <select id="campaign_id" name="campaign_id">
                    <option value="">— None —</option>
                    <?php foreach ($campaigns as $c): ?>
                    <option value="<?= (int) $c['id'] ?>"><?= h((string) $c['name']) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php endif; ?>

                <div style="margin-bottom: 12px;">
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="exclude_from_feed" value="1">
                        <span>Exclude from threat feed</span>
                    </label>
                    <p class="muted" style="margin: 4px 0 0 0;">IPs that hit this token will never appear in the feed, even if classified as suspicious or bot.</p>
                </div>

                <div style="margin-bottom: 12px;">
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="force_include_in_feed" value="1">
                        <span>Always include in threat feed</span>
                    </label>
                    <p class="muted" style="margin: 4px 0 0 0;">Any IP that hits this token is added to the threat feed regardless of classification. Useful for canary tokens where any hit is inherently suspicious. Overrides exclude if both are set.</p>
                </div>

                <div style="margin-bottom: 12px;">
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="include_in_token_webhook" value="1">
                        <span>Fire token webhook on hit</span>
                    </label>
                    <p class="muted" style="margin: 4px 0 0 0;">When enabled, a webhook fires each time this token is hit (deduped per visitor per 5 minutes). Requires a Token Webhook URL in Settings.</p>
                </div>

                <div style="margin-bottom: 12px;">
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="include_in_email" value="1">
                        <span>Send email alert on hit</span>
                    </label>
                    <p class="muted" style="margin: 4px 0 0 0;">When enabled, an email fires each time this token is hit regardless of classification (deduped per IP per the configured window). Requires Email Alerting configured in Settings.</p>
                </div>

                <div style="margin-bottom: 12px;">
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="alert_on_first_hit" value="1">
                        <span>Flag first-hit alert context</span>
                    </label>
                </div>
                <label for="dormancy_alert_hours">Dormancy reactivation threshold (hours)</label>
                <input id="dormancy_alert_hours" type="number" min="0" name="dormancy_alert_hours" value="0">

                <button type="submit">Create token</button>
            </form>

            <?php if ($isDemo): ?>
                <div class="admin-advanced" style="padding: 12px;">
                    <h2>Create decoy endpoint pack</h2>
                    <p class="muted demo-lock-note">Not available in demo mode.</p>
                </div>
            <?php else: ?>
                <form method="post" action="/admin/create-decoy-pack">
                    <h2>Create decoy endpoint pack</h2>
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <label for="decoy_pack">Preset</label>
                    <select id="decoy_pack" name="pack">
                        <option value="baseline">Baseline</option>
                        <option value="wordpress">WordPress</option>
                        <option value="laravel">Laravel</option>
                        <option value="phpmyadmin">phpMyAdmin</option>
                        <option value="k8s">Kubernetes</option>
                        <option value="git">Git exposure</option>
                    </select>
                    <label for="decoy_destination">Destination URL</label>
                    <input id="decoy_destination" type="url" name="destination" required placeholder="https://www.example.com/">
                    <p class="muted">Creates multiple decoy tokens with forced threat-feed inclusion and token webhook enabled.</p>
                    <button type="submit">Create decoy pack</button>
                </form>
            <?php endif; ?>

            <h2>Token summary</h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>ID</th>
                        <th>Token / Path</th>
                        <th>Description</th>
                        <th>Campaign</th>
                        <th>State</th>
                        <th>Destination</th>
                        <th>Active</th>
			<th>Clicks</th>
                        <th>Excl. Feed</th>
                        <th>Force Feed</th>
                        <th>Webhook</th>
                        <th>Email</th>
                        <th>Health</th>
                        <th>Stale</th>
                        <th class="actions-col">Actions</th>
                    </tr>
		    <?php foreach ($links as $link): ?>
		<tr>
		    <td><?= (int) $link['id'] ?></td>
		    <td class="mono">
		        <a class="table-link mono-link" href="<?= h($buildDashboardUrl([
                            'token' => (string) $link['token'],
                            'hide_behavioral' => '1',
                            'hide_subdomains' => '1',
                            'page' => null,
                        ])) ?>">
		            <?= h((string) $link['token']) ?>
		        </a>
		    </td>
		    <td><?= h((string) ($link['description'] ?? '')) ?></td>
		    <td class="muted">
		        <?php if (!empty($link['campaign_name'])): ?>
		            <span class="badge badge-uncertain"><?= h((string) $link['campaign_name']) ?></span>
		        <?php else: ?>
		            —
		        <?php endif; ?>
		    </td>
                    <td><?= h((string) ($link['token_state'] ?? 'active')) ?></td>
		    <td class="wrap"><?= h((string) $link['destination']) ?></td>
		    <td><?= ((int) $link['active'] === 1) ? 'Yes' : 'No' ?></td>
		    <td><?= (int) $link['click_count'] ?></td>
		    <td>
		        <?php if ((int) ($link['exclude_from_feed'] ?? 0) === 1): ?>
		            <span class="badge badge-suspicious" title="IPs hitting this token are excluded from the threat feed">Yes</span>
		        <?php else: ?>
		            No
		        <?php endif; ?>
		    </td>
		    <td>
		        <?php if ((int) ($link['force_include_in_feed'] ?? 0) === 1): ?>
		            <span class="badge badge-bot" title="Any IP hitting this token is always in the threat feed">Yes</span>
		        <?php else: ?>
		            No
		        <?php endif; ?>
		    </td>
		    <td>
		        <?php if ((int) ($link['include_in_token_webhook'] ?? 0) === 1): ?>
		            <span class="badge badge-human" title="Token webhook fires on hit">Yes</span>
		        <?php else: ?>
		            No
		        <?php endif; ?>
		    </td>
		    <td>
		        <?php if ((int) ($link['include_in_email'] ?? 0) === 1): ?>
		            <span class="badge badge-human" title="Email alert fires on hit">Yes</span>
		        <?php else: ?>
		            No
		        <?php endif; ?>
		    </td>
                    <td>
                        <?php $healthCode = (int) ($link['last_health_http_code'] ?? 0); ?>
                        <?= $healthCode > 0 ? h((string) $healthCode) : '—' ?>
                    </td>
                    <td>
                        <?php
                        $lastHitMs = (int) ($link['last_clicked_at_unix_ms'] ?? 0);
                        $stale = ($staleTokenDays > 0 && $lastHitMs > 0) ? ((currentUnixMs() - $lastHitMs) > ($staleTokenDays * 86400000)) : false;
                        ?>
                        <?php if ($stale): ?>
                            <span class="badge badge-suspicious">stale</span>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>

		    <td class="actions-col actions-col--menu token-actions-cell">
                        <div class="action-menu" data-action-menu>
                            <?= renderActionMenuTrigger('Token actions') ?>
                            <div class="action-menu-panel" hidden>
                                <div class="action-menu-inner">
                                    <form method="get" action="/admin" class="inline-action-form action-menu-form">
                                        <input type="hidden" name="tab" value="links">
                                        <input type="hidden" name="edit_link_id" value="<?= (int) $link['id'] ?>">
                                        <button type="submit" class="action-menu-submit">Edit token</button>
                                    </form>
                                    <button type="button" class="action-menu-item" data-toggle-row="token-templates-<?= (int) $link['id'] ?>">Deployment templates</button>
                                    <?php if (!$isDemo): ?>
                                        <form method="post" action="/admin/check-link-health" class="inline-action-form action-menu-form">
                                            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                            <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
                                            <button type="submit" class="action-menu-submit">↻ Check link health</button>
                                        </form>
                                    <?php endif; ?>
                                    <?php if ((int) $link['active'] === 1): ?>
                                        <form method="post" action="/admin/deactivate-link" class="inline-action-form action-menu-form">
                                            <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
                                            <button type="submit" class="action-menu-submit">Deactivate token</button>
                                        </form>
                                    <?php else: ?>
                                        <form method="post" action="/admin/activate-link" class="inline-action-form action-menu-form">
                                            <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
                                            <button type="submit" class="action-menu-submit">Activate token</button>
                                        </form>
                                    <?php endif; ?>
                                    <form method="post" action="/admin/delete-link" class="inline-action-form action-menu-form" data-confirm="Delete this token/path?">
                                        <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
                                        <button type="submit" class="action-menu-submit">Delete token</button>
                                    </form>
                                    <form method="post" action="/admin/delete-link" class="inline-action-form action-menu-form" data-confirm="Delete this token/path and all related clicks?">
                                        <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
                                        <input type="hidden" name="delete_clicks" value="1">
                                        <button type="submit" class="danger-button action-menu-submit">Delete token + clicks</button>
                                    </form>
                                </div>
                            </div>
                        </div>
		    </td>
		</tr>
                <?php $tokenTemplates = buildTokenDeploymentSnippets($baseUrl, $link); ?>
                <tr id="token-templates-<?= (int) $link['id'] ?>" class="template-row" style="display:none;">
                    <td colspan="12" class="template-cell">
                        <div class="deployment-panel">
                            <strong class="template-title">Deployment Templates for <?= h(normalizeTokenPath((string) $link['token'])) ?></strong>
                            <div class="snippet-grid">
                                <?php foreach ($tokenTemplates as $snippetTitle => $snippetBody): ?>
                                    <?= renderSnippetBox($snippetTitle, $snippetBody) ?>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </td>
                </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>

	<div class="tab-content" id="content-asn">

	    <?php if ($editAsnRule !== null): ?>
	    <form method="post" action="/admin/update-asn-rule">
	        <h2>Edit ASN rule</h2>
	        <input type="hidden" name="id" value="<?= (int) $editAsnRule['id'] ?>">

	        <label for="edit_asn_asn">ASN</label>
	        <input id="edit_asn_asn" type="text" name="asn" required value="<?= h((string) $editAsnRule['asn']) ?>">

	        <label for="edit_asn_label">Label</label>
	        <input id="edit_asn_label" type="text" name="label" value="<?= h((string) ($editAsnRule['label'] ?? '')) ?>">

	        <label for="edit_asn_penalty">Penalty</label>
	        <input id="edit_asn_penalty" type="number" name="penalty" min="1" max="100" value="<?= (int) $editAsnRule['penalty'] ?>">

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="exclude_from_feed" value="1" <?= ((int) ($editAsnRule['exclude_from_feed'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Never add to threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">Score penalty still applies. Use this for your own infrastructure, CDNs, or monitoring services.</p>
	        </div>

	        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
	        <button type="submit">Save ASN rule</button>
	            <form method="get" action="/admin" class="inline-action-form">
	                <input type="hidden" name="tab" value="asn">
	                <button type="submit">Cancel</button>
	            </form>
	        </div>
	    </form>
	    <?php endif; ?>

	    <form method="post" action="/admin/create-asn-rule">
	        <h2>Create ASN rule</h2>
	        <label for="asn">ASN</label>
	        <input id="asn" type="text" name="asn" required placeholder="8075">
	        <label for="asn_label">Label</label>
	        <input id="asn_label" type="text" name="label" placeholder="Microsoft">
	        <label for="asn_penalty">Penalty</label>
	        <input id="asn_penalty" type="number" name="penalty" min="1" max="100" value="10">
	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="exclude_from_feed" value="1">
	                <span>Never add to threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">Score penalty still applies. Use this for your own infrastructure, CDNs, or monitoring services.</p>
	        </div>
	        <button type="submit">Add ASN rule</button>
	    </form>

	    <h2>ASN rules</h2>
	    <div class="table-wrap">
	        <table class="compact-table">
	            <tr>
	                <th>ID</th>
	                <th>ASN</th>
	                <th>Label</th>
	                <th>Penalty</th>
	                <th>Active</th>
	                <th>Excl. Feed</th>
	                <th class="actions-col">Actions</th>
	            </tr>
	            <?php foreach ($asnRules as $rule): ?>
	                <tr>
	                    <td><?= (int) $rule['id'] ?></td>
	                    <td class="mono"><?= h((string) $rule['asn']) ?></td>
	                    <td><?= h((string) ($rule['label'] ?? '')) ?></td>
	                    <td><?= (int) $rule['penalty'] ?></td>
	                    <td><?= ((int) $rule['active'] === 1) ? 'Yes' : 'No' ?></td>
	                    <td>
	                        <?php if ((int) ($rule['exclude_from_feed'] ?? 0) === 1): ?>
	                            <span class="badge badge-suspicious" title="This ASN will never appear in the threat feed">Yes</span>
	                        <?php else: ?>
	                            No
	                        <?php endif; ?>
	                    </td>
	                    <td class="actions-col actions-col--menu">
	                        <div class="action-menu" data-action-menu>
	                            <?= renderActionMenuTrigger('ASN rule actions') ?>
	                            <div class="action-menu-panel" hidden>
	                                <div class="action-menu-inner">
	                                    <form method="get" action="/admin" class="inline-action-form action-menu-form">
	                                        <input type="hidden" name="tab" value="asn">
	                                        <input type="hidden" name="edit_asn_rule_id" value="<?= (int) $rule['id'] ?>">
	                                        <button type="submit" class="action-menu-submit">Edit ASN rule</button>
	                                    </form>
	                                    <?php if ((int) $rule['active'] === 1): ?>
	                                        <form method="post" action="/admin/deactivate-asn-rule" class="inline-action-form action-menu-form">
	                                            <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
	                                            <button type="submit" class="action-menu-submit">Deactivate ASN rule</button>
	                                        </form>
	                                    <?php else: ?>
	                                        <form method="post" action="/admin/activate-asn-rule" class="inline-action-form action-menu-form">
	                                            <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
	                                            <button type="submit" class="action-menu-submit">Activate ASN rule</button>
	                                        </form>
	                                    <?php endif; ?>
	                                    <form method="post" action="/admin/delete-asn-rule" class="inline-action-form action-menu-form" data-confirm="Delete this ASN rule?">
	                                        <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
	                                        <button type="submit" class="danger-button action-menu-submit">Delete ASN rule</button>
	                                    </form>
	                                </div>
	                            </div>
	                        </div>
	                    </td>
	                </tr>
	            <?php endforeach; ?>
	        </table>
	    </div>
	</div>

        <div class="tab-content" id="content-countries">

            <?php if ($editCountryRule !== null): ?>
            <form method="post" action="/admin/update-country-rule">
                <h2>Edit country rule</h2>
                <input type="hidden" name="id" value="<?= (int) $editCountryRule['id'] ?>">

                <label for="edit_country_code">Country Code</label>
                <input id="edit_country_code" type="text" name="country_code" required maxlength="2" style="text-transform:uppercase;" value="<?= h((string) $editCountryRule['country_code']) ?>">

                <label for="edit_country_label">Label (optional)</label>
                <input id="edit_country_label" type="text" name="label" value="<?= h((string) ($editCountryRule['label'] ?? '')) ?>" placeholder="e.g. High-risk region">

                <label for="edit_country_penalty">Score Penalty (1–100)</label>
                <input id="edit_country_penalty" type="number" name="penalty" min="1" max="100" value="<?= (int) $editCountryRule['penalty'] ?>">

                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                    <button type="submit">Save country rule</button>
                    <form method="get" action="/admin" class="inline-action-form">
                        <input type="hidden" name="tab" value="countries">
                        <button type="submit">Cancel</button>
                    </form>
                </div>
            </form>
            <?php endif; ?>

            <form method="post" action="/admin/create-country-rule">
                <h2>Add country rule</h2>
                <p class="muted">Applies a score penalty to all requests from the specified country. Use 2-letter ISO country codes (for example, CN, RU, KP). Only affects scoring and does not exclude IPs from the threat feed.</p>

                <label for="country_code">Country Code</label>
                <input id="country_code" type="text" name="country_code" required maxlength="2" style="text-transform:uppercase; width: 80px;" placeholder="CN">

                <label for="country_label">Label (optional)</label>
                <input id="country_label" type="text" name="label" placeholder="e.g. High-risk region">

                <label for="country_penalty">Score Penalty (1–100)</label>
                <input id="country_penalty" type="number" name="penalty" min="1" max="100" value="15">

                <button type="submit">Add country rule</button>
            </form>

            <h2>Country rules</h2>
            <?php if (empty($countryRules)): ?>
                <p class="muted">No country rules configured.</p>
            <?php else: ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>Code</th>
                        <th>Label</th>
                        <th>Penalty</th>
                        <th>Active</th>
                        <th>Created</th>
                        <th class="actions-col">Actions</th>
                    </tr>
                    <?php foreach ($countryRules as $rule): ?>
                        <tr>
                            <td class="mono"><?= h((string) $rule['country_code']) ?></td>
                            <td><?= h((string) ($rule['label'] ?? '')) ?></td>
                            <td>-<?= (int) $rule['penalty'] ?></td>
                            <td><?= ((int) $rule['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td><?= h((string) ($rule['created_at'] ?? '')) ?></td>
                            <td class="actions-col actions-col--menu">
                                <div class="action-menu" data-action-menu>
                                    <?= renderActionMenuTrigger('Country rule actions') ?>
                                    <div class="action-menu-panel" hidden>
                                        <div class="action-menu-inner">
                                            <form method="get" action="/admin" class="inline-action-form action-menu-form">
                                                <input type="hidden" name="tab" value="countries">
                                                <input type="hidden" name="edit_country_id" value="<?= (int) $rule['id'] ?>">
                                                <button type="submit" class="action-menu-submit">Edit country rule</button>
                                            </form>
                                            <?php if ((int) $rule['active'] === 1): ?>
                                                <form method="post" action="/admin/deactivate-country-rule" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
                                                    <button type="submit" class="action-menu-submit">Deactivate country rule</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" action="/admin/activate-country-rule" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
                                                    <button type="submit" class="action-menu-submit">Activate country rule</button>
                                                </form>
                                            <?php endif; ?>
                                            <form method="post" action="/admin/delete-country-rule" class="inline-action-form action-menu-form" data-confirm="Delete this country rule?">
                                                <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
                                                <button type="submit" class="danger-button action-menu-submit">Delete country rule</button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>
        </div>

        <div class="tab-content" id="content-overrides">

            <?php if ($editOverride !== null): ?>
            <form method="post" action="/admin/update-ip-override">
                <h2>Edit IP override</h2>
                <input type="hidden" name="id" value="<?= (int) $editOverride['id'] ?>">

                <label for="edit_override_ip">IP Address</label>
                <input id="edit_override_ip" type="text" name="ip" required value="<?= h((string) $editOverride['ip']) ?>">

                <label for="edit_override_mode">Mode</label>
                <select id="edit_override_mode" name="mode">
                    <option value="none"  <?= $editOverride['mode'] === 'none'  ? 'selected' : '' ?>>None — score normally (use for hide-only overrides)</option>
                    <option value="block" <?= $editOverride['mode'] === 'block' ? 'selected' : '' ?>>Block — always classify as bot (score 0)</option>
                    <option value="allow" <?= $editOverride['mode'] === 'allow' ? 'selected' : '' ?>>Allow — always classify as human (score 100)</option>
                    <option value="feed_include" <?= $editOverride['mode'] === 'feed_include' ? 'selected' : '' ?>>Always include in threat feed</option>
                    <option value="feed_exclude" <?= $editOverride['mode'] === 'feed_exclude' ? 'selected' : '' ?>>Never include in threat feed</option>
                </select>

                <label>
                    <input type="checkbox" name="hide_from_dashboard" value="1" <?= ((int) ($editOverride['hide_from_dashboard'] ?? 0) === 1) ? 'checked' : '' ?>>
                    Hide from dashboard — suppress this IP from the activity feed (still logged &amp; scored normally)
                </label>

                <label for="edit_override_notes">Notes</label>
                <input id="edit_override_notes" type="text" name="notes" value="<?= h((string) ($editOverride['notes'] ?? '')) ?>" placeholder="Optional note">

                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                    <button type="submit">Save IP override</button>
                    <form method="get" action="/admin" class="inline-action-form">
                        <input type="hidden" name="tab" value="overrides">
                        <button type="submit">Cancel</button>
                    </form>
                </div>
            </form>
            <?php endif; ?>

            <form method="post" action="/admin/create-ip-override">
                <h2>Add IP override</h2>
                <p class="muted">Block/allow modes bypass scoring entirely. Feed modes force include/exclude behavior without changing scoring. You can also hide the IP from the dashboard activity feed; it is still logged and scored. Applies to future requests only.</p>

                <label for="override_ip">IP Address</label>
                <input id="override_ip" type="text" name="ip" required placeholder="1.2.3.4 or 2001:db8::1">

                <label for="override_mode">Mode</label>
                <select id="override_mode" name="mode">
                    <option value="none">None — score normally (use for hide-only overrides)</option>
                    <option value="block">Block — always classify as bot (score 0)</option>
                    <option value="allow">Allow — always classify as human (score 100)</option>
                    <option value="feed_include">Always include in threat feed</option>
                    <option value="feed_exclude">Never include in threat feed</option>
                </select>

                <label>
                    <input type="checkbox" name="hide_from_dashboard" value="1">
                    Hide from dashboard — suppress from activity feed (still logged &amp; scored)
                </label>

                <label for="override_notes">Notes</label>
                <input id="override_notes" type="text" name="notes" placeholder="Optional note (e.g. monitoring service, your office IP)">

                <button type="submit">Add IP override</button>
            </form>

            <h2>IP overrides</h2>
            <?php if (empty($ipOverrides)): ?>
                <p class="muted">No IP overrides configured.</p>
            <?php else: ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>IP</th>
                        <th>Mode</th>
                        <th>Hidden</th>
                        <th>Notes</th>
                        <th>Active</th>
                        <th>Created</th>
                        <th class="actions-col">Actions</th>
                    </tr>
                    <?php foreach ($ipOverrides as $override): ?>
                        <tr>
                            <td class="mono"><?= h((string) $override['ip']) ?></td>
                            <td>
                                <?php if ($override['mode'] === 'block'): ?>
                                    <span class="badge badge-bot">block</span>
                                <?php elseif ($override['mode'] === 'allow'): ?>
                                    <span class="badge badge-human">allow</span>
                                <?php elseif ($override['mode'] === 'feed_include'): ?>
                                    <span class="badge badge-suspicious">feed include</span>
                                <?php elseif ($override['mode'] === 'feed_exclude'): ?>
                                    <span class="badge badge-muted">feed exclude</span>
                                <?php else: ?>
                                    <span class="badge badge-muted">none</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ((int) ($override['hide_from_dashboard'] ?? 0) === 1): ?>
                                    <span class="badge badge-muted">hidden</span>
                                <?php else: ?>
                                    <span class="muted">—</span>
                                <?php endif; ?>
                            </td>
                            <td><?= h((string) ($override['notes'] ?? '')) ?></td>
                            <td><?= ((int) $override['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td><?= h((string) ($override['created_at'] ?? '')) ?></td>
                            <td class="actions-col actions-col--menu">
                                <div class="action-menu" data-action-menu>
                                    <?= renderActionMenuTrigger('IP override actions') ?>
                                    <div class="action-menu-panel" hidden>
                                        <div class="action-menu-inner">
                                            <form method="get" action="/admin" class="inline-action-form action-menu-form">
                                                <input type="hidden" name="tab" value="overrides">
                                                <input type="hidden" name="edit_override_id" value="<?= (int) $override['id'] ?>">
                                                <button type="submit" class="action-menu-submit">Edit IP override</button>
                                            </form>
                                            <?php if ((int) $override['active'] === 1): ?>
                                                <form method="post" action="/admin/deactivate-ip-override" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="id" value="<?= (int) $override['id'] ?>">
                                                    <button type="submit" class="action-menu-submit">Deactivate IP override</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" action="/admin/activate-ip-override" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="id" value="<?= (int) $override['id'] ?>">
                                                    <button type="submit" class="action-menu-submit">Activate IP override</button>
                                                </form>
                                            <?php endif; ?>
                                            <form method="post" action="/admin/delete-ip-override" class="inline-action-form action-menu-form" data-confirm="Delete this IP override?">
                                                <input type="hidden" name="id" value="<?= (int) $override['id'] ?>">
                                                <button type="submit" class="danger-button action-menu-submit">Delete IP override</button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>
        </div>

        <div class="tab-content" id="content-settings">
            <div class="two-column-settings">
                <form method="post" action="/admin/save-settings">
                    <h2>Settings</h2>

                    <label for="app_name">App Name</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= h((string) $appName) ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="app_name" type="text" name="app_name" value="<?= h((string) $appName) ?>" required>
                    <?php endif; ?>

                    <label for="base_url">Base URL</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= h((string) $baseUrl) ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="base_url" type="url" name="base_url" value="<?= h((string) $baseUrl) ?>" placeholder="https://yourdomain.example">
                    <?php endif; ?>

                    <label for="default_redirect_url">Default Redirect URL</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= h((string) $defaultRedirectUrl) ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="default_redirect_url" type="url" name="default_redirect_url" value="<?= h((string) $defaultRedirectUrl) ?>" required>
                    <?php endif; ?>

                    <label for="unknown_path_behavior">Unknown Path Behavior</label>
                    <select id="unknown_path_behavior" name="unknown_path_behavior">
                        <option value="redirect" <?= $unknownPathBehavior === 'redirect' ? 'selected' : '' ?>>Redirect</option>
                        <option value="404" <?= $unknownPathBehavior === '404' ? 'selected' : '' ?>>404</option>
                    </select>

                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field">
                            Adaptive deception responses: <?= $adaptiveDeceptionEnabled ? 'Enabled' : 'Disabled' ?>
                            <span class="demo-lock-note">Not configurable in demo mode</span>
                        </div>
                    <?php else: ?>
                        <label style="display: inline-flex; align-items: center; gap: 6px; margin: 8px 0;">
                            <input type="checkbox" name="adaptive_deception_enabled" value="1" <?= $adaptiveDeceptionEnabled ? 'checked' : '' ?>>
                            <span>Adaptive deception responses for suspicious unknown hits</span>
                        </label>
                    <?php endif; ?>
                    <p class="muted">When enabled, suspicious scans can receive realistic decoy responses (fake env/login/API errors) instead of redirect/404.</p>

                    <label for="stale_token_days">Stale token threshold (days)</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= (int) $staleTokenDays ?> days <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="stale_token_days" type="number" min="0" max="3650" name="stale_token_days" value="<?= (int) $staleTokenDays ?>">
                    <?php endif; ?>
                    <p class="muted">Used by token summary watchdog badges. Set 0 to disable stale detection.</p>

		    <div style="margin-bottom: 12px;">
                         <label style="display: inline-flex; align-items: center; gap: 6px; margin-right: 16px;">
			        <input type="checkbox" name="noise_filter_enabled" value="1" <?= $noiseFilterEnabled ? 'checked' : '' ?>>
			        <span>Noise filter enabled</span>
		         </label>
                <?php if ($isDemo): ?>
                    <span class="demo-locked-field" style="display:inline-flex; align-items:center; gap:6px; padding:7px 10px;">
                        <?= $wildcardMode ? 'Wildcard DNS mode: Enabled' : 'Wildcard DNS mode: Disabled' ?>
                        <span class="demo-lock-note">Not configurable in demo mode</span>
                    </span>
                <?php else: ?>
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="wildcard_mode" value="1" <?= $wildcardMode ? 'checked' : '' ?>>
                        <span>Wildcard DNS mode</span>
                    </label>
                <?php endif; ?>
		   </div>
                   <p class="muted">Wildcard DNS mode shows a Subdomain column in the activity table and enables host/subdomain filtering. Enable this when using a wildcard DNS record to capture traffic across multiple subdomains.</p>

		   <label for="display_min_score">Minimum Display Score</label>
		   <input id="display_min_score" type="number"  min="0" max="100" name="display_min_score" value="<?= h((string) getSetting($pdo, 'display_min_score', '20')) ?>">

		   <p class="muted">Hide lower-scored events from the dashboard unless “Show all” is checked.</p>

                    <details class="admin-advanced">
                    <summary>Dashboard layout &amp; behavioral panels</summary>

		   <label for="page_size">Rows Per Page</label>
		   <input id="page_size" type="number" min="10" max="500" name="page_size" value="<?= h($pageSizeSetting) ?>">
		   <p class="muted">Number of activity rows shown per page (10-500).</p>

		   <label for="auto_refresh_secs">Auto-Refresh Interval (seconds)</label>
		   <input id="auto_refresh_secs" type="number" min="0" name="auto_refresh_secs" value="<?= h((string) $autoRefreshSecs) ?>">
		   <p class="muted">Reload the dashboard after this many seconds. Set to 0 to disable.</p>

		   <label for="behavioral_window_hours">Behavioral Flags Window (hours)</label>
		   <input id="behavioral_window_hours" type="number" min="1" max="168" name="behavioral_window_hours" value="<?= h((string) $behavioralWindowHours) ?>">
		   <p class="muted">How far back to look for burst, rapid-repeat, and multi-token signals. Default 24h.</p>

		   <label for="behavioral_max_rows">Behavioral Flags Max Rows</label>
		   <input id="behavioral_max_rows" type="number" min="1" max="200" name="behavioral_max_rows" value="<?= h((string) $behavioralMaxRows) ?>">
		   <p class="muted">Maximum number of IPs shown in the Behaviorally Flagged IPs panel. Default 25.</p>

		   <div style="margin-bottom: 12px; margin-top: 4px;">
		       <label style="display: inline-flex; align-items: center; gap: 6px;">
		           <input type="checkbox" name="behavioral_hidden" value="1" <?= $behavioralHidden ? 'checked' : '' ?>>
		           <span>Hide Behavioral Flags panel by default</span>
		       </label>
		       <p class="muted" style="margin-top: 4px;">When enabled, the panel starts collapsed on page load. You can still expand it manually.</p>
		   </div>

		   <div style="margin-bottom: 12px; margin-top: 4px;">
		       <label style="display: inline-flex; align-items: center; gap: 6px;">
		           <input type="checkbox" name="subdomains_hidden" value="1" <?= $subdomainsHidden ? 'checked' : '' ?>>
		           <span>Hide Subdomain Activity panel by default</span>
		       </label>
		       <p class="muted" style="margin-top: 4px;">When enabled, the subdomain summary starts collapsed on page load. Only applies when Wildcard DNS mode is on.</p>
		   </div>

                    </details>

                    <details class="admin-advanced">
                    <summary>Threat &amp; token webhooks</summary>

		   <label for="webhook_url">Threat Webhook URL</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= h($webhookUrl) ?: '(not set)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <div style="display:flex;gap:0.5rem;align-items:center;">
		           <input id="webhook_url" type="url" name="webhook_url" value="<?= h($webhookUrl) ?>" placeholder="https://hooks.slack.com/..." style="flex:1;">
		           <button type="button" class="btn-small" id="test-threat-webhook" <?= $webhookUrl === '' ? 'disabled' : '' ?>>Test</button>
		       </div>
		       <span id="test-threat-webhook-result" style="font-size:0.8125rem;margin-top:4px;display:none;"></span>
		   <?php endif; ?>
		   <p class="muted">Fires when an unknown-path hit meets the threshold below. Use the preset dropdown to populate a template for your platform.</p>

		   <label for="webhook_preset">Threat Webhook Platform Preset</label>
		   <?php if (!$isDemo): ?>
		   <select id="webhook_preset" data-type="threat" data-target="webhook_template">
		       <option value="">— select a preset to load a template —</option>
		       <option value="slack">Slack</option>
		       <option value="discord">Discord</option>
		       <option value="teams">Microsoft Teams</option>
		       <option value="pagerduty">PagerDuty</option>
		       <option value="custom">Custom (generic JSON)</option>
		   </select>
		   <p class="muted">Selecting a preset overwrites the template below. Save settings to apply.</p>
		   <?php endif; ?>

		   <label for="webhook_template">Threat Webhook Payload Template (optional)</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= $webhookTemplate !== '' ? h($webhookTemplate) : '(none)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <textarea id="webhook_template" name="webhook_template" rows="8" style="font-family: var(--font-mono); font-size: 0.8125rem; width: 100%; resize: vertical;" placeholder='{"event": "signaltrace_alert", "ip": "{{ip}}", "label": "{{label}}", "score": {{score}}}'><?= h($webhookTemplate) ?></textarea>
		   <?php endif; ?>
		   <p class="muted">
		       JSON template with placeholders. When set, overrides auto-detection.<br>
		       Available: <code>{{ip}}</code> <code>{{token}}</code> <code>{{label}}</code> <code>{{score}}</code> <code>{{org}}</code> <code>{{asn}}</code> <code>{{country}}</code> <code>{{ua}}</code> <code>{{time}}</code> <code>{{triggers}}</code>
		   </p>

		   <label for="webhook_threshold">Threat Webhook Threshold</label>
		   <select id="webhook_threshold" name="webhook_threshold">
		       <?php $webhookThreshold = (string) getSetting($pdo, 'webhook_threshold', 'bot'); ?>
		       <option value="bot"        <?= $webhookThreshold === 'bot'        ? 'selected' : '' ?>>bot only</option>
		       <option value="suspicious" <?= $webhookThreshold === 'suspicious' ? 'selected' : '' ?>>suspicious and above</option>
		       <option value="uncertain"  <?= $webhookThreshold === 'uncertain'  ? 'selected' : '' ?>>uncertain and above</option>
		       <option value="human"      <?= $webhookThreshold === 'human'      ? 'selected' : '' ?>>all hits</option>
		   </select>
		   <p class="muted">Minimum classification to trigger the threat webhook. Does not apply to known token hits — those use the token webhook below.</p>

		   <label for="token_webhook_url">Token Webhook URL</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= h($tokenWebhookUrl) ?: '(not set)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <div style="display:flex;gap:0.5rem;align-items:center;">
		           <input id="token_webhook_url" type="url" name="token_webhook_url" value="<?= h($tokenWebhookUrl) ?>" placeholder="https://hooks.slack.com/..." style="flex:1;">
		           <button type="button" class="btn-small" id="test-token-webhook" <?= $tokenWebhookUrl === '' ? 'disabled' : '' ?>>Test</button>
		       </div>
		       <span id="test-token-webhook-result" style="font-size:0.8125rem;margin-top:4px;display:none;"></span>
		   <?php endif; ?>
		   <p class="muted">Fires when any known tracked token is hit, regardless of classification. Deduplicates per visitor per token per 5 minutes.</p>

		   <label for="token_webhook_preset">Token Webhook Platform Preset</label>
		   <?php if (!$isDemo): ?>
		   <select id="token_webhook_preset" data-type="token" data-target="token_webhook_template">
		       <option value="">— select a preset to load a template —</option>
		       <option value="slack">Slack</option>
		       <option value="discord">Discord</option>
		       <option value="teams">Microsoft Teams</option>
		       <option value="pagerduty">PagerDuty</option>
		       <option value="custom">Custom (generic JSON)</option>
		   </select>
		   <p class="muted">Selecting a preset overwrites the template below. Save settings to apply.</p>
		   <?php endif; ?>

		   <label for="token_webhook_template">Token Webhook Payload Template (optional)</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= $tokenWebhookTemplate !== '' ? h($tokenWebhookTemplate) : '(none)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <textarea id="token_webhook_template" name="token_webhook_template" rows="8" style="font-family: var(--font-mono); font-size: 0.8125rem; width: 100%; resize: vertical;" placeholder='{"event": "signaltrace_token_hit", "ip": "{{ip}}", "token": "{{token}}", "label": "{{label}}", "score": {{score}}}'><?= h($tokenWebhookTemplate) ?></textarea>
		   <?php endif; ?>
		   <p class="muted">
		       Same placeholder syntax as the threat webhook. Leave blank for auto-detected Slack/Discord format or generic JSON.<br>
		       Available: <code>{{ip}}</code> <code>{{token}}</code> <code>{{label}}</code> <code>{{score}}</code> <code>{{org}}</code> <code>{{asn}}</code> <code>{{country}}</code> <code>{{ua}}</code> <code>{{time}}</code> <code>{{triggers}}</code>
		   </p>

                    </details>

                    <details class="admin-advanced">
                    <summary>Email alerting</summary>

		   <?php
		   $smtpConfigured = defined('EMAIL_SMTP_HOST') && EMAIL_SMTP_HOST !== ''
		                  && defined('EMAIL_SMTP_USER') && EMAIL_SMTP_USER !== ''
		                  && defined('EMAIL_SMTP_PASS') && EMAIL_SMTP_PASS !== '';
		   ?>

		   <?php if ($smtpConfigured): ?>

		   <div style="padding: 0.75rem 1rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 1rem;">
		       <p class="muted" style="margin-bottom: 0.5rem;">SMTP credentials are configured in <code>config.local.php</code>.</p>
		       <div style="display: flex; flex-wrap: wrap; gap: 0.4rem;">
		           <span class="badge badge-human">Host: <?= h((string) EMAIL_SMTP_HOST) ?></span>
		           <span class="badge badge-human">Port: <?= defined('EMAIL_SMTP_PORT') ? (int) EMAIL_SMTP_PORT : 587 ?></span>
		           <span class="badge badge-human">Encryption: <?= defined('EMAIL_SMTP_ENCRYPTION') ? h((string) EMAIL_SMTP_ENCRYPTION) : 'tls' ?></span>
		           <span class="badge badge-human">User: <?= h((string) EMAIL_SMTP_USER) ?></span>
		           <span class="badge badge-human">From: <?= defined('EMAIL_SMTP_FROM') && EMAIL_SMTP_FROM !== '' ? h((string) EMAIL_SMTP_FROM) : '(same as user)' ?></span>
		           <span class="badge badge-human">Password: ••••••••</span>
		       </div>
		   </div>

		   <div style="margin-bottom: 12px;">
		       <label style="display: inline-flex; align-items: center; gap: 6px;">
		           <?php if ($isDemo): ?>
		               <input type="checkbox" disabled <?= getSetting($pdo, 'email_enabled', '0') === '1' ? 'checked' : '' ?>>
		               <span>Email alerting enabled <span class="demo-lock-note">Not configurable in demo mode</span></span>
		           <?php else: ?>
		               <input type="checkbox" name="email_enabled" value="1" <?= getSetting($pdo, 'email_enabled', '0') === '1' ? 'checked' : '' ?>>
		               <span>Email alerting enabled</span>
		           <?php endif; ?>
		       </label>
		   </div>

		   <label for="email_to">Recipient Address</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= h((string) getSetting($pdo, 'email_to', '')) ?: '(not set)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <input id="email_to" type="email" name="email_to" value="<?= h((string) getSetting($pdo, 'email_to', '')) ?>" placeholder="alerts@yourdomain.example">
		   <?php endif; ?>

		   <label for="email_threshold">Alert Threshold</label>
		   <?php $emailThreshold = (string) getSetting($pdo, 'email_threshold', 'bot'); ?>
		   <select id="email_threshold" name="email_threshold">
		       <option value="bot"        <?= $emailThreshold === 'bot'        ? 'selected' : '' ?>>bot only</option>
		       <option value="suspicious" <?= $emailThreshold === 'suspicious' ? 'selected' : '' ?>>suspicious and above</option>
		       <option value="uncertain"  <?= $emailThreshold === 'uncertain'  ? 'selected' : '' ?>>uncertain and above</option>
		       <option value="all"        <?= $emailThreshold === 'all'        ? 'selected' : '' ?>>all hits</option>
		   </select>
		   <p class="muted">Minimum classification label to trigger an email alert for unknown-path hits. Per-token email alerts fire on any hit regardless of this threshold.</p>

		   <label for="email_dedup_minutes">Deduplication Window (minutes)</label>
		   <input id="email_dedup_minutes" type="number" min="1" name="email_dedup_minutes" value="<?= h((string) getSetting($pdo, 'email_dedup_minutes', '60')) ?>">
		   <p class="muted">Suppresses repeat alerts for the same IP within this window. Default 60 minutes.</p>

		   <?php else: ?>

		   <div style="padding: 0.75rem 1rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 0.75rem;">
		       <span class="badge badge-suspicious">Not configured</span>
		       <p class="muted" style="margin-top: 0.5rem; margin-bottom: 0;">SMTP credentials must be set in <code>config.local.php</code> — they are not stored in the database. Define <code>EMAIL_SMTP_HOST</code>, <code>EMAIL_SMTP_PORT</code>, <code>EMAIL_SMTP_ENCRYPTION</code>, <code>EMAIL_SMTP_USER</code>, <code>EMAIL_SMTP_PASS</code>, and <code>EMAIL_SMTP_FROM</code> as constants. See <code>config.local.php.example</code> for the format. Run <code>setup.sh</code> to be prompted for these values. Email alerting will not send until SMTP is configured.</p>
		   </div>

		   <?php endif; ?>

                    </details>

                    <details class="admin-advanced">
                    <summary>Exports &amp; API endpoints</summary>

		   <label for="export_min_confidence">Export minimum classification</label>
		   <select id="export_min_confidence" name="export_min_confidence">
		       <option value="human"        <?= $exportMinConf === 'human'        ? 'selected' : '' ?>>human</option>
		       <option value="uncertain" <?= $exportMinConf === 'uncertain' ? 'selected' : '' ?>>uncertain</option>
		       <option value="suspicious"   <?= $exportMinConf === 'suspicious'   ? 'selected' : '' ?>>suspicious</option>
		       <option value="bot"          <?= $exportMinConf === 'bot'          ? 'selected' : '' ?>>bot</option>
		   </select>
		   <p class="muted">Minimum classification label for exports when no dashboard filters are active.</p>

		   <label for="export_min_score">Export Minimum Score (0–100)</label>
		   <input id="export_min_score" type="number" min="0" max="100" name="export_min_score" value="<?= h($exportMinScore) ?>">
		   <p class="muted">Minimum numeric confidence score for exports. Acts as a second filter alongside the label — both conditions must be met. Set to 0 to disable score filtering.</p>

		   <label for="export_window_hours">Export Time Window (hours)</label>
		   <input id="export_window_hours" type="number" min="1" name="export_window_hours" value="<?= h($exportWinHours) ?>">
		   <p class="muted">How far back to look when no date filters are active (168 = 7 days). Use 87600 to export everything.</p>

		   <?php if ($baseUrl !== ''): ?>
		   <div style="margin-top: 1rem; padding: 0.875rem 1rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius);">
		       <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.6rem;">Export Endpoints</strong>
		       <p class="muted" style="margin-bottom: 0.5rem;">Authenticate with admin Basic Auth, or set <code>EXPORT_API_TOKEN</code> in <code>config.local.php</code> and use <code>Authorization: Bearer YOUR_TOKEN</code> (recommended — not logged) or <code>?api_key=YOUR_TOKEN</code> (appears in access logs).</p>
		       <div style="margin-bottom: 0.4rem;">
		           <span class="mono"><?= h(rtrim($baseUrl, '/') . '/export/json') ?></span>
		           <button type="button" class="copy-button" data-copy="<?= h(rtrim($baseUrl, '/') . '/export/json') ?>">Copy</button>
		       </div>
		       <div>
		           <span class="mono"><?= h(rtrim($baseUrl, '/') . '/export/csv') ?></span>
		           <button type="button" class="copy-button" data-copy="<?= h(rtrim($baseUrl, '/') . '/export/csv') ?>">Copy</button>
		       </div>
		   </div>
		   <?php endif; ?>

                    </details>

                    <details class="admin-advanced">
                    <summary>IP enrichment (AbuseIPDB)</summary>

		   <?php
		   $abuseKey      = (string) getSetting($pdo, 'abuseipdb_api_key', '');
		   $abuseLimit    = (string) getSetting($pdo, 'abuseipdb_daily_limit', '500');
		   $abuseKeySet   = $abuseKey !== '';
		   ?>

		   <label>AbuseIPDB API Key</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field">••••••••<span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <?php if ($abuseKeySet): ?>
		       <div style="display:flex; gap:0.5rem; align-items:center; margin-bottom:4px;">
		           <span class="mono" style="flex:1; padding: 7px 10px; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius); font-size:0.8125rem;">••••••••<?= h(substr($abuseKey, -4)) ?></span>
		           <button type="button" class="btn-small" id="abuseipdb-change-key">Change Key</button>
		       </div>
		       <div id="abuseipdb-key-input" style="display:none;">
		           <input type="password" name="abuseipdb_api_key" id="abuseipdb_api_key" value="" placeholder="Paste new API key" autocomplete="off">
		           <p class="muted" style="margin-top:4px;">Leave blank to keep the existing key.</p>
		       </div>
		       <?php else: ?>
		       <input type="password" name="abuseipdb_api_key" id="abuseipdb_api_key" value="" placeholder="Your AbuseIPDB v2 API key" autocomplete="off">
		       <p class="muted">Get a free key at <a href="https://www.abuseipdb.com/register" target="_blank" rel="noopener">abuseipdb.com</a>. Free tier allows 1,000 checks per day. Leave blank to disable AbuseIPDB enrichment.</p>
		       <?php endif; ?>
		   <?php endif; ?>

		   <label for="abuseipdb_daily_limit">AbuseIPDB Daily Lookup Limit</label>
		   <input id="abuseipdb_daily_limit" type="number" min="0" max="9999" name="abuseipdb_daily_limit" value="<?= h($abuseLimit) ?>">
		   <p class="muted">Maximum AbuseIPDB lookups per day. Once reached, new IPs will show Shodan data only until the next UTC midnight reset. Set to 0 to disable. Free tier limit is 1,000/day.</p>

		   <?php
		   $abuseUsedToday = (int) getSetting($pdo, 'abuseipdb_used_today', '0');
		   $abuseResetDate = (string) getSetting($pdo, 'abuseipdb_reset_date', '');
		   if ($abuseKeySet): ?>
		   <div style="padding: 0.5rem 0.75rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius); font-size: 0.8125rem; color: var(--text-sec);">
		       Today's usage: <strong><?= $abuseUsedToday ?></strong> / <?= h($abuseLimit) ?> lookups
		       <?php if ($abuseResetDate !== ''): ?>
		       — resets at UTC midnight
		       <?php endif; ?>
		   </div>
		   <?php endif; ?>

                    </details>

                    <button type="submit">Save settings</button>
                </form>

                <div>
                    <form method="post" action="/admin/save-threat-feed-settings">
                        <h2>Threat Feed</h2>

                        <label>
                            <input type="checkbox" name="threat_feed_enabled" value="1" <?= $threatFeedEnabled ? 'checked' : '' ?>>
                            Enable threat feed
                        </label>

                        <label for="threat_feed_window_hours">Keep IPs on feed for this many hours</label>
                        <input id="threat_feed_window_hours" type="number" min="1" name="threat_feed_window_hours" value="<?= h($threatFeedWindowHours) ?>">

                        <label for="threat_feed_min_confidence">Minimum confidence to include</label>
                        <select id="threat_feed_min_confidence" name="threat_feed_min_confidence">
                            <option value="human"      <?= $threatFeedMinConfidence === 'human'      ? 'selected' : '' ?>>human</option>
                            <option value="uncertain"  <?= $threatFeedMinConfidence === 'uncertain'  ? 'selected' : '' ?>>uncertain</option>
                            <option value="suspicious" <?= $threatFeedMinConfidence === 'suspicious' ? 'selected' : '' ?>>suspicious</option>
                            <option value="bot"        <?= $threatFeedMinConfidence === 'bot'        ? 'selected' : '' ?>>bot</option>
                        </select>

                        <label for="threat_feed_min_hits">Minimum hits before adding to feed</label>
                        <input id="threat_feed_min_hits" type="number" min="1" name="threat_feed_min_hits" value="<?= h($threatFeedMinHits) ?>">
                        <p class="muted">An IP must be seen at least this many times within the window before appearing in the feed. Set to 1 to include on first hit.</p>

                        <button type="submit">Save threat feed settings</button>
                    </form>

                    <?php
                    $feedCount = getThreatFeedCount($pdo);
                    ?>
                    <details class="admin-advanced">
                    <summary>Feed URLs &amp; intel exports</summary>
                    <div style="margin-top: 1rem; padding: 0.875rem 1rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius);">
                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.6rem;">
                            Feed Preview
                        </strong>
                        <p class="muted" style="margin-bottom: 0.75rem;">
                            Currently <strong><?= (int) $feedCount['ipv4'] ?></strong> IPv4
                            and <strong><?= (int) $feedCount['ipv6'] ?></strong> IPv6
                            addresses in the feed
                            (<?= (int) $feedCount['total'] ?> total).
                        </p>

                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.5rem;">IPv4 Feeds</strong>
                        <?php
                        $ipv4Feeds = [
                            'Plain text'    => '/feed/ips.txt',
                            'Nginx deny'    => '/feed/ips.nginx',
                            'iptables'      => '/feed/ips.iptables',
                            'CIDR (/32)'    => '/feed/ips.cidr',
                        ];
                        $ipv6Feeds = [
                            'Plain text'    => '/feed/ipv6.txt',
                            'Nginx deny'    => '/feed/ipv6.nginx',
                            'ip6tables'     => '/feed/ipv6.iptables',
                            'CIDR (/128)'   => '/feed/ipv6.cidr',
                        ];
                        foreach ($ipv4Feeds as $label => $feedPath):
                            $fullUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . $feedPath;
                        ?>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <span style="font-size: 0.75rem; color: var(--text-secondary); min-width: 90px;"><?= h($label) ?></span>
                            <span class="mono" style="font-size: 0.75rem;"><?= h($fullUrl) ?></span>
                            <button type="button" class="copy-button" data-copy="<?= h($fullUrl) ?>">Copy</button>
                            <?php if ($baseUrl !== ''): ?>
                                <a class="copy-button" href="<?= h($fullUrl) ?>" target="_blank" rel="noopener">Open</a>
                            <?php endif; ?>
                        </div>
                        <?php endforeach; ?>

                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-top: 0.75rem; margin-bottom: 0.5rem;">IPv6 Feeds</strong>
                        <?php foreach ($ipv6Feeds as $label => $feedPath):
                            $fullUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . $feedPath;
                        ?>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <span style="font-size: 0.75rem; color: var(--text-secondary); min-width: 90px;"><?= h($label) ?></span>
                            <span class="mono" style="font-size: 0.75rem;"><?= h($fullUrl) ?></span>
                            <button type="button" class="copy-button" data-copy="<?= h($fullUrl) ?>">Copy</button>
                            <?php if ($baseUrl !== ''): ?>
                                <a class="copy-button" href="<?= h($fullUrl) ?>" target="_blank" rel="noopener">Open</a>
                            <?php endif; ?>
                        </div>
                        <?php endforeach; ?>

                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-top: 0.75rem; margin-bottom: 0.5rem;">Threat Intel Formats</strong>
                        <p class="muted" style="margin-bottom: 0.5rem;">Full enriched exports with classification, score, org, country, and timestamps. Both IPv4 and IPv6 included. Authenticate with admin Basic Auth or the export API token.</p>
                        <p class="muted" style="margin-bottom: 0.5rem;"><strong>Note:</strong> MISP and STIX exports are capped at <strong>bot and suspicious</strong> classifications only, regardless of the threat feed minimum confidence setting above. Uncertain and human-classified IPs are excluded from intel formats since these are consumed by platforms that act automatically. Tokens with "Always include in threat feed" enabled are also capped at suspicious for intel formats.</p>
                        <?php
                        $intelFeeds = [
                            'MISP Event'  => '/feed/misp.json',
                            'STIX 2.1'    => '/feed/stix.json',
                        ];
                        foreach ($intelFeeds as $label => $feedPath):
                            $fullUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . $feedPath;
                        ?>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <span style="font-size: 0.75rem; color: var(--text-secondary); min-width: 90px;"><?= h($label) ?></span>
                            <span class="mono" style="font-size: 0.75rem;"><?= h($fullUrl) ?></span>
                            <button type="button" class="copy-button" data-copy="<?= h($fullUrl) ?>">Copy</button>
                            <?php if ($baseUrl !== ''): ?>
                                <a class="copy-button" href="<?= h($fullUrl) ?>" target="_blank" rel="noopener">Open</a>
                            <?php endif; ?>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    </details>

                    <details class="admin-advanced">
                    <summary>Redirect rate limiting</summary>
                    <form method="post" action="/admin/save-rate-limit-settings">
                        <?php if ($isDemo): ?>
                            <p class="muted demo-lock-note">Not configurable in demo mode.</p>
                            <div class="demo-locked-field"><?= h((string) getSetting($pdo, 'redirect_rate_limit_count', '10')) ?> requests <span class="demo-lock-note">Not configurable in demo mode</span></div>
                            <div class="demo-locked-field"><?= h((string) getSetting($pdo, 'redirect_rate_limit_window', '60')) ?> seconds <span class="demo-lock-note">Not configurable in demo mode</span></div>
                        <?php else: ?>
                            <label for="redirect_rate_limit_count">Max redirects per IP per token</label>
                            <input id="redirect_rate_limit_count" type="number" min="0" name="redirect_rate_limit_count" value="<?= h((string) getSetting($pdo, 'redirect_rate_limit_count', '10')) ?>">
                            <p class="muted">Maximum redirects from a single IP to the same token within the window below. Applies to known tokens only. Set to 0 to disable.</p>

                            <label for="redirect_rate_limit_window">Window (seconds)</label>
                            <input id="redirect_rate_limit_window" type="number" min="0" name="redirect_rate_limit_window" value="<?= h((string) getSetting($pdo, 'redirect_rate_limit_window', '60')) ?>">
                            <p class="muted">Hits are still logged when the limit is exceeded — only the redirect is blocked (429).</p>

                            <button type="submit">Save rate limit settings</button>
                        <?php endif; ?>
                    </form>
                    </details>

                    <?php if ($isDemo): ?>
                        <details class="admin-advanced">
                        <summary>Data retention &amp; cleanup</summary>
                        <div>
                            <h2>Data retention</h2>
                            <p class="muted demo-lock-note">Not available in demo mode. The database resets automatically on a schedule.</p>
                        </div>
                        <div>
                            <h2>Manual cleanup</h2>
                            <p class="muted demo-lock-note">Not available in demo mode.</p>
                        </div>
                        <div>
                            <h2>Database maintenance</h2>
                            <p class="muted demo-lock-note">Not available in demo mode.</p>
                            <div class="demo-locked-field">Scheduled maintenance: <?= $sqliteMaintenanceEnabled ? 'Enabled' : 'Disabled' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                            <div class="demo-locked-field">Last maintenance: <?= h($sqliteMaintenanceLastRun) ?> <span class="demo-lock-note">Read-only</span></div>
                            <div class="demo-locked-field">Last VACUUM: <?= h($sqliteVacuumLastRun) ?> <span class="demo-lock-note">Read-only</span></div>
                        </div>
                        </details>
                    <?php else: ?>
                    <details class="admin-advanced">
                    <summary>Data retention &amp; cleanup</summary>
                    <form method="post" action="/admin/save-retention-settings">
                        <h2>Data retention</h2>

                        <label for="data_retention_days">Delete click data older than this many days</label>
                        <input id="data_retention_days" type="number" min="0" name="data_retention_days" value="<?= h($dataRetentionDays) ?>">

                        <label for="auth_retention_days">Delete auth failure records older than this many days</label>
                        <input id="auth_retention_days" type="number" min="0" name="auth_retention_days" value="<?= h($authRetentionDays) ?>">

                        <label for="enrichment_retention_days">Delete IP enrichment cache older than this many days</label>
                        <input id="enrichment_retention_days" type="number" min="0" name="enrichment_retention_days" value="<?= h($enrichmentRetentionDays) ?>">

                        <label style="display:inline-flex;align-items:center;gap:6px;">
                            <input type="checkbox" name="archive_before_cleanup" value="1" <?= $archiveBeforeCleanup ? 'checked' : '' ?>>
                            <span>Archive click rows to CSV before cleanup</span>
                        </label>

                        <p class="muted">Set any value to 0 to disable cleanup for that data set.</p>

                        <button type="submit">Save retention settings</button>
                    </form>

                    <form method="post" action="/admin/run-cleanup" data-confirm="Run cleanup using the current retention setting?">
                        <h2>Manual cleanup</h2>
                        <p class="muted">Run cleanup now using the saved retention setting.</p>
                        <button type="submit" class="warning-button">Run cleanup now</button>
                    </form>

                    <form method="post" action="/admin/run-db-maintenance" data-confirm="Run SQLite maintenance now?">
                        <h2>Database maintenance</h2>
                        <p class="muted">Runs ANALYZE and PRAGMA optimize for SQLite planner health.</p>

                        <label style="display:inline-flex;align-items:center;gap:6px;">
                            <input type="checkbox" name="run_vacuum" value="1">
                            <span>Also run VACUUM now (can be slower)</span>
                        </label>
                        <button type="submit">Run SQLite maintenance</button>
                    </form>

                    <form method="post" action="/admin/save-db-maintenance-settings">
                        <h2>Scheduled maintenance</h2>
                        <label style="display:inline-flex;align-items:center;gap:6px;">
                            <input type="checkbox" name="sqlite_maintenance_enabled" value="1" <?= $sqliteMaintenanceEnabled ? 'checked' : '' ?>>
                            <span>Enable scheduled SQLite maintenance</span>
                        </label>

                        <label for="sqlite_maintenance_interval_mins">Maintenance interval (minutes)</label>
                        <input id="sqlite_maintenance_interval_mins" type="number" min="15" max="10080" name="sqlite_maintenance_interval_mins" value="<?= h($sqliteMaintenanceIntervalMins) ?>">

                        <label style="display:inline-flex;align-items:center;gap:6px;">
                            <input type="checkbox" name="sqlite_vacuum_enabled" value="1" <?= $sqliteVacuumEnabled ? 'checked' : '' ?>>
                            <span>Allow scheduled VACUUM</span>
                        </label>

                        <label for="sqlite_vacuum_min_interval_hours">VACUUM minimum interval (hours)</label>
                        <input id="sqlite_vacuum_min_interval_hours" type="number" min="6" max="720" name="sqlite_vacuum_min_interval_hours" value="<?= h($sqliteVacuumIntervalHours) ?>">
                        <p class="muted">Safe policy: VACUUM is optional, off by default, and interval-limited.</p>
                        <button type="submit">Save maintenance settings</button>
                    </form>

                    <div class="admin-advanced" style="padding: 12px;">
                        <h2>Database stats</h2>
                        <div class="details-grid">
                            <div>
                                <div><span class="mono">DB size:</span> <?= h((string) $dbStats['size_mb']) ?> MB</div>
                                <div><span class="mono">Total clicks:</span> <?= (int) $dbStats['total_clicks'] ?></div>
                                <div><span class="mono">Last maintenance:</span> <?= h($sqliteMaintenanceLastRun) ?></div>
                            </div>
                            <div>
                                <div><span class="mono">Clicks (24h):</span> <?= (int) $dbStats['clicks_24h'] ?></div>
                                <div><span class="mono">Clicks (7d):</span> <?= (int) $dbStats['clicks_7d'] ?></div>
                                <div><span class="mono">Last VACUUM:</span> <?= h($sqliteVacuumLastRun) ?></div>
                            </div>
                        </div>
                    </div>
                    </details>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="tab-content" id="content-skip">
            <form method="post" action="/admin/create-skip-pattern">
                <h2>Create skip pattern</h2>

                <label for="skip_type">Pattern Type</label>
                <select id="skip_type" name="type">
                    <option value="exact">Exact</option>
                    <option value="contains">Contains</option>
                    <option value="prefix">Prefix</option>
                </select>

                <label for="skip_pattern">Pattern</label>
                <input id="skip_pattern" type="text" name="pattern" required placeholder=".env or api/">

                <button type="submit">Add skip pattern</button>
            </form>

            <h2>Skip patterns</h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Pattern</th>
                        <th>Active</th>
                        <th class="skip-actions-col">Actions</th>
                    </tr>
                    <?php foreach ($skipPatterns as $pattern): ?>
                        <tr>
                            <td><?= (int) $pattern['id'] ?></td>
                            <td><?= h((string) $pattern['type']) ?></td>
                            <td class="mono"><?= h((string) $pattern['pattern']) ?></td>
                            <td><?= ((int) $pattern['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td class="skip-actions-col actions-col--menu">
                                <div class="action-menu" data-action-menu>
                                    <?= renderActionMenuTrigger('Skip pattern actions') ?>
                                    <div class="action-menu-panel" hidden>
                                        <div class="action-menu-inner">
                                            <?php if ((int) $pattern['active'] === 1): ?>
                                                <form method="post" action="/admin/deactivate-skip-pattern" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="id" value="<?= (int) $pattern['id'] ?>">
                                                    <button type="submit" class="action-menu-submit">Deactivate skip pattern</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" action="/admin/activate-skip-pattern" class="inline-action-form action-menu-form">
                                                    <input type="hidden" name="id" value="<?= (int) $pattern['id'] ?>">
                                                    <button type="submit" class="action-menu-submit">Activate skip pattern</button>
                                                </form>
                                            <?php endif; ?>
                                            <form method="post" action="/admin/delete-skip-pattern" class="inline-action-form action-menu-form" data-confirm="Delete this skip pattern?">
                                                <input type="hidden" name="id" value="<?= (int) $pattern['id'] ?>">
                                                <button type="submit" class="danger-button action-menu-submit">Delete skip pattern</button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>

        <script nonce="<?= h($cspNonce) ?>">
        /* --------------------------------------------------------
           THEME INIT — runs immediately to avoid flash of wrong theme
           -------------------------------------------------------- */
        (function () {
            var saved = localStorage.getItem('st-theme');
            var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            var theme = saved || (prefersDark ? 'dark' : 'light');
            document.documentElement.setAttribute('data-theme', theme);
        })();

        function toggleTheme() {
            var current = document.documentElement.getAttribute('data-theme') || 'light';
            var next    = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('st-theme', next);
            updateThemeButton(next);
        }

        function updateThemeButton(theme) {
            var icon  = document.getElementById('theme-icon');
            var label = document.getElementById('theme-label');
            if (!icon || !label) return;
            if (theme === 'dark') {
                icon.textContent  = '🌙';
                label.textContent = 'Dark';
            } else {
                icon.textContent  = '☀️';
                label.textContent = 'Light';
            }
        }

        /* --------------------------------------------------------
           CSRF TOKEN INJECTION
           -------------------------------------------------------- */
        const CSRF_TOKEN = <?= json_encode($csrfToken) ?>;

        function injectCsrf() {
            document.querySelectorAll('form[method="post"], form[method="POST"]').forEach(function (form) {
                if (!form.querySelector('input[name="csrf_token"]')) {
                    var input   = document.createElement('input');
                    input.type  = 'hidden';
                    input.name  = 'csrf_token';
                    input.value = CSRF_TOKEN;
                    form.appendChild(input);
                }
            });
        }

        /* Run immediately for forms already in the DOM */
        injectCsrf();

        /* --------------------------------------------------------
           TAB MANAGEMENT
           -------------------------------------------------------- */
        function showTab(name, updateUrl) {
            if (typeof updateUrl === 'undefined') updateUrl = true;

            document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
            document.querySelectorAll('.tab-content').forEach(function (c) { c.classList.remove('active'); });
            var tab     = document.getElementById('tab-' + name);
            var content = document.getElementById('content-' + name);
            if (tab && content) {
                tab.classList.add('active');
                content.classList.add('active');
                localStorage.setItem('activeTab', name);

                if (updateUrl) {
                    var url = new URL(window.location.href);
                    if (name === 'dashboard') {
                        url.searchParams.delete('tab');
                    } else {
                        url.searchParams.set('tab', name);
                    }
                    history.replaceState(null, '', url.pathname + (url.search ? url.search : '') + url.hash);
                }
            }
        }

        function toggleDetails(id, button) {
            var row  = document.getElementById(id);
            if (!row) return;
            var open = row.classList.toggle('open');
            if (button) { button.textContent = open ? 'Hide ▴' : 'Details ▾'; }
            if (open) { loadShodanEnrichment(row); }
        }

        /* --------------------------------------------------------
           SHODAN ENRICHMENT
           Fetches InternetDB data when a details panel opens.
           Only fetches once per panel — result is cached in the DOM.
           -------------------------------------------------------- */
        function loadShodanEnrichment(row) {
            var box = row.querySelector('.shodan-box');
            if (!box) return;

            // Already loaded or loading
            if (box.dataset.loaded) return;
            box.dataset.loaded = '1';

            var ip = box.dataset.ip;
            if (!ip) return;

            var loading = box.querySelector('.shodan-loading');
            var content = box.querySelector('.shodan-content');

            fetch('/admin/enrichment?ip=' + encodeURIComponent(ip))
                .then(function(r) { return r.json(); })
                .then(function(data) { renderEnrichment(box, ip, data, loading, content); })
                .catch(function() {
                    if (loading) loading.style.display = 'none';
                    if (content) {
                        content.innerHTML = '<span class="muted" style="font-size:0.8125rem;">Enrichment unavailable.</span>';
                        content.style.display = '';
                    }
                });
        }

        function renderEnrichment(box, ip, data, loading, content) {
            if (loading) loading.style.display = 'none';
            if (!content) return;

            if (data.private) {
                content.innerHTML = '<span class="muted" style="font-size:0.8125rem;">Private or reserved IP — no enrichment available.</span>';
                content.style.display = '';
                return;
            }

            var html = '';

            // ── Single rescan button at the top ───────────────
            html += '<div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:8px;">';
            html += '<span style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-sec);">Sources: Shodan InternetDB · AbuseIPDB</span>';
            html += '<button type="button" class="copy-button rescan-btn" style="font-size:0.7rem;">Rescan</button>';
            html += '</div>';

            // ── Shodan InternetDB section ──────────────────────
            var ports     = data.ports     || [];
            var vulns     = data.vulns     || [];
            var tags      = data.tags      || [];
            var hostnames = data.hostnames || [];
            var hasShod   = ports.length > 0 || vulns.length > 0 || tags.length > 0 || hostnames.length > 0;

            html += '<div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-sec);margin-bottom:4px;">Shodan InternetDB</div>';

            if (!hasShod && data.not_found) {
                html += '<div class="muted" style="font-size:0.8125rem;margin-bottom:0.75rem;">No data in Shodan for this IP.</div>';
            } else {
                if (hostnames.length > 0) {
                    html += '<div><span class="mono">Hostnames:</span> ' + escHtml(hostnames.join(', ')) + '</div>';
                }
                if (ports.length > 0) {
                    html += '<div><span class="mono">Open ports:</span> ';
                    html += ports.map(function(p) {
                        return '<span class="badge badge-uncertain">' + escHtml(String(p)) + '</span>';
                    }).join(' ');
                    html += '</div>';
                } else {
                    html += '<div><span class="mono">Open ports:</span> <span class="muted">none</span></div>';
                }
                if (vulns.length > 0) {
                    html += '<div><span class="mono">CVEs:</span> ';
                    html += vulns.map(function(v) {
                        return '<a class="copy-button" href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v) + '" target="_blank" rel="noopener">' + escHtml(v) + '</a>';
                    }).join(' ');
                    html += '</div>';
                }
                if (tags.length > 0) {
                    html += '<div><span class="mono">Tags:</span> ';
                    html += tags.map(function(t) {
                        return '<span class="badge badge-suspicious">' + escHtml(t) + '</span>';
                    }).join(' ');
                    html += '</div>';
                }
            }

            if (data.fetched_at) {
                html += '<div style="margin-top:4px;"><span class="muted" style="font-size:0.75rem;">Fetched: ' + escHtml(data.fetched_at) + (data.cached ? ' (cached)' : '') + '</span></div>';
            }

            // ── AbuseIPDB section ──────────────────────────────
            var hasAbuse = data.abuse_score !== undefined && data.abuse_score !== null && data.abuse_score !== '';
            html += '<div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-sec);margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid var(--border);margin-bottom:4px;">AbuseIPDB</div>';

            if (!hasAbuse) {
                html += '<div class="muted" style="font-size:0.8125rem;">No AbuseIPDB data — API key not configured or daily limit reached.</div>';
            } else {
                var score = parseInt(data.abuse_score, 10);
                if (isNaN(score)) score = 0;
                var scoreColor = score >= 75 ? 'var(--bot-text)' : score >= 25 ? 'var(--suspicious-text)' : 'var(--human-text)';
                html += '<div><span class="mono">Abuse confidence:</span> <strong style="color:' + scoreColor + '">' + score + '% likelihood of malicious activity</strong></div>';
                html += '<div><span class="mono">Total reports:</span> ' + escHtml(String(data.abuse_reports || 0)) + '</div>';
                if (data.abuse_last_reported) {
                    html += '<div><span class="mono">Last reported:</span> ' + escHtml(data.abuse_last_reported) + '</div>';
                }
                if (data.abuse_isp) {
                    html += '<div><span class="mono">ISP:</span> ' + escHtml(data.abuse_isp) + '</div>';
                }
                if (data.abuse_usage_type) {
                    html += '<div><span class="mono">Usage type:</span> ' + escHtml(data.abuse_usage_type) + '</div>';
                }
                if (data.abuse_domain) {
                    html += '<div><span class="mono">Domain:</span> ' + escHtml(data.abuse_domain) + '</div>';
                }
                html += '<div style="margin-top:4px;display:flex;gap:0.5rem;align-items:center;">';
                html += '<a class="copy-button" href="https://www.abuseipdb.com/check/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener">View on AbuseIPDB</a>';
                if (data.fetched_at) {
                    html += '<span class="muted" style="font-size:0.75rem;">Fetched: ' + escHtml(data.fetched_at) + (data.cached ? ' (cached)' : '') + '</span>';
                }
                html += '</div>';
            }

            content.innerHTML = html;
            content.style.display = '';

            // Wire up rescan buttons
            content.querySelectorAll('.rescan-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    btn.textContent = 'Rescanning…';
                    btn.disabled = true;
                    var loadingEl = box.querySelector('.shodan-loading');
                    if (loadingEl) { loadingEl.style.display = ''; }
                    content.style.display = 'none';
                    delete box.dataset.loaded;

                    fetch('/admin/enrichment/rescan?ip=' + encodeURIComponent(ip))
                        .then(function(r) { return r.json(); })
                        .then(function(data) { renderEnrichment(box, ip, data, loadingEl, content); })
                        .catch(function() {
                            btn.textContent = 'Rescan';
                            btn.disabled = false;
                            if (loadingEl) loadingEl.style.display = 'none';
                            content.style.display = '';
                        });
                });
            });
        }

        function escHtml(str) {
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }

        function applyReportMapMetric(metric) {
            var selected = (metric === 'risky_hits') ? 'risky_hits' : 'total_events';
            document.querySelectorAll('[data-map-panel]').forEach(function (panel) {
                if (panel.dataset.mapPanel === selected) {
                    panel.removeAttribute('hidden');
                } else {
                    panel.setAttribute('hidden', '');
                }
            });
        }

        /* --------------------------------------------------------
           COPY TO CLIPBOARD
           -------------------------------------------------------- */
        async function copyText(value) {
            try {
                await navigator.clipboard.writeText(value);
            } catch (e) {
                var temp = document.createElement('textarea');
                temp.value = value;
                document.body.appendChild(temp);
                temp.select();
                document.execCommand('copy');
                document.body.removeChild(temp);
            }
        }

        /* --------------------------------------------------------
           DELEGATED EVENT HANDLERS
           Replaces all inline onclick/onsubmit attributes so the
           page works under a strict nonce-based CSP.
           -------------------------------------------------------- */
        function closeAllActionMenus() {
            document.querySelectorAll('.action-menu-panel').forEach(function (p) {
                p.setAttribute('hidden', '');
            });
            document.querySelectorAll('.action-menu-trigger').forEach(function (t) {
                t.setAttribute('aria-expanded', 'false');
            });
        }

        document.addEventListener('click', function (e) {
            // Close row action menus on outside click
            if (!e.target.closest('.action-menu')) {
                closeAllActionMenus();
            }

            var menuTrigger = e.target.closest('.action-menu-trigger');
            if (menuTrigger) {
                e.preventDefault();
                var wrap = menuTrigger.closest('.action-menu');
                var panel = wrap ? wrap.querySelector('.action-menu-panel') : null;
                if (panel) {
                    var wasHidden = panel.hasAttribute('hidden');
                    closeAllActionMenus();
                    if (wasHidden) {
                        panel.removeAttribute('hidden');
                        menuTrigger.setAttribute('aria-expanded', 'true');
                    }
                }
                return;
            }

            // Theme toggle
            if (e.target.closest('#theme-toggle')) {
                toggleTheme();
                return;
            }

            // Tab switching — data-tab="name"
            var tabEl = e.target.closest('[data-tab]');
            if (tabEl) {
                showTab(tabEl.dataset.tab);
                return;
            }

            // Generic hidden row toggle — data-toggle-row="row-id"
            var toggleRowEl = e.target.closest('[data-toggle-row]');
            if (toggleRowEl) {
                var rowId = toggleRowEl.dataset.toggleRow;
                var row = document.getElementById(rowId);
                if (row) {
                    row.style.display = (getComputedStyle(row).display === 'none') ? 'table-row' : 'none';
                }
                closeAllActionMenus();
                return;
            }

            // Campaign edit toggle
            var campaignEditEl = e.target.closest('[data-edit-campaign]');
            if (campaignEditEl) {
                var campaignId = campaignEditEl.dataset.editCampaign;
                var editRow = document.getElementById('edit-campaign-' + campaignId);
                var displayRow = campaignEditEl.closest('tr');
                if (editRow && displayRow) {
                    editRow.style.display = 'table-row';
                    displayRow.style.display = 'none';
                }
                closeAllActionMenus();
                return;
            }

            // Campaign edit cancel
            var campaignCancelEl = e.target.closest('[data-cancel-campaign-edit]');
            if (campaignCancelEl) {
                var cancelId = campaignCancelEl.dataset.cancelCampaignEdit;
                var cancelRow = campaignCancelEl.closest('tr');
                var summaryRow = cancelRow ? cancelRow.previousElementSibling : null;
                if (cancelRow) {
                    cancelRow.style.display = 'none';
                }
                if (summaryRow) {
                    summaryRow.style.display = 'table-row';
                }
                return;
            }

            // Details toggle — data-details="row-id"
            var detailsEl = e.target.closest('[data-details]');
            if (detailsEl) {
                toggleDetails(detailsEl.dataset.details, detailsEl);
                return;
            }

            // Copy to clipboard — data-copy="text"
            var copyEl = e.target.closest('[data-copy]');
            if (copyEl) {
                copyText(copyEl.dataset.copy);
                return;
            }

            // Confirm before action — data-confirm="message"
            var confirmEl = e.target.closest('[data-confirm]');
            if (confirmEl && confirmEl.tagName === 'BUTTON') {
                if (!confirm(confirmEl.dataset.confirm)) {
                    e.preventDefault();
                }
                return;
            }
        });

        document.addEventListener('submit', function (e) {
            // Confirm before form submit — data-confirm="message" on the form
            var msg = e.target.dataset.confirm;
            if (msg && !confirm(msg)) {
                e.preventDefault();
            }
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                closeAllActionMenus();
            }
        });

        /* --------------------------------------------------------
           DOMContentLoaded — tab restore, CSRF re-injection,
           auto-refresh, theme button sync
           -------------------------------------------------------- */
        document.addEventListener('DOMContentLoaded', function () {

            /* Sync button label with current theme */
            var currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            updateThemeButton(currentTheme);

            /* Inject CSRF into any forms rendered after the initial parse */
            injectCsrf();

            /* Tab restore — URL param beats localStorage.
               Only restore from localStorage when a tab param was explicitly
               saved from a previous in-page navigation. Fresh /admin loads
               (no ?tab= in URL) always start on the dashboard. */
            var urlParams  = new URLSearchParams(window.location.search);
            var tabFromUrl = urlParams.get('tab');
            var saved      = tabFromUrl || (tabFromUrl === null ? null : localStorage.getItem('activeTab')) || 'dashboard';
            if (!tabFromUrl) {
                // No tab in URL — only restore localStorage if we came from
                // an in-page action (referrer is same origin /admin)
                var ref = document.referrer;
                var sameOrigin = ref !== '' && ref.indexOf(window.location.origin + '/admin') === 0;
                saved = sameOrigin ? (localStorage.getItem('activeTab') || 'dashboard') : 'dashboard';
            }
            showTab(saved, false);

            /* Auto-refresh — only fires when the dashboard tab is active */
            var refreshSecs = <?= (int) $autoRefreshSecs ?>;
            if (refreshSecs > 0) {
                setTimeout(function () {
                    var active = document.querySelector('.tab.active');
                    if (active && active.id === 'tab-dashboard') {
                        window.location.reload();
                    }
                }, refreshSecs * 1000);
            }


            /* ── Campaign edit buttons ─────────────────────────────── */
            document.querySelectorAll('[data-edit-campaign]').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var campaignId = btn.dataset.editCampaign;
                    var editRow = document.getElementById('edit-campaign-' + campaignId);
                    var displayRow = btn.closest('tr');
                    if (editRow && displayRow) {
                        editRow.style.display = 'table-row';
                        if (getComputedStyle(editRow).display === 'none') {
                            editRow.style.display = 'block';
                        }
                        displayRow.style.display = 'none';
                    }
                });
            });

            document.querySelectorAll('[data-cancel-campaign-edit]').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var cancelRow = btn.closest('tr');
                    var summaryRow = cancelRow ? cancelRow.previousElementSibling : null;
                    if (cancelRow) cancelRow.style.display = 'none';
                    if (summaryRow) summaryRow.style.display = 'table-row';
                });
            });

            /* ── Webhook test buttons ─────────────────────────────────── */
            function setupWebhookTest(btnId, resultId, endpoint) {
                var btn = document.getElementById(btnId);
                var result = document.getElementById(resultId);
                if (!btn || !result) return;

                // Enable/disable based on URL field value
                var urlInput = btnId === 'test-threat-webhook'
                    ? document.getElementById('webhook_url')
                    : document.getElementById('token_webhook_url');

                if (urlInput) {
                    urlInput.addEventListener('input', function () {
                        btn.disabled = urlInput.value.trim() === '';
                    });
                }

                btn.addEventListener('click', function () {
                    btn.disabled = true;
                    btn.textContent = 'Sending…';
                    result.style.display = 'none';

                    var csrf = document.querySelector('input[name="csrf_token"]');
                    var fd = new FormData();
                    if (csrf) fd.append('csrf_token', csrf.value);

                    fetch(endpoint, { method: 'POST', body: fd })
                        .then(function (r) { return r.json(); })
                        .then(function (data) {
                            result.textContent = data.message;
                            result.style.display = 'block';
                            result.style.color = data.ok ? 'var(--human)' : 'var(--bot)';
                        })
                        .catch(function () {
                            result.textContent = 'Request failed — check the browser console.';
                            result.style.display = 'block';
                            result.style.color = 'var(--bot)';
                        })
                        .finally(function () {
                            btn.disabled = false;
                            btn.textContent = 'Test';
                        });
                });
            }

            setupWebhookTest('test-threat-webhook', 'test-threat-webhook-result', '/admin/test-threat-webhook');
            setupWebhookTest('test-token-webhook',  'test-token-webhook-result',  '/admin/test-token-webhook');

            /* ── AbuseIPDB change key toggle ──────────────────────────── */
            var changeKeyBtn = document.getElementById('abuseipdb-change-key');
            if (changeKeyBtn) {
                changeKeyBtn.addEventListener('click', function () {
                    var input = document.getElementById('abuseipdb-key-input');
                    if (input) {
                        input.style.display = '';
                        changeKeyBtn.style.display = 'none';
                        var field = document.getElementById('abuseipdb_api_key');
                        if (field) field.focus();
                    }
                });
            }

            /* ── Webhook preset dropdowns ─────────────────────────────── */
            document.querySelectorAll('select[data-type]').forEach(function (select) {
                select.addEventListener('change', function () {
                    var preset = select.value;
                    var type   = select.dataset.type;
                    var target = select.dataset.target;
                    if (!preset || !target) return;

                    var textarea = document.getElementById(target);
                    if (!textarea) return;

                    fetch('/admin/webhook-preset?preset=' + encodeURIComponent(preset) + '&type=' + encodeURIComponent(type))
                        .then(function (r) { return r.json(); })
                        .then(function (data) {
                            if (data.template !== undefined) {
                                textarea.value = data.template;
                                // Flash the textarea border to confirm it updated
                                textarea.style.transition = 'border-color 0.2s';
                                textarea.style.borderColor = 'var(--human)';
                                setTimeout(function () {
                                    textarea.style.borderColor = '';
                                }, 1200);
                                // Scroll the textarea into view
                                textarea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                            }
                        })
                        .catch(function () {
                            select.value = '';
                        });
                });
            });

            /* ── Saved dashboard filter presets ───────────────────────── */
            var presetSelect = document.getElementById('filter-preset-select');
            var presetSave = document.getElementById('filter-preset-save');
            var presetDelete = document.getElementById('filter-preset-delete');
            var densityToggle = document.getElementById('density-toggle');
            var presetKey = 'signaltrace-filter-presets-v1';
            var densityKey = 'signaltrace-density-v1';

            function readPresets() {
                try {
                    var raw = localStorage.getItem(presetKey);
                    var parsed = raw ? JSON.parse(raw) : {};
                    return (parsed && typeof parsed === 'object') ? parsed : {};
                } catch (e) {
                    return {};
                }
            }

            function writePresets(presets) {
                localStorage.setItem(presetKey, JSON.stringify(presets));
            }

            function refreshPresetSelect() {
                if (!presetSelect) return;
                var presets = readPresets();
                presetSelect.innerHTML = '<option value="">Saved presets</option>';
                Object.keys(presets).sort().forEach(function (name) {
                    var opt = document.createElement('option');
                    opt.value = name;
                    opt.textContent = name;
                    presetSelect.appendChild(opt);
                });
            }

            function currentFilterParams() {
                var p = new URLSearchParams(window.location.search);
                var keys = ['token', 'ip', 'visitor', 'campaign', 'host', 'known', 'show_top_tokens', 'show_all', 'show_hidden', 'date_from', 'date_to'];
                var out = {};
                keys.forEach(function (k) {
                    if (p.has(k) && p.get(k) !== '') out[k] = p.get(k);
                });
                return out;
            }

            if (presetSelect) {
                refreshPresetSelect();
                presetSelect.addEventListener('change', function () {
                    if (!presetSelect.value) return;
                    var presets = readPresets();
                    var selected = presets[presetSelect.value];
                    if (!selected) return;
                    var url = new URL(window.location.href);
                    var keys = ['token', 'ip', 'visitor', 'campaign', 'host', 'known', 'show_top_tokens', 'show_all', 'show_hidden', 'date_from', 'date_to', 'page'];
                    keys.forEach(function (k) { url.searchParams.delete(k); });
                    Object.keys(selected).forEach(function (k) { url.searchParams.set(k, selected[k]); });
                    window.location.href = url.pathname + '?' + url.searchParams.toString();
                });
            }

            if (presetSave) {
                presetSave.addEventListener('click', function () {
                    var name = prompt('Preset name');
                    if (!name) return;
                    var presets = readPresets();
                    presets[name.trim()] = currentFilterParams();
                    writePresets(presets);
                    refreshPresetSelect();
                });
            }

            if (presetDelete) {
                presetDelete.addEventListener('click', function () {
                    if (!presetSelect || !presetSelect.value) return;
                    var presets = readPresets();
                    delete presets[presetSelect.value];
                    writePresets(presets);
                    refreshPresetSelect();
                });
            }

            function applyDensity(mode) {
                var compact = mode === 'compact';
                document.body.classList.toggle('density-compact', compact);
                if (densityToggle) {
                    densityToggle.textContent = compact ? 'Density: compact' : 'Density: comfy';
                }
            }

            var savedDensity = localStorage.getItem(densityKey) || 'comfy';
            applyDensity(savedDensity);
            if (densityToggle) {
                densityToggle.addEventListener('click', function () {
                    var next = document.body.classList.contains('density-compact') ? 'comfy' : 'compact';
                    localStorage.setItem(densityKey, next);
                    applyDensity(next);
                });
            }

            var mapMetricSelect = document.getElementById('report-map-metric');
            applyReportMapMetric(mapMetricSelect ? mapMetricSelect.value : 'total_events');
            if (mapMetricSelect) {
                mapMetricSelect.addEventListener('change', function () {
                    applyReportMapMetric(mapMetricSelect.value);
                });
            }
        });
        </script>
    </div><!-- /.page-body -->
    </body>
    </html>
    <?php
}