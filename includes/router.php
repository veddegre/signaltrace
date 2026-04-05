<?php

declare(strict_types=1);

/* ======================================================
   PIXEL HANDLER (unchanged)
   ====================================================== */
function handlePixelRequest(PDO $pdo, string $path): void
{
    if (!preg_match('#^/pixel/(.+)\.gif$#', $path, $matches)) {
        return;
    }

    $token = trim($matches[1], '/');
    $link = getLinkByToken($pdo, $token);

    if ($link) {
        $pixelData = collectRequestData($path);
        $pixelData['event_type'] = 'pixel';

        logClick($pdo, [
            'id' => $link['id'] ?? null,
            'token' => 'pixel:' . $token,
            'destination' => '',
        ], $pixelData);
    }

    header('Content-Type: image/gif');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
    exit;
}

/* ======================================================
   🧠 THREAT FEED
   ====================================================== */
function handleThreatFeed(PDO $pdo, array $settings): void
{
    $threshold = (int) ($settings['feed_score_threshold'] ?? 25);
    $windowMinutes = (int) ($settings['feed_time_window_minutes'] ?? 1440);

    $cutoff = (int) round(microtime(true) * 1000) - ($windowMinutes * 60 * 1000);

    $stmt = $pdo->prepare("
        SELECT DISTINCT ip
        FROM clicks
        WHERE ip IS NOT NULL
          AND ip != ''
          AND clicked_at_unix_ms IS NOT NULL
          AND confidence_score IS NOT NULL
          AND confidence_score <= :threshold
          AND clicked_at_unix_ms >= :cutoff
        ORDER BY ip ASC
    ");

    $stmt->execute([
        ':threshold' => $threshold,
        ':cutoff' => $cutoff,
    ]);

    $ips = $stmt->fetchAll(PDO::FETCH_COLUMN);

    header('Content-Type: text/plain');
    header('Cache-Control: no-store');

    foreach ($ips as $ip) {
        echo $ip . "\n";
    }

    exit;
}

/* ======================================================
   📦 JSON EXPORT
   ====================================================== */
function handleJsonExport(PDO $pdo): void
{
    $stmt = $pdo->query("
        SELECT *
        FROM clicks
        ORDER BY id DESC
        LIMIT 1000
    ");

    $data = $stmt->fetchAll();

    header('Content-Type: application/json');
    echo json_encode($data, JSON_PRETTY_PRINT);

    exit;
}

/* ======================================================
   ADMIN PAGE
   ====================================================== */
function handleAdminPage(PDO $pdo, array $settings): void
{
    requireAdminAuth();

    $appName = $settings['app_name'] ?? 'SignalTrace';
    $baseUrl = trim((string) ($settings['base_url'] ?? ''));
    $defaultRedirectUrl = trim((string) ($settings['default_redirect_url'] ?? 'https://example.com/'));
    $unknownPathBehavior = trim((string) ($settings['unknown_path_behavior'] ?? 'redirect'));
    $pixelEnabled = ($settings['pixel_enabled'] ?? '1') === '1';
    $noiseFilterEnabled = ($settings['noise_filter_enabled'] ?? '1') === '1';

    $tokenFilter = trim((string) ($_GET['token'] ?? ''));
    $ipFilter = trim((string) ($_GET['ip'] ?? ''));
    $visitorFilter = trim((string) ($_GET['visitor'] ?? ''));
    $knownOnly = isset($_GET['known']) && $_GET['known'] === '1';
    $dateFrom = trim((string) ($_GET['date_from'] ?? ''));
    $dateTo = trim((string) ($_GET['date_to'] ?? ''));
    $asnRules = getAsnRules($pdo);

    $clicks = getRecentClicksAdvancedFiltered(
        $pdo,
        200,
        $tokenFilter !== '' ? $tokenFilter : null,
        $ipFilter !== '' ? $ipFilter : null,
        $visitorFilter !== '' ? $visitorFilter : null,
        $knownOnly,
        $dateFrom !== '' ? $dateFrom : null,
        $dateTo !== '' ? $dateTo : null,
    );

    $links = getAllLinks($pdo);

    $tokenCounts = getClickCountsByToken(
        $pdo,
        $knownOnly,
        $dateFrom !== '' ? $dateFrom : null,
        $dateTo !== '' ? $dateTo : null,
    );

    $skipPatterns = getSkipPatterns($pdo);
    $showTopTokens = isset($_GET['show_top_tokens']) && $_GET['show_top_tokens'] === '1';
    $showAll = isset($_GET['show_all']) && $_GET['show_all'] === '1';

    $refreshParams = [];
    if ($tokenFilter !== '') {
        $refreshParams['token'] = $tokenFilter;
    }
    if ($ipFilter !== '') {
        $refreshParams['ip'] = $ipFilter;
    }
    if ($visitorFilter !== '') {
        $refreshParams['visitor'] = $visitorFilter;
    }
    if ($knownOnly) {
        $refreshParams['known'] = '1';
    }
    if ($showTopTokens) {
        $refreshParams['show_top_tokens'] = '1';
    }
    if ($showAll) {
        $refreshParams['show_all'] = '1';
    }
    if ($dateFrom !== '') {
        $refreshParams['date_from'] = $dateFrom;
    }
    if ($dateTo !== '') {
        $refreshParams['date_to'] = $dateTo;
    }

    $refreshUrl = '/admin' . (!empty($refreshParams) ? '?' . http_build_query($refreshParams) : '');

    renderAdminPage(
        $appName,
        $baseUrl,
        $defaultRedirectUrl,
        $unknownPathBehavior,
        $pixelEnabled,
        $noiseFilterEnabled,
        $tokenFilter,
        $ipFilter,
        $visitorFilter,
        $knownOnly,
        $clicks,
        $links,
        $tokenCounts,
        $skipPatterns,
        $asnRules,
        $refreshUrl,
    );

    exit;
}

/* ======================================================
   TRACKED REQUEST (unchanged)
   ====================================================== */
function handleTrackedRequest(PDO $pdo, string $path, array $settings, array $skipPatternMap): void
{
    $defaultRedirectUrl = trim((string) ($settings['default_redirect_url'] ?? 'https://example.com/'));
    $unknownPathBehavior = trim((string) ($settings['unknown_path_behavior'] ?? 'redirect'));
    $noiseFilterEnabled = ($settings['noise_filter_enabled'] ?? '1') === '1';

    $token = normalizeTokenFromPath($path);
    $requestData = collectRequestData($path);
    $link = getLinkByToken($pdo, $token);

    if (
        !$link
        && $noiseFilterEnabled
        && shouldSkipLogging($token, $path, $requestData['user_agent'] ?? null, $skipPatternMap)
    ) {
        redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
    }

    if ($link) {
        logClick($pdo, $link, $requestData);
        header('Location: ' . $link['destination'], true, 302);
        exit;
    }

    logClick($pdo, [
        'id' => null,
        'token' => $token,
        'destination' => '',
    ], $requestData);

    redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
}
