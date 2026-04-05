<?php

declare(strict_types=1);

/* ======================================================
   PIXEL HANDLER
   ====================================================== */
function handlePixelRequest(PDO $pdo, string $path): void
{
    if (!preg_match('#^/pixel/(.+)\.gif$#', $path, $matches)) {
        return;
    }

    $token = trim($matches[1], '/');
    $link  = getLinkByToken($pdo, $token);

    if ($link) {
        $pixelData               = collectRequestData($path, $pdo);
        $pixelData['event_type'] = 'pixel';

        logClick($pdo, [
            'id'          => $link['id'] ?? null,
            'token'       => 'pixel:' . $token,
            'destination' => '',
        ], $pixelData);
    }

    header('Content-Type: image/gif');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
    exit;
}

/* ======================================================
   THREAT FEED
   ====================================================== */
function handleThreatFeed(PDO $pdo, array $settings): void
{
    $enabled = ($settings['threat_feed_enabled'] ?? '1') === '1';
    if (!$enabled) {
        header('Content-Type: text/plain');
        echo '';
        exit;
    }

    $ips = getThreatFeedIps($pdo);

    header('Content-Type: text/plain');
    header('Cache-Control: no-store');
    foreach ($ips as $ip) {
        echo $ip . "\n";
    }
    exit;
}

/* ======================================================
   EXPORTS — filter-aware, settings-aware
   /export/json  and  /export/csv
   ====================================================== */
function handleExport(PDO $pdo, string $format): void
{
    // NOTE: ?token= is reserved for the auth API key in requireExportAuth().
    // Export filter parameters use distinct names to avoid collision.
    $tokenFilter   = trim((string) ($_GET['path']    ?? ''));
    $ipFilter      = trim((string) ($_GET['ip']      ?? ''));
    $visitorFilter = trim((string) ($_GET['visitor'] ?? ''));
    $knownOnly     = isset($_GET['known']) && $_GET['known'] === '1';
    $dateFrom      = trim((string) ($_GET['date_from'] ?? ''));
    $dateTo        = trim((string) ($_GET['date_to']   ?? ''));

    // Manual filters present means bypass export settings and use exactly what
    // the admin filtered. No filters means use the configured threshold + window.
    $manualFilters = ($tokenFilter !== '' || $ipFilter !== '' || $visitorFilter !== ''
        || $knownOnly || $dateFrom !== '' || $dateTo !== '');

    $rows = exportClicks(
        $pdo,
        $manualFilters,
        $tokenFilter   !== '' ? $tokenFilter   : null,
        $ipFilter      !== '' ? $ipFilter      : null,
        $visitorFilter !== '' ? $visitorFilter : null,
        $knownOnly,
        $dateFrom !== '' ? $dateFrom : null,
        $dateTo   !== '' ? $dateTo   : null,
    );

    if ($format === 'csv') {
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="signaltrace-export-' . date('Ymd-His') . '.csv"');
        header('Cache-Control: no-store');

        if (empty($rows)) {
            exit;
        }

        $out = fopen('php://output', 'w');

        // Header row from first result's keys.
        fputcsv($out, array_keys($rows[0]));

        foreach ($rows as $row) {
            fputcsv($out, $row);
        }

        fclose($out);
    } else {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode($rows, JSON_PRETTY_PRINT);
    }

    exit;
}

/* ======================================================
   ADMIN PAGE
   ====================================================== */
function handleAdminPage(PDO $pdo, array $settings): void
{
    requireAdminAuth();

    $appName             = $settings['app_name']             ?? 'SignalTrace';
    $baseUrl             = trim((string) ($settings['base_url']             ?? ''));
    $defaultRedirectUrl  = trim((string) ($settings['default_redirect_url'] ?? 'https://example.com/'));
    $unknownPathBehavior = trim((string) ($settings['unknown_path_behavior'] ?? 'redirect'));
    $pixelEnabled        = ($settings['pixel_enabled']        ?? '1') === '1';
    $noiseFilterEnabled  = ($settings['noise_filter_enabled'] ?? '1') === '1';

    $tokenFilter   = trim((string) ($_GET['token']   ?? ''));
    $ipFilter      = trim((string) ($_GET['ip']      ?? ''));
    $visitorFilter = trim((string) ($_GET['visitor'] ?? ''));
    $knownOnly     = isset($_GET['known'])    && $_GET['known']    === '1';
    $dateFrom      = trim((string) ($_GET['date_from'] ?? ''));
    $dateTo        = trim((string) ($_GET['date_to']   ?? ''));
    $asnRules      = getAsnRules($pdo);

    // Pagination
    $pageSize    = max(10, (int) ($settings['page_size'] ?? 50));
    $currentPage = max(1, (int) ($_GET['page'] ?? 1));
    $offset      = ($currentPage - 1) * $pageSize;

    [$clicks, $totalCount] = getRecentClicksAdvancedFilteredPaged(
        $pdo,
        $pageSize,
        $offset,
        $tokenFilter   !== '' ? $tokenFilter   : null,
        $ipFilter      !== '' ? $ipFilter      : null,
        $visitorFilter !== '' ? $visitorFilter : null,
        $knownOnly,
        $dateFrom !== '' ? $dateFrom : null,
        $dateTo   !== '' ? $dateTo   : null,
    );

    $totalPages  = $pageSize > 0 ? max(1, (int) ceil($totalCount / $pageSize)) : 1;
    // Clamp current page now that we know the total — prevents wasteful
    // large-offset queries on subsequent requests.
    $currentPage = min($currentPage, $totalPages);

    $links       = getAllLinks($pdo);
    $tokenCounts = getClickCountsByToken(
        $pdo,
        $knownOnly,
        $dateFrom !== '' ? $dateFrom : null,
        $dateTo   !== '' ? $dateTo   : null,
    );

    $skipPatterns  = getSkipPatterns($pdo);
    $showTopTokens = isset($_GET['show_top_tokens']) && $_GET['show_top_tokens'] === '1';
    $showAll       = isset($_GET['show_all'])        && $_GET['show_all']        === '1';

    // Per-IP summary when filtering by a single exact IP
    $ipSummary = null;
    if ($ipFilter !== '' && !str_contains($ipFilter, '%')) {
        $ipSummary = getIpSummary($pdo, $ipFilter);
    }

    $refreshParams = [];
    if ($tokenFilter   !== '') $refreshParams['token']           = $tokenFilter;
    if ($ipFilter      !== '') $refreshParams['ip']              = $ipFilter;
    if ($visitorFilter !== '') $refreshParams['visitor']         = $visitorFilter;
    if ($knownOnly)            $refreshParams['known']           = '1';
    if ($showTopTokens)        $refreshParams['show_top_tokens'] = '1';
    if ($showAll)              $refreshParams['show_all']        = '1';
    if ($dateFrom      !== '') $refreshParams['date_from']       = $dateFrom;
    if ($dateTo        !== '') $refreshParams['date_to']         = $dateTo;

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
        $totalCount,
        $totalPages,
        $currentPage,
        $pageSize,
        $links,
        $tokenCounts,
        $skipPatterns,
        $asnRules,
        $refreshUrl,
        $ipSummary,
    );

    exit;
}

/* ======================================================
   TRACKED REQUEST
   ====================================================== */
function handleTrackedRequest(PDO $pdo, string $path, array $settings, array $skipPatternMap): void
{
    $defaultRedirectUrl  = trim((string) ($settings['default_redirect_url']  ?? 'https://example.com/'));
    $unknownPathBehavior = trim((string) ($settings['unknown_path_behavior'] ?? 'redirect'));
    $noiseFilterEnabled  = ($settings['noise_filter_enabled'] ?? '1') === '1';

    $token       = normalizeTokenFromPath($path);
    $requestData = collectRequestData($path, $pdo);
    $link        = getLinkByToken($pdo, $token);

    if (
        !$link
        && $noiseFilterEnabled
        && shouldSkipLogging($token, $path, $requestData['user_agent'] ?? null, $skipPatternMap)
    ) {
        redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
    }

    if ($link) {
        logClick($pdo, $link, $requestData);
        maybeFireAlert($pdo, $requestData);
        maybeRunAutoCleanup($pdo);

        $destination = (string) ($link['destination'] ?? '');
        if (!isSafeRedirectUrl($destination)) {
            error_log('SignalTrace: unsafe destination for token ' . $token . ': ' . $destination);
            redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
        }

        header('Location: ' . $destination, true, 302);
        exit;
    }

    logClick($pdo, [
        'id'          => null,
        'token'       => $token,
        'destination' => '',
    ], $requestData);

    maybeFireAlert($pdo, $requestData);
    maybeRunAutoCleanup($pdo);

    redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
}
