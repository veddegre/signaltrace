<?php
declare(strict_types=1);

function handleThreatFeed(PDO $pdo): void
{
    $ips = getThreatFeedIps($pdo);

    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    echo implode("\n", $ips);
    exit;
}

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
            'destination' => ''
        ], $pixelData);
    }

    header('Content-Type: image/gif');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
    exit;
}

function handleAdminPage(PDO $pdo, array $settings): void
{
    requireAdminAuth();

    $appName = $settings['app_name'] ?? 'SignalTrace';
    $baseUrl = trim((string)($settings['base_url'] ?? ''));
    $defaultRedirectUrl = trim((string)($settings['default_redirect_url'] ?? 'https://example.com/'));
    $unknownPathBehavior = trim((string)($settings['unknown_path_behavior'] ?? 'redirect'));
    $pixelEnabled = ($settings['pixel_enabled'] ?? '1') === '1';
    $noiseFilterEnabled = ($settings['noise_filter_enabled'] ?? '1') === '1';

    $tokenFilter = trim((string)($_GET['token'] ?? ''));
    $ipFilter = trim((string)($_GET['ip'] ?? ''));
    $visitorFilter = trim((string)($_GET['visitor'] ?? ''));
    $knownOnly = isset($_GET['known']) && $_GET['known'] === '1';

    $clicks = getRecentClicksAdvancedFiltered($pdo, 200, $tokenFilter, $ipFilter, $visitorFilter, $knownOnly);
    $links = getAllLinks($pdo);
    $tokenCounts = getClickCountsByToken($pdo, $knownOnly);
    $skipPatterns = getSkipPatterns($pdo);

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
        $refreshUrl
    );

    exit;
}

function handleTrackedRequest(PDO $pdo, string $path, array $settings, array $skipPatternMap): void
{
    $defaultRedirectUrl = trim((string)($settings['default_redirect_url'] ?? 'https://example.com/'));
    $unknownPathBehavior = trim((string)($settings['unknown_path_behavior'] ?? 'redirect'));
    $noiseFilterEnabled = ($settings['noise_filter_enabled'] ?? '1') === '1';

    $token = normalizeTokenFromPath($path);
    $requestData = collectRequestData($path);
    $link = getLinkByToken($pdo, $token);

    if (
        !$link &&
        $noiseFilterEnabled &&
        shouldSkipLogging($token, $path, $requestData['user_agent'] ?? null, $skipPatternMap)
    ) {
        redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
    }

    if ($link) {
        logClick($pdo, $link, $requestData);
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Location: ' . $link['destination'], true, 302);
        exit;
    }

    logClick($pdo, [
        'id' => null,
        'token' => $token,
        'destination' => ''
    ], $requestData);

    redirectOr404($unknownPathBehavior, $defaultRedirectUrl);
}
