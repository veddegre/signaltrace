<?php

declare(strict_types=1);

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function getClientIp(): string
{
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }

    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function isRawIpHost(?string $host): bool
{
    if ($host === null || $host === '') {
        return false;
    }

    $hostOnly = strtolower(trim($host));
    if (str_contains($hostOnly, ':')) {
        $hostOnly = preg_replace('/:\d+$/', '', $hostOnly) ?? $hostOnly;
    }

    return filter_var($hostOnly, FILTER_VALIDATE_IP) !== false;
}

function hasExploitLikeQuery(?string $query): bool
{
    if ($query === null || $query === '') {
        return false;
    }

    $q = strtolower($query);

    $patterns = [
        'allow_url_include','auto_prepend_file','php://input','php://filter',
        'base64_encode','base64_decode','cmd=','exec=','shell=',
        'wget ','curl ','/bin/sh','/bin/bash','powershell',
        '%ad','-d+','-d%20','../','..%2f','%2e%2e%2f',
    ];

    foreach ($patterns as $pattern) {
        if (str_contains($q, $pattern)) {
            return true;
        }
    }

    return false;
}

function isLikelyBrowserUserAgent(?string $ua): bool
{
    if ($ua === null || $ua === '') {
        return false;
    }

    $ua = strtolower($ua);

    $signals = [
        'mozilla/5.0','chrome/','crios/','safari/','firefox/',
        'fxios/','edg/','opr/','opera/','version/',
        'applewebkit/','gecko/',
    ];

    foreach ($signals as $signal) {
        if (str_contains($ua, $signal)) {
            return true;
        }
    }

    return false;
}

function isKnownAutomationUserAgent(?string $ua): bool
{
    if ($ua === null || $ua === '') {
        return false;
    }

    $ua = strtolower($ua);

    $signals = [
        'bot','crawler','spider','preview','scanner','urlscan',
        'wget','curl','python-requests','go-http-client',
        'googleimageproxy','bingbot','slurp','facebookexternalhit',
        'skypeuripreview','slackbot','discordbot','telegrambot',
        'linkedinbot','outlook','microsoft office','safelinks',
        'proofpoint','mimecast','barracuda','symantec','trend micro',
        'zgrab','masscan','nmap','sqlmap','nikto','gobuster',
        'dirbuster','feroxbuster','httpclient','java/','libwww-perl',
        'aiohttp','httpx','restsharp','okhttp','apache-httpclient',
    ];

    foreach ($signals as $signal) {
        if (str_contains($ua, $signal)) {
            return true;
        }
    }

    return false;
}

function detectBot(?string $ua, string $method, string $path): array
{
    $ua = strtolower($ua ?? '');
    $p = strtolower(trim($path, '/'));
    $query = strtolower((string) ($_SERVER['QUERY_STRING'] ?? ''));
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    $reasons = [];

    if ($ua !== '' && isKnownAutomationUserAgent($ua)) {
        $reasons[] = 'ua:automation';
    }

    if ($method === 'HEAD') {
        $reasons[] = 'method:HEAD';
    }

    if ($method === 'POST' && hasExploitLikeQuery($query)) {
        $reasons[] = 'method:POST_exploit_query';
    }

    if (hasExploitLikeQuery($query)) {
        $reasons[] = 'query:exploit_like';
    }

    if (isRawIpHost($host)) {
        $reasons[] = 'host:raw_ip';
    }

    return [
        'is_bot' => !empty($reasons),
        'reason' => empty($reasons) ? null : implode(', ', array_unique($reasons)),
    ];
}

function buildVisitorHash(?string $ip, ?string $ua): ?string
{
    if (!$ip || !$ua) {
        return null;
    }

    return hash('sha256', VISITOR_HASH_SALT . '|' . $ip . '|' . $ua);
}

/* ======================================================
   🔥 UPDATED SCORING WITH PHASE 2 DETECTION
   ====================================================== */

function calculateConfidence(array $requestData): array
{
    $pdo = db(); // IMPORTANT

    $score = 50;
    $reasons = [];

    $ip = (string) ($requestData['ip'] ?? '');
    $ua = strtolower((string) ($requestData['user_agent'] ?? ''));
    $method = strtoupper((string) ($requestData['request_method'] ?? ''));
    $accept = strtolower((string) ($requestData['accept'] ?? ''));
    $acceptLanguage = (string) ($requestData['accept_language'] ?? '');
    $acceptEncoding = strtolower((string) ($requestData['accept_encoding'] ?? ''));
    $host = (string) ($requestData['host'] ?? '');
    $query = strtolower((string) ($requestData['query_string'] ?? ''));
    $path = strtolower((string) ($requestData['request_uri'] ?? ''));
    $referer = (string) ($requestData['referer'] ?? '');
    $secFetchSite = strtolower((string) ($requestData['sec_fetch_site'] ?? ''));
    $secFetchMode = strtolower((string) ($requestData['sec_fetch_mode'] ?? ''));
    $secFetchDest = strtolower((string) ($requestData['sec_fetch_dest'] ?? ''));
    $secChUa = (string) ($requestData['sec_ch_ua'] ?? '');
    $secChUaPlatform = (string) ($requestData['sec_ch_ua_platform'] ?? '');
    $org = strtolower((string) ($requestData['ip_org'] ?? ''));
    $asn = (string) ($requestData['ip_asn'] ?? '');

    /* ======================================================
       === BASE SIGNALS ===
       ====================================================== */

    if ($method === 'GET') {
        $score += 10;
        $reasons[] = 'get_request';
    }

    if ($method === 'POST') {
        $score -= 25;
        $reasons[] = 'post_request';
    }

    if ($accept === '') {
        $score -= 15;
        $reasons[] = 'accept_missing';
    }

    if ($acceptLanguage === '') {
        $score -= 10;
        $reasons[] = 'accept_language_missing';
    }

    if (isLikelyBrowserUserAgent($ua) && !isKnownAutomationUserAgent($ua)) {
        $score += 10;
        $reasons[] = 'browser_ua';
    }

    if (isKnownAutomationUserAgent($ua)) {
        $score -= 20;
        $reasons[] = 'known_automation_ua';
    }

    if (isRawIpHost($host)) {
        $score -= 15;
        $reasons[] = 'host_raw_ip';
    }

    if (hasExploitLikeQuery($query)) {
        $score -= 40;
        $reasons[] = 'exploit_like_query';
    }

    if (!empty($requestData['is_bot'])) {
        $score -= 25;
        $reasons[] = 'bot_signal';
    }

    if ($referer === '') {
        $score -= 5;
        $reasons[] = 'no_referer';
    }

    if ($secFetchSite === '' && $secFetchMode === '' && $secFetchDest === '') {
        $score -= 10;
        $reasons[] = 'sec_fetch_missing';
    }

    if ($secChUa === '' && $secChUaPlatform === '') {
        $score -= 8;
        $reasons[] = 'sec_ch_ua_missing';
    }

    if ($acceptEncoding === '') {
        $score -= 5;
        $reasons[] = 'accept_encoding_missing';
    }

    if ($referer !== '' && str_contains(strtolower($referer), 'gvsu.site') && $path === '/') {
        $score -= 8;
        $reasons[] = 'self_referer_root';
    }

    $hostingSignals = [
        'amazon',
        'microsoft',
        'digitalocean',
        'linode',
        'ovh',
        'vultr',
        'oracle',
        'google',
        'cloudflare',
        'hostpapa',
        'tencent',
    ];

    foreach ($hostingSignals as $signal) {
        if ($org !== '' && str_contains($org, $signal)) {
            $score -= 8;
            $reasons[] = 'hosting_provider_ip';
            break;
        }
    }

    $asnPenaltyMap = getActiveAsnPenaltyMap($pdo);

    if ($asn !== '' && isset($asnPenaltyMap[$asn])) {
        $score -= (int) $asnPenaltyMap[$asn];
        $reasons[] = 'asn_rule:' . $asn;
    }

    /* ======================================================
       === PATH RISK DETECTION ===
       ====================================================== */

    if ($path !== '') {
        $highRiskPathParts = [
            '.env',
            '.git',
            '.aws/credentials',
            'vendor/phpunit',
            '_ignition',
            'eval-stdin.php',
        ];

        foreach ($highRiskPathParts as $part) {
            if (str_contains($path, $part)) {
                $score -= 40;
                $reasons[] = "path:$part";
                break;
            }
        }
    }

    if ($path !== '') {
        $mediumRiskPathParts = [
            'wp-admin',
            'wp-login',
            'phpinfo',
            'autodiscover',
            'swagger',
            'graphql',
        ];

        foreach ($mediumRiskPathParts as $part) {
            if (str_contains($path, $part)) {
                $score -= 25;
                $reasons[] = "path:$part";
                break;
            }
        }
    }

    /* ======================================================
       === TIMING + SCAN DETECTION ===
       ====================================================== */

    if ($ip !== '') {

        $lastSeen = getLastSeenForIp($pdo, $ip);
        $now = (int) round(microtime(true) * 1000);

        if ($lastSeen !== null) {
            $deltaMs = $now - $lastSeen;

            if ($deltaMs < 1000) {
                $score -= 40;
                $reasons[] = 'rapid_repeat';
            } elseif ($deltaMs < 3000) {
                $score -= 20;
                $reasons[] = 'fast_repeat';
            }
        }

        $recentCount = getRecentEventCountForIp($pdo, $ip, 10);
        if ($recentCount >= 5) {
            $score -= 30;
            $reasons[] = 'burst_activity';
        }

        $distinctTokens = getDistinctTokenCountForIp($pdo, $ip, 30);
        if ($distinctTokens >= 3) {
            $score -= 35;
            $reasons[] = 'multi_token_scan';
        }
    }

    /* ======================================================
       === FINALIZE ===
       ====================================================== */

    $score = max(0, min(100, $score));

    if ($score >= 75) {
        $label = 'human';
    } elseif ($score >= 45) {
        $label = 'likely-human';
    } elseif ($score >= 20) {
        $label = 'suspicious';
    } else {
        $label = 'bot';
    }

    return [
        'confidence_score' => $score,
        'confidence_label' => $label,
        'confidence_reason' => implode(', ', array_unique($reasons)),
    ];
}

function collectRequestData(string $path): array
{
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $bot = detectBot($userAgent, $method, $path);

    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';

    $eventType = 'click';
    $normalizedPath = strtolower(trim($path, '/'));

    if (str_starts_with($normalizedPath, 'pixel/')) {
        $eventType = 'pixel';
    }

    $data = [
        'event_type' => $eventType,
        'ip' => getClientIp(),
        'user_agent' => $userAgent,
        'referer' => $_SERVER['HTTP_REFERER'] ?? null,
        'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
        'accept' => $_SERVER['HTTP_ACCEPT'] ?? null,
        'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? null,
        'request_method' => $method,
        'host' => $_SERVER['HTTP_HOST'] ?? null,
        'scheme' => $scheme,
        'request_uri' => $_SERVER['REQUEST_URI'] ?? null,
        'query_string' => $_SERVER['QUERY_STRING'] ?? null,
        'remote_port' => $_SERVER['REMOTE_PORT'] ?? null,
        'sec_fetch_site' => $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null,
        'sec_fetch_mode' => $_SERVER['HTTP_SEC_FETCH_MODE'] ?? null,
        'sec_fetch_dest' => $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null,
        'sec_ch_ua' => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? null,
        'is_bot' => $bot['is_bot'],
        'bot_reason' => $bot['reason'],
    ];

    $data['visitor_hash'] = buildVisitorHash(
        $data['ip'],
        $data['user_agent'],
    );

    try {
        if (!empty($data['ip'])) {
            $reader = getGeoIpReader(); // assumes you already have this helper
            if ($reader !== null) {
                $record = $reader->city($data['ip']);

                $data['ip_org'] = $record->traits->organization ?? null;
                $data['ip_asn'] = $record->traits->autonomousSystemNumber ?? null;
                $data['ip_country'] = $record->country->isoCode ?? null;
            }
        }
    } catch (Throwable $e) {
        // silently ignore GeoIP failures
    }

    return array_merge($data, calculateConfidence($data));
}

function normalizeTokenFromPath(string $path): string
{
    $token = trim($path, '/');
    return $token === '' ? 'root' : $token;
}

function shouldSkipLogging(string $token, string $path, ?string $userAgent, array $skipMap): bool
{
    $token = strtolower(trim($token, '/'));
    $path = strtolower(trim($path, '/'));
    $ua = strtolower($userAgent ?? '');

    foreach ($skipMap['exact'] ?? [] as $pattern) {
        if ($token === $pattern) {
            return true;
        }
    }

    foreach ($skipMap['contains'] ?? [] as $pattern) {
        if (str_contains($token, $pattern) || str_contains($path, $pattern)) {
            return true;
        }
    }

    foreach ($skipMap['prefix'] ?? [] as $pattern) {
        if (str_starts_with($token, $pattern)) {
            return true;
        }
    }

    $uaSkips = [];

    foreach ($uaSkips as $sig) {
        if ($ua !== '' && str_contains($ua, $sig) && !str_starts_with($token, 'pixel:')) {
            return true;
        }
    }

    return false;
}

function redirectOr404(string $behavior, string $fallbackUrl): void
{
    if ($behavior === '404') {
        http_response_code(404);
        echo 'Not found';
        exit;
    }

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Location: ' . $fallbackUrl, true, 302);
    exit;
}

function getGeoIpReader(): ?\GeoIp2\Database\Reader
{
    static $reader = null;

    if ($reader !== null) {
        return $reader;
    }

    $dbPath = __DIR__ . '/../data/GeoLite2-City.mmdb';

    if (!file_exists($dbPath)) {
        return null;
    }

    try {
        $reader = new \GeoIp2\Database\Reader($dbPath);
        return $reader;
    } catch (Throwable $e) {
        return null;
    }
}
