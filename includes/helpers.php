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
        'allow_url_include',
        'auto_prepend_file',
        'php://input',
        'php://filter',
        'base64_encode',
        'base64_decode',
        'cmd=',
        'exec=',
        'shell=',
        'wget ',
        'curl ',
        '/bin/sh',
        '/bin/bash',
        'powershell',
        '%ad',
        '-d+',
        '-d%20',
        '../',
        '..%2f',
        '%2e%2e%2f',
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

    $browserSignals = [
        'mozilla/5.0',
        'chrome/',
        'crios/',
        'safari/',
        'firefox/',
        'fxios/',
        'edg/',
        'opr/',
        'opera/',
        'version/',
        'applewebkit/',
        'gecko/',
    ];

    foreach ($browserSignals as $signal) {
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
        'bot', 'crawler', 'spider', 'preview', 'scanner', 'urlscan',
        'wget', 'curl', 'python-requests', 'go-http-client',
        'googleimageproxy', 'bingbot', 'slurp', 'facebookexternalhit',
        'skypeuripreview', 'slackbot', 'discordbot', 'telegrambot',
        'linkedinbot', 'outlook', 'microsoft office', 'safelinks',
        'proofpoint', 'mimecast', 'barracuda', 'symantec', 'trend micro',
        'zgrab', 'masscan', 'nmap', 'sqlmap', 'nikto', 'gobuster',
        'dirbuster', 'feroxbuster', 'httpclient', 'java/', 'libwww-perl',
        'aiohttp', 'httpx', 'restsharp', 'okhttp', 'apache-httpclient',
        'libredtail-http'
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
    $query = strtolower((string)($_SERVER['QUERY_STRING'] ?? ''));
    $host = (string)($_SERVER['HTTP_HOST'] ?? '');
    $reasons = [];

    $signatures = [
        'bot', 'crawler', 'spider', 'preview', 'scanner', 'urlscan',
        'wget', 'curl', 'python-requests', 'go-http-client',
        'googleimageproxy', 'bingbot', 'slurp', 'facebookexternalhit',
        'skypeuripreview', 'slackbot', 'discordbot', 'telegrambot',
        'linkedinbot', 'outlook', 'microsoft office', 'safelinks',
        'proofpoint', 'mimecast', 'barracuda', 'symantec', 'trend micro',
        'zgrab', 'masscan', 'nmap', 'sqlmap', 'nikto', 'gobuster',
        'dirbuster', 'feroxbuster', 'httpclient', 'java/', 'libwww-perl',
        'aiohttp', 'httpx', 'restsharp', 'okhttp', 'apache-httpclient',
        'libredtail-http'
    ];

    foreach ($signatures as $sig) {
        if ($ua !== '' && str_contains($ua, $sig)) {
            $reasons[] = "ua:$sig";
        }
    }

    $junkPaths = [
        'favicon.ico',
        'apple-touch-icon.png',
        'apple-touch-icon-precomposed.png',
        '.env',
        '.git/config',
        '.ds_store',
        'info.php',
        'phpinfo.php',
        'robots.txt',
    ];

    foreach ($junkPaths as $junk) {
        if ($p === strtolower($junk)) {
            $reasons[] = "path:$junk";
        }
    }

    $suspiciousPathParts = [
        '.env',
        '.git/',
        'wp-admin',
        'wp-login',
        'phpinfo',
        'vendor/phpunit',
        '_ignition',
        'eval-stdin.php',
        'autodiscover',
        'actuator',
        'swagger',
        'graphql',
        '.aws/credentials',
    ];

    foreach ($suspiciousPathParts as $part) {
        if ($p !== '' && str_contains($p, strtolower($part))) {
            $reasons[] = "path_contains:$part";
        }
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

    $salt = defined('VISITOR_HASH_SALT') ? VISITOR_HASH_SALT : 'change-this-salt';

    return hash('sha256', $salt . '|' . $ip . '|' . $ua);
}

function calculateConfidence(array $requestData): array
{
    $score = 50;
    $reasons = [];

    $ua = strtolower((string)($requestData['user_agent'] ?? ''));
    $method = strtoupper((string)($requestData['request_method'] ?? ''));
    $referer = (string)($requestData['referer'] ?? '');
    $accept = strtolower((string)($requestData['accept'] ?? ''));
    $acceptLanguage = (string)($requestData['accept_language'] ?? '');
    $secFetchSite = strtolower((string)($requestData['sec_fetch_site'] ?? ''));
    $secFetchMode = strtolower((string)($requestData['sec_fetch_mode'] ?? ''));
    $secFetchDest = strtolower((string)($requestData['sec_fetch_dest'] ?? ''));
    $query = strtolower((string)($requestData['query_string'] ?? ''));
    $host = (string)($requestData['host'] ?? '');
    $path = strtolower((string)($requestData['request_uri'] ?? ''));

    if ($method === 'GET') {
        $score += 10;
        $reasons[] = 'get_request';
    }

    if ($method === 'HEAD') {
        $score -= 40;
        $reasons[] = 'head_request';
    }

    if ($method === 'POST') {
        $score -= 15;
        $reasons[] = 'post_request';
    }

    if ($referer !== '') {
        $score += 8;
        $reasons[] = 'has_referer';
    }

    if (str_contains($accept, 'text/html')) {
        $score += 12;
        $reasons[] = 'accept_html';
    }

    if ($acceptLanguage !== '') {
        $score += 5;
        $reasons[] = 'accept_language_present';
    }

    if ($secFetchSite !== '') {
        $score += 5;
        $reasons[] = 'sec_fetch_site_present';
    }

    if ($secFetchMode === 'navigate') {
        $score += 15;
        $reasons[] = 'sec_fetch_navigate';
    }

    if ($secFetchDest === 'document') {
        $score += 10;
        $reasons[] = 'sec_fetch_document';
    }

    if (isLikelyBrowserUserAgent($ua)) {
        $score += 20;
        $reasons[] = 'browser_ua';
    }

    if ($ua === '') {
        $score -= 25;
        $reasons[] = 'no_ua';
    }

    $badUaPatterns = [
        'curl', 'wget', 'python-requests', 'go-http-client', 'zgrab', 'masscan',
        'sqlmap', 'nikto', 'gobuster', 'dirbuster', 'feroxbuster', 'libredtail-http',
        'aiohttp', 'httpx', 'restsharp', 'okhttp', 'apache-httpclient', 'java/',
        'libwww-perl'
    ];

    foreach ($badUaPatterns as $pattern) {
        if ($ua !== '' && str_contains($ua, $pattern)) {
            $score -= 50;
            $reasons[] = "ua:$pattern";
        }
    }

    $previewPatterns = [
        'preview', 'skype', 'slack', 'outlook', 'microsoft office',
        'safelinks', 'proofpoint', 'mimecast', 'barracuda'
    ];

    foreach ($previewPatterns as $pattern) {
        if ($ua !== '' && str_contains($ua, $pattern)) {
            $score -= 15;
            $reasons[] = "preview:$pattern";
        }
    }

    if (isRawIpHost($host)) {
        $score -= 25;
        $reasons[] = 'host_raw_ip';
    }

    if (hasExploitLikeQuery($query)) {
        $score -= 60;
        $reasons[] = 'exploit_like_query';
    }

    $suspiciousPathParts = [
        '.env',
        '.git/',
        'wp-admin',
        'wp-login',
        'phpinfo',
        'vendor/phpunit',
        '_ignition',
        'eval-stdin.php',
        'autodiscover',
        'actuator',
        'swagger',
        'graphql',
        '.aws/credentials',
    ];

    foreach ($suspiciousPathParts as $part) {
        if ($path !== '' && str_contains($path, strtolower($part))) {
            $score -= 35;
            $reasons[] = "path:$part";
        }
    }

    if (!empty($requestData['is_bot'])) {
        $score -= 30;
        $reasons[] = 'bot_signal';
    }

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

    $data = [
        'event_type' => 'click',
        'ip' => getClientIp(),
        'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
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
        is_string($data['ip']) ? $data['ip'] : null,
        is_string($data['user_agent']) ? $data['user_agent'] : null
    );

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

    $uaSkips = [
        'curl',
        'wget',
        'python-requests',
        'go-http-client',
    ];

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
