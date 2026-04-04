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

    $signals = [
        'mozilla/5.0',
        'chrome/',
        'safari/',
        'firefox/',
        'edg/',
        'applewebkit/',
        'gecko/',
    ];

    foreach ($signals as $s) {
        if (str_contains($ua, $s)) {
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
        'bot','crawler','spider','scanner','preview','wget','curl',
        'python-requests','go-http-client','zgrab','masscan','nmap',
        'sqlmap','nikto','gobuster','dirbuster','feroxbuster',
        'httpclient','java/','libwww-perl','aiohttp','httpx'
    ];

    foreach ($signatures as $sig) {
        if ($ua !== '' && str_contains($ua, $sig)) {
            $reasons[] = "ua:$sig";
        }
    }

    if ($method === 'HEAD') {
        $reasons[] = 'method:HEAD';
    }

    if ($method === 'POST' && hasExploitLikeQuery($query)) {
        $reasons[] = 'post_exploit';
    }

    if (hasExploitLikeQuery($query)) {
        $reasons[] = 'query_exploit';
    }

    if (isRawIpHost($host)) {
        $reasons[] = 'host_raw_ip';
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

    // Method
    if ($method === 'GET') {
        $score += 10;
        $reasons[] = 'get_request';
    }

    if ($method === 'POST') {
        $score -= 8; // reduced
        $reasons[] = 'post_request';
    }

    if ($method === 'HEAD') {
        $score -= 25;
        $reasons[] = 'head_request';
    }

    // Headers
    if ($referer !== '') {
        $score += 6;
        $reasons[] = 'has_referer';
    }

    if ($accept !== '') {
        if (str_contains($accept, 'text/html')) {
            $score += 10;
            $reasons[] = 'accept_html';
        }
    } else {
        $score -= 6;
        $reasons[] = 'accept_missing';
    }

    if ($acceptLanguage !== '') {
        $score += 4;
        $reasons[] = 'accept_language_present';
    } else {
        $score -= 6;
        $reasons[] = 'accept_language_missing';
    }

    if ($secFetchSite !== '' || $secFetchMode !== '' || $secFetchDest !== '') {
        $score += 5;
        $reasons[] = 'sec_headers_present';
    } else {
        $score -= 6;
        $reasons[] = 'sec_headers_missing';
    }

    // UA
    if (isLikelyBrowserUserAgent($ua)) {
        $score += 15;
        $reasons[] = 'browser_ua';
    }

    if ($ua === '') {
        $score -= 20;
        $reasons[] = 'no_ua';
    }

    // Infra / behavior
    if (isRawIpHost($host)) {
        $score -= 15;
        $reasons[] = 'host_raw_ip';
    }

    if (hasExploitLikeQuery($query)) {
        $score -= 50;
        $reasons[] = 'exploit_like_query';
    }

    // Path probing
    $suspiciousPathParts = [
        '.env','.git/','wp-admin','wp-login','phpinfo',
        'vendor/phpunit','_ignition','autodiscover','swagger','graphql'
    ];

    foreach ($suspiciousPathParts as $part) {
        if ($path !== '' && str_contains($path, $part)) {
            $score -= 30;
            $reasons[] = "path:$part";
        }
    }

    // Bot signal
    if (!empty($requestData['is_bot'])) {
        $score -= 10; // reduced
        $reasons[] = 'bot_signal';
    }

    // Clamp
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

    $data['visitor_hash'] = buildVisitorHash($data['ip'], $data['user_agent']);

    return array_merge($data, calculateConfidence($data));
}
