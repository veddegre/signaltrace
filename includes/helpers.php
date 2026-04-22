<?php

declare(strict_types=1);

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* ======================================================
   CLIENT IP
   ====================================================== */

/**
 * Returns a validated client IP.
 * Only trusts X-Forwarded-For when TRUSTED_PROXY_IP is configured and the
 * immediate upstream matches it. Takes the rightmost XFF entry (the one our
 * infrastructure appended), not the leftmost (which a client can forge).
 */
function getClientIp(): string
{
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    if (
        defined('TRUSTED_PROXY_IP')
        && TRUSTED_PROXY_IP !== ''
        && $remoteAddr === TRUSTED_PROXY_IP
        && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])
    ) {
        $parts     = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
        $candidate = end($parts);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    return $remoteAddr;
}

/* ======================================================
   SAFE REDIRECT
   ====================================================== */

function isSafeRedirectUrl(string $url): bool
{
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    return in_array($scheme, ['http', 'https'], true);
}

/**
 * Returns true if the hostname resolves to a private, loopback, or
 * link-local address — used to block SSRF via the webhook URL setting.
 * Checks both literal IP addresses and hostnames that look like private ranges.
 */
function isPrivateOrLoopbackHost(string $host): bool
{
    // Strip port if present.
    $host = preg_replace('/:\d+$/', '', $host) ?? $host;

    // If it's a valid IP, check ranges directly.
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    // Block obvious loopback/metadata hostnames.
    $blocked = ['localhost', '::1', '0.0.0.0'];
    if (in_array($host, $blocked, true)) {
        return true;
    }

    // Block cloud metadata endpoints by hostname pattern.
    if (str_contains($host, '169.254') || str_contains($host, 'metadata.')) {
        return true;
    }

    return false;
}

/* ======================================================
   CSRF TOKENS
   ====================================================== */

function generateCsrfToken(): string
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $token    = (string) ($_POST['csrf_token'] ?? '');
    $expected = (string) ($_SESSION['csrf_token'] ?? '');

    if ($expected === '' || !hash_equals($expected, $token)) {
        http_response_code(403);
        exit('Invalid or missing CSRF token.');
    }
}

/* ======================================================
   BOT / UA DETECTION
   ====================================================== */

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
    $ua      = strtolower($ua);
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
    $ua      = strtolower($ua);
    $signals = [
        'bot','crawler','spider','preview','scanner','urlscan',
        'wget','curl','python-requests','go-http-client',
        'googleimageproxy','bingbot','slurp','facebookexternalhit',
        'skypeuripreview','slackbot','discordbot','telegrambot',
        'linkedinbot','outlook','microsoft office','safelinks',
        'proofpoint','mimecast','barracuda','symantec','trend micro',
        'zgrab','masscan','nmap','sqlmap','nikto','gobuster',
        'dirbuster','feroxbuster','httpclient','java/','libwww-perl',
        'aiohttp','httpx','restsharp','okhttp','apache-httpclient','headlesschrome',
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
    $ua      = strtolower($ua ?? '');
    $query   = strtolower((string) ($_SERVER['QUERY_STRING'] ?? ''));
    $host    = (string) ($_SERVER['HTTP_HOST'] ?? '');
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
   GEOIP  (single consolidated reader using ASN + Country DBs)
   Replaces both the old getGeoIpReader() (City db, dead code)
   and getMaxMindReaders() in db.php.
   ====================================================== */

function getGeoIpReaders(): array
{
    static $readers = null;
    if ($readers !== null) {
        return $readers;
    }

    $asnPath     = getenv('MAXMIND_ASN_DB')     ?: '/var/lib/GeoIP/GeoLite2-ASN.mmdb';
    $countryPath = getenv('MAXMIND_COUNTRY_DB') ?: '/var/lib/GeoIP/GeoLite2-Country.mmdb';

    $asnReader     = null;
    $countryReader = null;

    try {
        if (is_file($asnPath)) {
            $asnReader = new \GeoIp2\Database\Reader($asnPath);
        }
    } catch (Throwable $e) {}

    try {
        if (is_file($countryPath)) {
            $countryReader = new \GeoIp2\Database\Reader($countryPath);
        }
    } catch (Throwable $e) {}

    $readers = ['asn' => $asnReader, 'country' => $countryReader];
    return $readers;
}

function lookupGeoIp(string $ip): array
{
    $result = ['ip_asn' => null, 'ip_org' => null, 'ip_country' => null];

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return $result;
    }

    $readers = getGeoIpReaders();

    if ($readers['asn'] instanceof \GeoIp2\Database\Reader) {
        try {
            $rec             = $readers['asn']->asn($ip);
            $result['ip_asn'] = isset($rec->autonomousSystemNumber)
                ? (string) $rec->autonomousSystemNumber : null;
            $result['ip_org'] = isset($rec->autonomousSystemOrganization)
                ? (string) $rec->autonomousSystemOrganization : null;
        } catch (Throwable $e) {}
    }

    if ($readers['country'] instanceof \GeoIp2\Database\Reader) {
        try {
            $rec                  = $readers['country']->country($ip);
            $result['ip_country'] = isset($rec->country->isoCode)
                ? (string) $rec->country->isoCode : null;
        } catch (Throwable $e) {}
    }

    return $result;
}

/* ======================================================
   CONFIDENCE SCORING
   ====================================================== */

function calculateConfidence(PDO $pdo, array $requestData): array
{
    $score   = 50;
    $reasons = [];

    $ip              = (string) ($requestData['ip'] ?? '');
    $ua              = strtolower((string) ($requestData['user_agent'] ?? ''));
    $method          = strtoupper((string) ($requestData['request_method'] ?? ''));
    $accept          = strtolower((string) ($requestData['accept'] ?? ''));
    $acceptLanguage  = (string) ($requestData['accept_language'] ?? '');
    $acceptEncoding  = strtolower((string) ($requestData['accept_encoding'] ?? ''));
    $host            = (string) ($requestData['host'] ?? '');
    $query           = strtolower((string) ($requestData['query_string'] ?? ''));
    $path            = strtolower((string) ($requestData['request_uri'] ?? ''));
    $referer         = (string) ($requestData['referer'] ?? '');
    $secFetchSite    = strtolower((string) ($requestData['sec_fetch_site'] ?? ''));
    $secFetchMode    = strtolower((string) ($requestData['sec_fetch_mode'] ?? ''));
    $secFetchDest    = strtolower((string) ($requestData['sec_fetch_dest'] ?? ''));
    $secChUa         = (string) ($requestData['sec_ch_ua'] ?? '');
    $secChUaPlatform = (string) ($requestData['sec_ch_ua_platform'] ?? '');
    $org             = strtolower((string) ($requestData['ip_org'] ?? ''));
    $asn             = (string) ($requestData['ip_asn'] ?? '');

    /* === BASE SIGNALS === */

    if ($method === 'GET') { $score += 10; $reasons[] = 'get_request'; }
    if ($method === 'POST') { $score -= 25; $reasons[] = 'post_request'; }

    if ($accept === '') { $score -= 15; $reasons[] = 'accept_missing'; }
    if ($acceptLanguage === '') { $score -= 10; $reasons[] = 'accept_language_missing'; }

    // Accept: */* with a browser UA is a strong signal the UA is spoofed.
    // Real browsers always send specific content-type preferences.
    if ($accept === '*/*') { $score -= 15; $reasons[] = 'accept_wildcard'; }

    // Only award browser_ua bonus when the UA looks like a real browser AND
    // at least one other browser-consistent header is present. This prevents
    // a spoofed Chrome UA with no other browser signals from getting the bonus.
    $hasBrowserHeaders = ($acceptLanguage !== '' || $secFetchMode !== '' || $secChUa !== '');

    if (isLikelyBrowserUserAgent($ua) && !isKnownAutomationUserAgent($ua) && $hasBrowserHeaders) {
        $score += 10; $reasons[] = 'browser_ua';
    } elseif (isLikelyBrowserUserAgent($ua) && !isKnownAutomationUserAgent($ua) && !$hasBrowserHeaders) {
        // UA looks like a browser but no supporting headers — likely spoofed.
        $score -= 10; $reasons[] = 'browser_ua_unsupported';
    }
    if (isKnownAutomationUserAgent($ua)) { $score -= 20; $reasons[] = 'known_automation_ua'; }
    if (isRawIpHost($host)) { $score -= 15; $reasons[] = 'host_raw_ip'; }
    if (hasExploitLikeQuery($query)) { $score -= 40; $reasons[] = 'exploit_like_query'; }
    if (!empty($requestData['is_bot'])) { $score -= 25; $reasons[] = 'bot_signal'; }
    if ($referer === '') { $score -= 5; $reasons[] = 'no_referer'; }

    // Sec-Fetch-* headers are sent by Chromium and Firefox but NOT by Safari.
    // Only apply the missing/incomplete penalty when the UA doesn't look like Safari.
    $isSafariUa = str_contains($ua, 'safari/') && !str_contains($ua, 'chrome/') && !str_contains($ua, 'chromium/') && !str_contains($ua, 'edg/') && !str_contains($ua, 'opr/');

    if (!$isSafariUa) {
        if ($secFetchSite === '' && $secFetchMode === '' && $secFetchDest === '') {
            $score -= 10; $reasons[] = 'sec_fetch_missing';
        } elseif ($secFetchSite === '' || $secFetchMode === '' || $secFetchDest === '') {
            $score -= 8; $reasons[] = 'sec_fetch_incomplete';
        } elseif (
            $secFetchMode === 'navigate'
            && $secFetchDest === 'document'
            && !in_array($secFetchSite, ['none', 'same-origin', 'cross-site'], true)
        ) {
            $score -= 10; $reasons[] = 'sec_fetch_inconsistent';
        }
    } else {
        // Safari sends Sec-Fetch-* inconsistently across versions — only penalise
        // if headers are present but contradictory, not for being absent.
        if (
            $secFetchMode !== '' && $secFetchDest !== ''
            && $secFetchMode === 'navigate'
            && $secFetchDest === 'document'
            && !in_array($secFetchSite, ['none', 'same-origin', 'cross-site', ''], true)
        ) {
            $score -= 10; $reasons[] = 'sec_fetch_inconsistent';
        }
    }

    // Sec-CH-UA is a Chromium-only feature (Client Hints). Safari and Firefox
    // never send it, so only penalise its absence when the UA looks Chromium-based.
    $isChromiumUa = str_contains($ua, 'chrome/') || str_contains($ua, 'chromium/') || str_contains($ua, 'edg/') || str_contains($ua, 'opr/') || str_contains($ua, 'crios/');

    if ($isChromiumUa && $secChUa === '' && $secChUaPlatform === '') {
        $score -= 8; $reasons[] = 'sec_ch_ua_missing';
    }
    if ($acceptEncoding === '') { $score -= 5; $reasons[] = 'accept_encoding_missing'; }

    $selfDomain = (defined('SELF_REFERER_DOMAIN') && SELF_REFERER_DOMAIN !== '')
        ? strtolower(SELF_REFERER_DOMAIN) : '';

    if ($selfDomain !== '' && $referer !== '' && str_contains(strtolower($referer), $selfDomain) && $path === '/') {
        $score -= 15; $reasons[] = 'self_referer_root';
    }

    $hostingSignals = [
        // Major clouds
        'amazon', 'aws', 'microsoft', 'azure', 'google',
        // CDN / DDoS protection
        'cloudflare', 'akamai', 'fastly',
        // VPS / dedicated providers
        'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner',
        'oracle', 'ibm', 'tencent', 'alibaba', 'huawei',
        'hostpapa', 'hostroyale', 'hostinger', 'hostwinds',
        'leaseweb', 'liquidweb', 'choopa',
        'serverius', 'psychz', 'quadranet', 'tzulo',
        'm247', 'combahton', 'heficed', 'datacamp',
        // Generic keywords — specific enough to avoid corporate proxy false positives
        'datacenter', 'data center', 'colocation', 'colo',
        'dedicated server', 'server farm', 'idc',
    ];
    foreach ($hostingSignals as $signal) {
        if ($org !== '' && str_contains($org, $signal)) {
            $score -= 8; $reasons[] = 'hosting_provider_ip'; break;
        }
    }

    $asnPenaltyMap = getActiveAsnPenaltyMap($pdo);
    if ($asn !== '' && isset($asnPenaltyMap[$asn])) {
        $score -= (int) $asnPenaltyMap[$asn];
        $reasons[] = 'asn_rule:' . $asn;
    }

    /* === PATH RISK === */
    if ($path !== '') {
        // High-risk paths: known credential/config file probes (-40)
        foreach ([
            '.env',
            '_environment',
            '.aws/credentials',
            '.ssh/',
            'config.php',
            'configuration.php',
            'wp-config.php',
            'laravel.log',
            '.git',
            'vendor/phpunit',
            '_ignition',
            'eval-stdin.php',
            'shell.php',
            'cmd.php',
            'webshell',
        ] as $part) {
            if (str_contains($path, $part)) { $score -= 40; $reasons[] = "path:$part"; break; }
        }

        // Medium-risk paths: admin panels, debug endpoints, common CMS probes (-25)
        foreach ([
            'wp-admin',
            'wp-login',
            'wp-content',
            'wp-includes',
            'phpinfo',
            'phpmyadmin',
            'adminer',
            'autodiscover',
            'swagger',
            'graphql',
            'actuator/',
            '/console',
            'telescope',
            'horizon',
            '/.well-known/security',
        ] as $part) {
            if (str_contains($path, $part)) { $score -= 25; $reasons[] = "path:$part"; break; }
        }
    }

    /* === TIMING + SCAN DETECTION === */
    if ($ip !== '') {
        $lastSeen = getLastSeenForIp($pdo, $ip);
        $now      = (int) round(microtime(true) * 1000);

        if ($lastSeen !== null) {
            $deltaMs = $now - $lastSeen;
            if ($deltaMs < 1000) { $score -= 40; $reasons[] = 'rapid_repeat'; }
            elseif ($deltaMs < 3000) { $score -= 20; $reasons[] = 'fast_repeat'; }
        }

        $recentCount = getRecentEventCountForIp($pdo, $ip, 10);
        if ($recentCount >= 5) { $score -= 30; $reasons[] = 'burst_activity'; }

        $distinctTokens = getDistinctTokenCountForIp($pdo, $ip, 30);
        if ($distinctTokens >= 3) { $score -= 35; $reasons[] = 'multi_token_scan'; }
    }

    /* === COUNTRY PENALTY === */
    $country = strtoupper((string) ($requestData['ip_country'] ?? ''));
    if ($country !== '') {
        $countryPenaltyMap = getActiveCountryPenaltyMap($pdo);
        if (isset($countryPenaltyMap[$country])) {
            $penalty = $countryPenaltyMap[$country];
            $score  -= $penalty;
            $reasons[] = 'country_penalty:' . $country;
        }
    }

    /* === FINALIZE === */
    $score = max(0, min(100, $score));
    if ($score >= 75)     { $label = 'human'; }
    elseif ($score >= 60) { $label = 'uncertain'; }
    elseif ($score >= 25) { $label = 'suspicious'; }
    else                  { $label = 'bot'; }

    return [
        'confidence_score'  => $score,
        'confidence_label'  => $label,
        'confidence_reason' => implode(', ', array_unique($reasons)),
    ];
}

/* ======================================================
   REQUEST DATA COLLECTION
   ====================================================== */

function collectRequestData(string $path, PDO $pdo): array
{
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $method    = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $bot       = detectBot($userAgent, $method, $path);
    $https     = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

    $eventType      = 'click';
    $normalizedPath = strtolower(trim($path, '/'));
    if (str_starts_with($normalizedPath, 'pixel/')) {
        $eventType = 'pixel';
    }

    $data = [
        'event_type'       => $eventType,
        'ip'               => getClientIp(),
        'user_agent'       => $userAgent,
        'referer'          => $_SERVER['HTTP_REFERER'] ?? null,
        'accept_language'  => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
        'accept'           => $_SERVER['HTTP_ACCEPT'] ?? null,
        'accept_encoding'  => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? null,
        'request_method'   => $method,
        'host'             => $_SERVER['HTTP_HOST'] ?? null,
        'scheme'           => $https ? 'https' : 'http',
        'request_uri'      => $_SERVER['REQUEST_URI'] ?? null,
        'query_string'     => $_SERVER['QUERY_STRING'] ?? null,
        'remote_port'      => $_SERVER['REMOTE_PORT'] ?? null,
        'sec_fetch_site'   => $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null,
        'sec_fetch_mode'   => $_SERVER['HTTP_SEC_FETCH_MODE'] ?? null,
        'sec_fetch_dest'   => $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null,
        'sec_ch_ua'        => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? null,
        'is_bot'           => $bot['is_bot'],
        'bot_reason'       => $bot['reason'],
    ];

    $data['visitor_hash'] = buildVisitorHash($data['ip'], $data['user_agent']);

    // GeoIP lookup using the single consolidated reader.
    if (!empty($data['ip'])) {
        $geo = lookupGeoIp($data['ip']);
        $data['ip_asn']     = $geo['ip_asn'];
        $data['ip_org']     = $geo['ip_org'];
        $data['ip_country'] = $geo['ip_country'];
    }

    // Check for an active IP override — if one exists, skip scoring entirely
    // and apply the pinned classification instead.
    if (!empty($data['ip'])) {
        $override = getIpOverrideByIp($pdo, $data['ip']);
        if ($override && (int) $override['active'] === 1) {
            $mode = (string) $override['mode'];
            if ($mode === 'allow') {
                return array_merge($data, [
                    'confidence_score'  => 100,
                    'confidence_label'  => 'human',
                    'confidence_reason' => 'ip_override:allow',
                ]);
            } else {
                return array_merge($data, [
                    'confidence_score'  => 0,
                    'confidence_label'  => 'bot',
                    'confidence_reason' => 'ip_override:block',
                ]);
            }
        }
    }

    return array_merge($data, calculateConfidence($pdo, $data));
}

/* ======================================================
   ROUTING HELPERS
   ====================================================== */

function normalizeTokenFromPath(string $path): string
{
    $token = trim($path, '/');
    return $token === '' ? 'root' : $token;
}

function shouldSkipLogging(string $token, string $path, ?string $userAgent, array $skipMap): bool
{
    $token = strtolower(trim($token, '/'));
    $path  = strtolower(trim($path, '/'));
    $ua    = strtolower($userAgent ?? '');

    foreach ($skipMap['exact'] ?? [] as $pattern) {
        if ($token === $pattern) return true;
    }
    foreach ($skipMap['contains'] ?? [] as $pattern) {
        if (str_contains($token, $pattern) || str_contains($path, $pattern)) return true;
    }
    foreach ($skipMap['prefix'] ?? [] as $pattern) {
        if (str_starts_with($token, $pattern)) return true;
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

    if (!isSafeRedirectUrl($fallbackUrl)) {
        http_response_code(500);
        error_log('SignalTrace: unsafe default_redirect_url: ' . $fallbackUrl);
        echo 'Configuration error.';
        exit;
    }

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Location: ' . $fallbackUrl, true, 302);
    exit;
}

/* ======================================================
   WEBHOOK ALERTING
   Fires asynchronously (non-blocking curl) so it never
   delays the tracked request response.
   Auto-detects Slack vs generic JSON by URL pattern.
   ====================================================== */

function fireWebhookAlert(PDO $pdo, array $requestData, array $triggerReasons): void
{
    $url = getSetting($pdo, 'webhook_url', '');
    if ($url === '' || !isSafeRedirectUrl($url)) {
        return;
    }

    // SECURITY: Block SSRF — prevent the webhook from being pointed at
    // internal/private IP ranges (cloud metadata endpoints, LAN hosts, etc.)
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($host !== '' && isPrivateOrLoopbackHost($host)) {
        error_log('SignalTrace: webhook URL blocked — resolves to private/loopback address: ' . $url);
        return;
    }

    $ip    = (string) ($requestData['ip'] ?? '');
    $token = (string) ($requestData['request_uri'] ?? '');
    $label = (string) ($requestData['confidence_label'] ?? '');
    $score = (int) ($requestData['confidence_score'] ?? 0);
    $org   = (string) ($requestData['ip_org'] ?? '');
    $asn   = (string) ($requestData['ip_asn'] ?? '');
    $country = (string) ($requestData['ip_country'] ?? '');
    $time  = date('Y-m-d H:i:s T');

    // SECURITY: Truncate and strip control characters from the UA before
    // including it in the payload. A malicious UA could contain Slack markdown
    // or characters that corrupt JSON display in some renderers.
    $rawUa = (string) ($requestData['user_agent'] ?? '');
    $ua    = mb_substr(preg_replace('/[\x00-\x1f\x7f]/', '', $rawUa), 0, 300);

    $triggers = implode(', ', $triggerReasons);

    // Custom template takes priority over auto-detection.
    $template = trim((string) getSetting($pdo, 'webhook_template', ''));

    if ($template !== '') {
        // JSON-encode each value before substitution so a malicious request
        // value (e.g. a UA containing quotes or backslashes) cannot break the
        // JSON structure of the template. json_encode adds surrounding quotes
        // so we strip them for string values the template already quotes.
        $esc = fn(string $v): string => trim((string) json_encode($v), '"');
        $replacements = [
            '{{ip}}'       => $esc($ip),
            '{{token}}'    => $esc($token),
            '{{label}}'    => $esc($label),
            '{{score}}'    => (string) $score,
            '{{org}}'      => $esc($org),
            '{{asn}}'      => $esc($asn),
            '{{country}}'  => $esc($country),
            '{{ua}}'       => $esc($ua),
            '{{time}}'     => $esc($time),
            '{{triggers}}' => $esc($triggers),
        ];
        $json = str_replace(array_keys($replacements), array_values($replacements), $template);

        // Validate the result is still JSON before sending.
        if (json_decode($json) === null) {
            error_log('SignalTrace: webhook template produced invalid JSON — skipping.');
            return;
        }
    } else {
        $isSlack = str_contains($url, 'hooks.slack.com') || str_contains($url, 'discord.com/api/webhooks');

        if ($isSlack) {
            $payload = [
                'text'        => '🚨 *SignalTrace Alert*',
                'attachments' => [[
                    'color'  => '#e53e3e',
                    'fields' => [
                        ['title' => 'IP',       'value' => $ip,      'short' => true],
                        ['title' => 'Token',    'value' => $token,   'short' => true],
                        ['title' => 'Label',    'value' => $label,   'short' => true],
                        ['title' => 'Score',    'value' => (string) $score, 'short' => true],
                        ['title' => 'Triggers', 'value' => $triggers,'short' => false],
                        ['title' => 'Org/ASN',  'value' => "$org (AS$asn)", 'short' => true],
                        ['title' => 'Country',  'value' => $country, 'short' => true],
                        ['title' => 'UA',       'value' => $ua,      'short' => false],
                        ['title' => 'Time',     'value' => $time,    'short' => true],
                    ],
                ]],
            ];
        } else {
            $payload = [
                'event'    => 'signaltrace_alert',
                'ip'       => $ip,
                'token'    => $token,
                'label'    => $label,
                'score'    => $score,
                'triggers' => $triggerReasons,
                'org'      => $org,
                'asn'      => $asn,
                'country'  => $country,
                'ua'       => $ua,
                'time'     => $time,
            ];
        }

        $json = json_encode($payload);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST              => true,
        CURLOPT_POSTFIELDS        => $json,
        CURLOPT_HTTPHEADER        => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_TIMEOUT_MS        => 2000,
        CURLOPT_CONNECTTIMEOUT_MS => 1500,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

/**
 * Called after scoring. Fires the threat webhook if the request meets the
 * configured classification threshold. Skips if a known token webhook fires
 * instead (known tokens use the token webhook, not the threat webhook).
 * Deduplicates: will not alert more than once per IP per 5 minutes.
 */
function maybeFireAlert(PDO $pdo, array $requestData): void
{
    if (defined('DEMO_MODE') && DEMO_MODE) {
        return;
    }

    // If this is a known token hit, the token webhook handles it instead.
    if (!empty($requestData['link_id'])) {
        return;
    }

    $webhookUrl = getSetting($pdo, 'webhook_url', '');
    if ($webhookUrl === '') {
        return;
    }

    $label     = (string) ($requestData['confidence_label'] ?? '');
    $threshold = strtolower((string) getSetting($pdo, 'webhook_threshold', 'bot'));

    $allowedLabels = match ($threshold) {
        'suspicious'   => ['bot', 'suspicious'],
        'uncertain' => ['bot', 'suspicious', 'uncertain'],
        'human'        => ['bot', 'suspicious', 'uncertain', 'human'],
        default        => ['bot'],
    };

    if (!in_array($label, $allowedLabels, true)) {
        return;
    }

    if (!shouldSendAlert($pdo, (string) ($requestData['ip'] ?? ''))) {
        return;
    }

    fireWebhookAlert($pdo, $requestData, [$label . '_classification']);
}

function shouldSendAlert(PDO $pdo, string $ip): bool
{
    if ($ip === '') {
        return false;
    }

    $threshold = strtolower((string) getSetting($pdo, 'webhook_threshold', 'bot'));

    $allowedLabels = match ($threshold) {
        'suspicious'   => ['bot', 'suspicious'],
        'uncertain' => ['bot', 'suspicious', 'uncertain'],
        'human'        => ['bot', 'suspicious', 'uncertain', 'human'],
        default        => ['bot'],
    };

    $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));
    $cutoff       = (int) round(microtime(true) * 1000) - (5 * 60 * 1000);

    $latest = $pdo->prepare("
        SELECT id FROM clicks
        WHERE ip = ?
          AND confidence_label IN ($placeholders)
        ORDER BY id DESC LIMIT 1
    ");
    $latest->execute(array_merge([$ip], $allowedLabels));
    $latestId = (int) ($latest->fetchColumn() ?: 0);

    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM clicks
        WHERE ip = ?
          AND id != ?
          AND clicked_at_unix_ms >= ?
          AND confidence_label IN ($placeholders)
    ");
    $stmt->execute(array_merge([$ip, $latestId, $cutoff], $allowedLabels));

    return (int) $stmt->fetchColumn() === 0;
}

/**
 * Called after scoring for known token hits.
 * Fires the token webhook if configured.
 * Deduplicates per visitor_hash + token per 5 minutes.
 */
function maybeFireTokenAlert(PDO $pdo, array $requestData): void
{
    if (defined('DEMO_MODE') && DEMO_MODE) {
        return;
    }

    // Only fires for known tokens.
    if (empty($requestData['link_id'])) {
        return;
    }

    $webhookUrl = getSetting($pdo, 'token_webhook_url', '');
    if ($webhookUrl === '' || !isSafeRedirectUrl($webhookUrl)) {
        return;
    }

    // Check the per-token opt-in flag.
    $linkId = (int) $requestData['link_id'];
    $stmt = $pdo->prepare("SELECT include_in_token_webhook FROM links WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $linkId]);
    $includeInWebhook = (int) ($stmt->fetchColumn() ?: 0);
    if ($includeInWebhook !== 1) {
        return;
    }

    $visitorHash = (string) ($requestData['visitor_hash'] ?? '');
    $token       = (string) ($requestData['token'] ?? '');

    if (!shouldSendTokenAlert($pdo, $token, $visitorHash)) {
        return;
    }

    fireTokenWebhookAlert($pdo, $requestData);
}

function shouldSendTokenAlert(PDO $pdo, string $token, string $visitorHash): bool
{
    if ($token === '') {
        return false;
    }

    $cutoff = (int) round(microtime(true) * 1000) - (5 * 60 * 1000);

    // Get the most recent click ID for this token+visitor so we can exclude it.
    $latest = $pdo->prepare("
        SELECT id FROM clicks
        WHERE token = :token
          AND visitor_hash = :visitor
          AND link_id IS NOT NULL
        ORDER BY id DESC LIMIT 1
    ");
    $latest->execute([':token' => $token, ':visitor' => $visitorHash]);
    $latestId = (int) ($latest->fetchColumn() ?: 0);

    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM clicks
        WHERE token = :token
          AND visitor_hash = :visitor
          AND link_id IS NOT NULL
          AND id != :latest_id
          AND clicked_at_unix_ms >= :cutoff
    ");
    $stmt->execute([
        ':token'     => $token,
        ':visitor'   => $visitorHash,
        ':latest_id' => $latestId,
        ':cutoff'    => $cutoff,
    ]);

    return (int) $stmt->fetchColumn() === 0;
}

function fireTokenWebhookAlert(PDO $pdo, array $requestData): void
{
    $url = getSetting($pdo, 'token_webhook_url', '');
    if ($url === '' || !isSafeRedirectUrl($url)) {
        return;
    }

    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($host !== '' && isPrivateOrLoopbackHost($host)) {
        error_log('SignalTrace: token webhook URL blocked — resolves to private/loopback address: ' . $url);
        return;
    }

    $ip      = (string) ($requestData['ip']               ?? '');
    $token   = (string) ($requestData['request_uri']      ?? '');
    $label   = (string) ($requestData['confidence_label'] ?? '');
    $score   = (int)    ($requestData['confidence_score'] ?? 0);
    $org     = (string) ($requestData['ip_org']           ?? '');
    $asn     = (string) ($requestData['ip_asn']           ?? '');
    $country = (string) ($requestData['ip_country']       ?? '');
    $time    = date('Y-m-d H:i:s T');

    $rawUa = (string) ($requestData['user_agent'] ?? '');
    $ua    = mb_substr(preg_replace('/[\x00-\x1f\x7f]/', '', $rawUa), 0, 300);

    $reasons  = (string) ($requestData['confidence_reason'] ?? '');
    $template = trim((string) getSetting($pdo, 'token_webhook_template', ''));

    if ($template !== '') {
        $esc = fn(string $v): string => trim((string) json_encode($v), '"');
        $replacements = [
            '{{ip}}'       => $esc($ip),
            '{{token}}'    => $esc($token),
            '{{label}}'    => $esc($label),
            '{{score}}'    => (string) $score,
            '{{org}}'      => $esc($org),
            '{{asn}}'      => $esc($asn),
            '{{country}}'  => $esc($country),
            '{{ua}}'       => $esc($ua),
            '{{time}}'     => $esc($time),
            '{{triggers}}' => $esc($reasons),
        ];
        $json = str_replace(array_keys($replacements), array_values($replacements), $template);

        if (json_decode($json) === null) {
            error_log('SignalTrace: token webhook template produced invalid JSON — skipping.');
            return;
        }
    } else {
        $isSlack = str_contains($url, 'hooks.slack.com') || str_contains($url, 'discord.com/api/webhooks');

        if ($isSlack) {
            $payload = [
                'text'        => '🔔 *SignalTrace Token Hit*',
                'attachments' => [[
                    'color'  => '#4f78f1',
                    'fields' => [
                        ['title' => 'IP',           'value' => $ip,              'short' => true],
                        ['title' => 'Token',        'value' => $token,           'short' => true],
                        ['title' => 'Label',        'value' => $label,           'short' => true],
                        ['title' => 'Score',        'value' => (string) $score,  'short' => true],
                        ['title' => 'Org/ASN',      'value' => "$org (AS$asn)",  'short' => true],
                        ['title' => 'Country',      'value' => $country,         'short' => true],
                        ['title' => 'Signals',      'value' => $reasons,         'short' => false],
                        ['title' => 'UA',           'value' => $ua,              'short' => false],
                        ['title' => 'Time',         'value' => $time,            'short' => true],
                    ],
                ]],
            ];
        } else {
            $payload = [
                'event'    => 'signaltrace_token_hit',
                'ip'       => $ip,
                'token'    => $token,
                'label'    => $label,
                'score'    => $score,
                'triggers' => $reasons,
                'org'      => $org,
                'asn'      => $asn,
                'country'  => $country,
                'ua'       => $ua,
                'time'     => $time,
            ];
        }

        $json = json_encode($payload);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST              => true,
        CURLOPT_POSTFIELDS        => $json,
        CURLOPT_HTTPHEADER        => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_TIMEOUT_MS        => 2000,
        CURLOPT_CONNECTTIMEOUT_MS => 1500,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

/* ======================================================
   EMAIL ALERTING
   Fires when a hit meets the configured email threshold,
   or when a known token with include_in_email=1 is hit.
   Deduplicates per IP with a configurable window (default 60 min).
   Uses PHPMailer for reliable SMTP delivery.
   ====================================================== */

/**
 * Checks threshold and dedup, then fires an email alert for
 * unknown-path hits that meet the configured classification threshold.
 */
function maybeFireEmailAlert(PDO $pdo, array $requestData): void
{
    if (defined('DEMO_MODE') && DEMO_MODE) {
        return;
    }

    if (getSetting($pdo, 'email_enabled', '0') !== '1') {
        return;
    }

    $emailTo = trim((string) getSetting($pdo, 'email_to', ''));
    if ($emailTo === '') {
        return;
    }

    // Only fires for unknown-path hits (no link_id).
    // Known token hits are handled by maybeFireTokenEmailAlert().
    $linkId = $requestData['link_id'] ?? null;
    if ($linkId !== null && $linkId !== '') {
        return;
    }

    $threshold = strtolower((string) getSetting($pdo, 'email_threshold', 'bot'));
    $label     = strtolower((string) ($requestData['confidence_label'] ?? ''));

    $meetsThreshold = match ($threshold) {
        'bot'       => $label === 'bot',
        'suspicious'=> in_array($label, ['bot', 'suspicious'], true),
        'uncertain' => in_array($label, ['bot', 'suspicious', 'uncertain'], true),
        'all'       => true,
        default     => $label === 'bot',
    };

    if (!$meetsThreshold) {
        return;
    }

    $ip           = (string) ($requestData['ip'] ?? '');
    $dedupMinutes = max(1, (int) getSetting($pdo, 'email_dedup_minutes', '60'));

    if (isEmailDedupBlocked($pdo, 'threat_' . $ip, $dedupMinutes)) {
        return;
    }

    fireEmailAlert($pdo, $requestData, 'threat');
    recordEmailDedup($pdo, 'threat_' . $ip);
}

/**
 * Fires an email alert when a known token with include_in_email=1 is hit.
 * Fires on any hit regardless of classification. Deduplicates per token+IP.
 */
function maybeFireTokenEmailAlert(PDO $pdo, array $requestData): void
{
    if (defined('DEMO_MODE') && DEMO_MODE) {
        return;
    }

    if (getSetting($pdo, 'email_enabled', '0') !== '1') {
        return;
    }

    $emailTo = trim((string) getSetting($pdo, 'email_to', ''));
    if ($emailTo === '') {
        return;
    }

    $token  = (string) ($requestData['request_uri'] ?? '');
    $linkId = $requestData['link_id'] ?? null;
    if ($linkId === null || $linkId === '') {
        return;
    }

    // Check if this token has email opted in.
    $stmt = $pdo->prepare("SELECT include_in_email FROM links WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => (int) $linkId]);
    $row = $stmt->fetch();
    if (!$row || (int) ($row['include_in_email'] ?? 0) !== 1) {
        return;
    }

    $ip           = (string) ($requestData['ip'] ?? '');
    $dedupMinutes = max(1, (int) getSetting($pdo, 'email_dedup_minutes', '60'));
    $dedupKey     = 'token_email_' . md5($token . '_' . $ip);

    if (isEmailDedupBlocked($pdo, $dedupKey, $dedupMinutes)) {
        return;
    }

    fireEmailAlert($pdo, $requestData, 'token');
    recordEmailDedup($pdo, $dedupKey);
}

/**
 * Builds and sends the plain text email via PHPMailer/SMTP.
 * $type is 'threat' or 'token' — affects the subject line.
 */
function fireEmailAlert(PDO $pdo, array $requestData, string $type = 'threat'): void
{
    if (!class_exists('\PHPMailer\PHPMailer\PHPMailer')) {
        error_log('SignalTrace: PHPMailer not found — run composer update.');
        return;
    }

    $emailTo        = trim((string) getSetting($pdo, 'email_to', ''));
    $emailFrom      = defined('EMAIL_SMTP_FROM')       ? (string) EMAIL_SMTP_FROM       : '';
    $smtpHost       = defined('EMAIL_SMTP_HOST')       ? (string) EMAIL_SMTP_HOST       : '';
    $smtpPort       = defined('EMAIL_SMTP_PORT')       ? (int)    EMAIL_SMTP_PORT       : 587;
    $smtpUser       = defined('EMAIL_SMTP_USER')       ? (string) EMAIL_SMTP_USER       : '';
    $smtpPass       = defined('EMAIL_SMTP_PASS')       ? (string) EMAIL_SMTP_PASS       : '';
    $smtpEncryption = defined('EMAIL_SMTP_ENCRYPTION') ? (string) EMAIL_SMTP_ENCRYPTION : 'tls';

    if ($emailTo === '' || $smtpHost === '') {
        return;
    }

    $ip      = (string) ($requestData['ip']               ?? '');
    $token   = (string) ($requestData['request_uri']      ?? '');
    $label   = (string) ($requestData['confidence_label'] ?? '');
    $score   = (int)    ($requestData['confidence_score'] ?? 0);
    $org     = (string) ($requestData['ip_org']           ?? '');
    $asn     = (string) ($requestData['ip_asn']           ?? '');
    $country = (string) ($requestData['ip_country']       ?? '');
    $ua      = mb_substr(preg_replace('/[\x00-\x1f\x7f]/', '', (string) ($requestData['user_agent'] ?? '')), 0, 300);
    $reasons = (string) ($requestData['confidence_reason'] ?? '');
    $host    = (string) ($requestData['host']              ?? '');
    $method  = (string) ($requestData['request_method']    ?? '');
    $time    = date('Y-m-d H:i:s T');
    $appName = (string) getSetting($pdo, 'app_name', 'SignalTrace');

    $subject = $type === 'token'
        ? "[{$appName}] Token hit: {$token} from {$ip}"
        : "[{$appName}] {$label} detected: {$ip}";

    $body = implode("\n", [
        $type === 'token' ? "Token hit detected by {$appName}." : "Threat alert from {$appName}.",
        '',
        "Time:          {$time}",
        "IP:            {$ip}",
        "Host:          {$host}",
        "Method:        {$method}",
        "Token / Path:  {$token}",
        "Classification:{$label} (score: {$score})",
        "Org:           {$org}",
        "ASN:           AS{$asn}",
        "Country:       {$country}",
        "Signals:       {$reasons}",
        "User-Agent:    {$ua}",
    ]);

    try {
        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host       = $smtpHost;
        $mail->Port       = $smtpPort;
        $mail->SMTPAuth   = $smtpUser !== '';
        $mail->Username   = $smtpUser;
        $mail->Password   = $smtpPass;
        $mail->SMTPSecure = match ($smtpEncryption) {
            'ssl'  => \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS,
            'none' => '',
            default => \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS,
        };
        $mail->setFrom($emailFrom !== '' ? $emailFrom : $emailTo, $appName);
        $mail->addAddress($emailTo);
        $mail->Subject = $subject;
        $mail->Body    = $body;
        $mail->isHTML(false);
        $mail->Timeout = 5;
        $mail->send();
    } catch (\Throwable $e) {
        error_log('SignalTrace: email alert failed — ' . $e->getMessage());
    }
}

/* ======================================================
   WEBHOOK PRESET TEMPLATES
   ====================================================== */

/**
 * Returns the JSON template string for a named webhook preset.
 * Used to pre-populate the template textarea when a preset is selected.
 *
 * @param  string $preset  'slack'|'discord'|'teams'|'pagerduty'
 * @param  string $type    'threat'|'token'
 * @return string          JSON template with {{placeholder}} syntax
 */
function webhookPresetTemplate(string $preset, string $type): string
{
    $event  = $type === 'token' ? 'signaltrace_token_hit' : 'signaltrace_alert';
    $emoji  = $type === 'token' ? '🔔' : '🚨';
    $title  = $type === 'token' ? 'SignalTrace Token Hit' : 'SignalTrace Threat Alert';
    $color  = $type === 'token' ? '#4f78f1' : '#e53e3e';

    return match ($preset) {
        'slack', 'discord' => json_encode([
            'text'        => "$emoji *$title*",
            'attachments' => [[
                'color'  => $color,
                'fields' => [
                    ['title' => 'IP',      'value' => '{{ip}}',       'short' => true],
                    ['title' => 'Token',   'value' => '{{token}}',    'short' => true],
                    ['title' => 'Label',   'value' => '{{label}}',    'short' => true],
                    ['title' => 'Score',   'value' => '{{score}}',    'short' => true],
                    ['title' => 'Org/ASN', 'value' => '{{org}} (AS{{asn}})', 'short' => true],
                    ['title' => 'Country', 'value' => '{{country}}',  'short' => true],
                    ['title' => 'Signals', 'value' => '{{triggers}}', 'short' => false],
                    ['title' => 'UA',      'value' => '{{ua}}',       'short' => false],
                    ['title' => 'Time',    'value' => '{{time}}',     'short' => true],
                ],
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),

        'teams' => json_encode([
            'type'       => 'message',
            'attachments' => [[
                'contentType' => 'application/vnd.microsoft.card.adaptive',
                'content'     => [
                    '$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
                    'type'    => 'AdaptiveCard',
                    'version' => '1.4',
                    'body'    => [
                        ['type' => 'TextBlock', 'size' => 'Medium', 'weight' => 'Bolder',
                         'text' => "$emoji $title"],
                        ['type' => 'FactSet', 'facts' => [
                            ['title' => 'IP',      'value' => '{{ip}}'],
                            ['title' => 'Token',   'value' => '{{token}}'],
                            ['title' => 'Label',   'value' => '{{label}}'],
                            ['title' => 'Score',   'value' => '{{score}}'],
                            ['title' => 'Org/ASN', 'value' => '{{org}} (AS{{asn}})'],
                            ['title' => 'Country', 'value' => '{{country}}'],
                            ['title' => 'Signals', 'value' => '{{triggers}}'],
                            ['title' => 'UA',      'value' => '{{ua}}'],
                            ['title' => 'Time',    'value' => '{{time}}'],
                        ]],
                    ],
                ],
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),

        'pagerduty' => json_encode([
            'routing_key'  => 'YOUR_PAGERDUTY_INTEGRATION_KEY',
            'event_action' => 'trigger',
            'payload'      => [
                'summary'   => "$title — {{label}} from {{ip}}",
                'severity'  => 'error',
                'source'    => '{{ip}}',
                'timestamp' => '{{time}}',
                'custom_details' => [
                    'token'    => '{{token}}',
                    'label'    => '{{label}}',
                    'score'    => '{{score}}',
                    'org'      => '{{org}}',
                    'asn'      => '{{asn}}',
                    'country'  => '{{country}}',
                    'ua'       => '{{ua}}',
                    'triggers' => '{{triggers}}',
                ],
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),

        'custom' => json_encode([
            'event'    => $event,
            'ip'       => '{{ip}}',
            'token'    => '{{token}}',
            'label'    => '{{label}}',
            'score'    => '{{score}}',
            'org'      => '{{org}}',
            'asn'      => '{{asn}}',
            'country'  => '{{country}}',
            'ua'       => '{{ua}}',
            'time'     => '{{time}}',
            'triggers' => '{{triggers}}',
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),

        default => '',
    };
}

/* ======================================================
   WEBHOOK TEST
   ====================================================== */

/**
 * Fires a clearly-labelled test payload to a webhook URL.
 * Uses the stored template if one is set, otherwise sends generic JSON.
 * Returns an array with 'ok' (bool) and 'message' (string).
 *
 * @param  string $url       Webhook URL to POST to
 * @param  string $template  Stored template (may be empty)
 * @param  string $type      'threat'|'token'
 * @return array{ok: bool, message: string}
 */
function fireTestWebhook(string $url, string $template, string $type): array
{
    if ($url === '' || !isSafeRedirectUrl($url)) {
        return ['ok' => false, 'message' => 'No valid webhook URL configured.'];
    }

    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($host !== '' && isPrivateOrLoopbackHost($host)) {
        return ['ok' => false, 'message' => 'Webhook URL resolves to a private or loopback address.'];
    }

    $time  = date('Y-m-d H:i:s T');
    $event = $type === 'token' ? 'signaltrace_token_hit' : 'signaltrace_alert';
    $emoji = $type === 'token' ? '🔔' : '🚨';
    $title = $type === 'token' ? 'SignalTrace Token Hit' : 'SignalTrace Threat Alert';
    $color = $type === 'token' ? '#4f78f1' : '#e53e3e';

    // Dummy data — clearly labelled as a test
    $dummy = [
        'ip'       => '203.0.113.42',
        'token'    => '/test/canary-path',
        'label'    => 'bot',
        'score'    => '12',
        'org'      => 'TEST-ORG (SignalTrace Test)',
        'asn'      => '64496',
        'country'  => 'US',
        'ua'       => 'SignalTrace-Webhook-Test/1.0',
        'time'     => $time,
        'triggers' => 'accept_missing, sec_fetch_missing, known_automation_ua',
    ];

    if ($template !== '') {
        $esc = fn(string $v): string => trim((string) json_encode($v), '"');
        $replacements = [
            '{{ip}}'       => $esc($dummy['ip']),
            '{{token}}'    => $esc($dummy['token']),
            '{{label}}'    => $esc($dummy['label']),
            '{{score}}'    => $dummy['score'],
            '{{org}}'      => $esc($dummy['org']),
            '{{asn}}'      => $esc($dummy['asn']),
            '{{country}}'  => $esc($dummy['country']),
            '{{ua}}'       => $esc($dummy['ua']),
            '{{time}}'     => $esc($dummy['time']),
            '{{triggers}}' => $esc($dummy['triggers']),
        ];
        $json = str_replace(array_keys($replacements), array_values($replacements), $template);

        if (json_decode($json) === null) {
            return ['ok' => false, 'message' => 'Stored template produced invalid JSON — fix the template before testing.'];
        }
    } else {
        $isSlack = str_contains($url, 'hooks.slack.com') || str_contains($url, 'discord.com/api/webhooks');

        if ($isSlack) {
            $payload = [
                'text'        => "$emoji *[TEST] $title*",
                'attachments' => [[
                    'color'  => $color,
                    'fields' => [
                        ['title' => 'IP',      'value' => $dummy['ip'],       'short' => true],
                        ['title' => 'Token',   'value' => $dummy['token'],    'short' => true],
                        ['title' => 'Label',   'value' => $dummy['label'],    'short' => true],
                        ['title' => 'Score',   'value' => $dummy['score'],    'short' => true],
                        ['title' => 'Org/ASN', 'value' => $dummy['org'] . ' (AS' . $dummy['asn'] . ')', 'short' => true],
                        ['title' => 'Country', 'value' => $dummy['country'],  'short' => true],
                        ['title' => 'Signals', 'value' => $dummy['triggers'], 'short' => false],
                        ['title' => 'UA',      'value' => $dummy['ua'],       'short' => false],
                        ['title' => 'Time',    'value' => $dummy['time'],     'short' => true],
                    ],
                ]],
            ];
        } else {
            $payload = [
                'test'     => true,
                'event'    => $event,
                'ip'       => $dummy['ip'],
                'token'    => $dummy['token'],
                'label'    => $dummy['label'],
                'score'    => (int) $dummy['score'],
                'triggers' => $dummy['triggers'],
                'org'      => $dummy['org'],
                'asn'      => $dummy['asn'],
                'country'  => $dummy['country'],
                'ua'       => $dummy['ua'],
                'time'     => $dummy['time'],
            ];
        }

        $json = (string) json_encode($payload);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST              => true,
        CURLOPT_POSTFIELDS        => $json,
        CURLOPT_HTTPHEADER        => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_TIMEOUT_MS        => 5000,
        CURLOPT_CONNECTTIMEOUT_MS => 3000,
    ]);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    curl_close($ch);

    if ($error !== '') {
        return ['ok' => false, 'message' => 'Connection failed: ' . $error];
    }

    if ($httpCode >= 200 && $httpCode < 300) {
        return ['ok' => true, 'message' => "Test delivered successfully (HTTP $httpCode)."];
    }

    return ['ok' => false, 'message' => "Endpoint returned HTTP $httpCode. Check the URL and try again."];
}

/* ======================================================
   IP ENRICHMENT — Shodan InternetDB
   ====================================================== */

/**
 * Returns true if an IP is private, loopback, or otherwise not suitable
 * for external enrichment lookups.
 */
function isPrivateIp(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return true;
    }
    return !filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

/**
 * Fetches enrichment data for an IP from Shodan InternetDB (no API key required)
 * and caches the result in the ip_enrichment table. Returns the cached or freshly
 * fetched enrichment row, or null if the IP is private or the fetch fails.
 *
 * - Returns immediately from cache if already fetched (including 404 not_found entries)
 * - Skips private/loopback/reserved IPs entirely
 * - On 404: stores not_found=1 so we never retry
 * - On network error: logs and returns null without caching (will retry next time)
 *
 * @return array|null  Keys: ip, ports, vulns, tags, hostnames, not_found, fetched_at
 *                     All data keys are decoded from JSON. null on skip or failure.
 */
function fetchAndCacheEnrichment(PDO $pdo, string $ip): ?array
{
    if (isPrivateIp($ip)) {
        return null;
    }

    // Return from cache if already fetched
    $cached = getEnrichment($pdo, $ip);
    if ($cached !== null) {
        return $cached;
    }

    $url = 'https://internetdb.shodan.io/' . urlencode($ip);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_TIMEOUT_MS        => 5000,
        CURLOPT_CONNECTTIMEOUT_MS => 3000,
        CURLOPT_HTTPHEADER        => ['Accept: application/json'],
        CURLOPT_USERAGENT         => 'SignalTrace/1.0',
        CURLOPT_FOLLOWLOCATION    => false,
    ]);

    $body     = (string) curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    curl_close($ch);

    if ($error !== '') {
        error_log("SignalTrace enrichment: curl error for $ip — $error");
        return null;
    }

    if ($httpCode === 404) {
        // IP not in Shodan — cache as not_found so we skip it in future
        $row = ['ports' => null, 'vulns' => null, 'tags' => null, 'hostnames' => null, 'not_found' => 1];
        saveEnrichment($pdo, $ip, $row);
        return getEnrichment($pdo, $ip);
    }

    if ($httpCode !== 200) {
        error_log("SignalTrace enrichment: unexpected HTTP $httpCode for $ip");
        return null;
    }

    $data = json_decode($body, true);
    if (!is_array($data)) {
        error_log("SignalTrace enrichment: invalid JSON for $ip");
        return null;
    }

    $row = [
        'ports'     => json_encode($data['ports']     ?? []),
        'vulns'     => json_encode($data['vulns']     ?? []),
        'tags'      => json_encode($data['tags']      ?? []),
        'hostnames' => json_encode($data['hostnames'] ?? []),
        'not_found' => 0,
    ];

    saveEnrichment($pdo, $ip, $row);
    return getEnrichment($pdo, $ip);
}

/**
 * Fetches AbuseIPDB confidence score and metadata for an IP.
 * Respects the configured daily limit — returns null without calling the API
 * if the limit has been reached for today.
 * Results are cached in ip_enrichment alongside Shodan data.
 *
 * @return array|null  Keys: abuse_score, abuse_reports, abuse_last_reported,
 *                     abuse_country, abuse_isp, abuse_usage_type, abuse_domain
 *                     null if API key not set, limit reached, private IP, or fetch fails.
 */
function fetchAndCacheAbuseIpDb(PDO $pdo, string $ip, bool $force = false): ?array
{
    if (isPrivateIp($ip)) {
        return null;
    }

    $apiKey = (string) getSetting($pdo, 'abuseipdb_api_key', '');
    if ($apiKey === '') {
        return null;
    }

    $dailyLimit = max(0, (int) getSetting($pdo, 'abuseipdb_daily_limit', '500'));
    if ($dailyLimit === 0) {
        return null;
    }

    // Check and reset daily counter at UTC midnight
    $today     = gmdate('Y-m-d');
    $resetDate = (string) getSetting($pdo, 'abuseipdb_reset_date', '');
    $usedToday = (int) getSetting($pdo, 'abuseipdb_used_today', '0');

    if ($resetDate !== $today) {
        $usedToday = 0;
        setSetting($pdo, 'abuseipdb_used_today', '0');
        setSetting($pdo, 'abuseipdb_reset_date', $today);
    }

    if ($usedToday >= $dailyLimit && !$force) {
        return null;
    }

    // Check if already cached in ip_enrichment
    $cached = getEnrichment($pdo, $ip);
    if ($cached !== null && isset($cached['abuse_score'])) {
        return [
            'abuse_score'          => $cached['abuse_score'],
            'abuse_reports'        => $cached['abuse_reports'],
            'abuse_last_reported'  => $cached['abuse_last_reported'],
            'abuse_country'        => $cached['abuse_country'],
            'abuse_isp'            => $cached['abuse_isp'],
            'abuse_usage_type'     => $cached['abuse_usage_type'],
            'abuse_domain'         => $cached['abuse_domain'],
        ];
    }

    // Fetch from AbuseIPDB v2
    $url = 'https://api.abuseipdb.com/api/v2/check?' . http_build_query([
        'ipAddress'    => $ip,
        'maxAgeInDays' => 90,
        'verbose'      => '',
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_TIMEOUT_MS        => 5000,
        CURLOPT_CONNECTTIMEOUT_MS => 3000,
        CURLOPT_HTTPHEADER        => [
            'Accept: application/json',
            'Key: ' . $apiKey,
        ],
        CURLOPT_USERAGENT         => 'SignalTrace/1.0',
        CURLOPT_FOLLOWLOCATION    => false,
    ]);

    $body     = (string) curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    curl_close($ch);

    if ($error !== '') {
        error_log("SignalTrace AbuseIPDB: curl error for $ip — $error");
        return null;
    }

    if ($httpCode !== 200) {
        error_log("SignalTrace AbuseIPDB: unexpected HTTP $httpCode for $ip");
        return null;
    }

    $data = json_decode($body, true);
    if (!is_array($data) || !isset($data['data'])) {
        error_log("SignalTrace AbuseIPDB: invalid response for $ip");
        return null;
    }

    $d = $data['data'];

    $abuseData = [
        'abuse_score'         => (int) ($d['abuseConfidenceScore'] ?? 0),
        'abuse_reports'       => (int) ($d['totalReports']         ?? 0),
        'abuse_last_reported' => (string) ($d['lastReportedAt']    ?? ''),
        'abuse_country'       => (string) ($d['countryCode']       ?? ''),
        'abuse_isp'           => (string) ($d['isp']               ?? ''),
        'abuse_usage_type'    => (string) ($d['usageType']         ?? ''),
        'abuse_domain'        => (string) ($d['domain']            ?? ''),
    ];

    // Increment daily counter
    setSetting($pdo, 'abuseipdb_used_today', (string) ($usedToday + 1));

    // Save into ip_enrichment — merge with existing Shodan data
    $existing = getEnrichment($pdo, $ip) ?? [];
    $merged   = array_merge($existing, $abuseData);
    saveEnrichment($pdo, $ip, $merged);

    return $abuseData;
}


function buildPublicBaseUrl(array $settings = []): string
{
    $base = trim((string) ($settings['base_url'] ?? ''));
    if ($base !== '') {
        return rtrim($base, '/');
    }

    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    return $host !== '' ? $scheme . '://' . $host : '';
}

function buildDocumentBeaconUrl(array $settings, array $link): string
{
    $base = buildPublicBaseUrl($settings);
    $token = trim((string) ($link['token'] ?? ''), '/');
    $kind = trim((string) ($link['document_kind'] ?? 'docx'));
    if ($base === '' || $token === '') {
        return '';
    }
    return $base . '/pixel/' . rawurlencode($token) . '.gif?src=document&kind=' . rawurlencode($kind);
}

function createDocumentCanaryDocx(array $link, string $beaconUrl, string $outputPath): void
{
    if (!class_exists('ZipArchive')) {
        throw new RuntimeException('ZipArchive is required to generate documents.');
    }

    $title = trim((string) ($link['document_label'] ?? ''));
    if ($title === '') {
        $title = trim((string) ($link['description'] ?? ''));
    }
    if ($title === '') {
        $title = 'Confidential Document';
    }

    $token = (string) ($link['token'] ?? '');
    $recipient = trim((string) ($link['recipient_name'] ?? ''));
    $docNote = $recipient !== '' ? 'Prepared for: ' . $recipient : 'Prepared for internal review';

    $contentTypes = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
XML;

    $rootRels = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
XML;

    $core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      . '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
      . 'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
      . 'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
      . '<dc:title>' . htmlspecialchars($title, ENT_XML1) . '</dc:title>'
      . '<dc:creator>SignalTrace</dc:creator>'
      . '<cp:lastModifiedBy>SignalTrace</cp:lastModifiedBy>'
      . '<dcterms:created xsi:type="dcterms:W3CDTF">' . gmdate('Y-m-d\TH:i:s\Z') . '</dcterms:created>'
      . '<dcterms:modified xsi:type="dcterms:W3CDTF">' . gmdate('Y-m-d\TH:i:s\Z') . '</dcterms:modified>'
      . '</cp:coreProperties>';

    $app = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>SignalTrace</Application>
</Properties>
XML;

    $styles = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:rPr><w:sz w:val="22"/></w:rPr>
  </w:style>
</w:styles>
XML;

    $safeTitle = htmlspecialchars($title, ENT_XML1);
    $safeToken = htmlspecialchars($token, ENT_XML1);
    $safeNote = htmlspecialchars($docNote, ENT_XML1);

    $document = <<<XML
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document
 xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
 xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
 xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:body>
    <w:p>
      <w:pPr><w:spacing w:after="240"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>{$safeTitle}</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:spacing w:after="180"/></w:pPr>
      <w:r><w:rPr><w:sz w:val="22"/></w:rPr><w:t>{$safeNote}</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:spacing w:after="180"/></w:pPr>
      <w:r><w:rPr><w:sz w:val="20"/></w:rPr><w:t>Reference: {$safeToken}</w:t></w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:drawing>
          <wp:inline distT="0" distB="0" distL="0" distR="0">
            <wp:extent cx="9525" cy="9525"/>
            <wp:effectExtent l="0" t="0" r="0" b="0"/>
            <wp:docPr id="1" name="Document Canary Beacon"/>
            <a:graphic>
              <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
                <pic:pic>
                  <pic:nvPicPr>
                    <pic:cNvPr id="0" name="beacon.gif"/>
                    <pic:cNvPicPr/>
                  </pic:nvPicPr>
                  <pic:blipFill>
                    <a:blip r:link="rIdImage1"/>
                    <a:stretch><a:fillRect/></a:stretch>
                  </pic:blipFill>
                  <pic:spPr>
                    <a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm>
                    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                  </pic:spPr>
                </pic:pic>
              </a:graphicData>
            </a:graphic>
          </wp:inline>
        </w:drawing>
      </w:r>
    </w:p>
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>
XML;

    $docRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
      . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
      . '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
      . '<Relationship Id="rIdImage1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="' . htmlspecialchars($beaconUrl, ENT_XML1) . '" TargetMode="External"/>'
      . '</Relationships>';

    @unlink($outputPath);
    $zip = new ZipArchive();
    if ($zip->open($outputPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create DOCX archive.');
    }

    $zip->addFromString('[Content_Types].xml', $contentTypes);
    $zip->addFromString('_rels/.rels', $rootRels);
    $zip->addFromString('docProps/core.xml', $core);
    $zip->addFromString('docProps/app.xml', $app);
    $zip->addFromString('word/document.xml', $document);
    $zip->addFromString('word/styles.xml', $styles);
    $zip->addFromString('word/_rels/document.xml.rels', $docRels);
    $zip->close();
}
