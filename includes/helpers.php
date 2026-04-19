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

    $emailTo         = trim((string) getSetting($pdo, 'email_to',              ''));
    $emailFrom       = trim((string) getSetting($pdo, 'email_from',            ''));
    $smtpHost        = trim((string) getSetting($pdo, 'email_smtp_host',       ''));
    $smtpPort        = max(1, (int)   getSetting($pdo, 'email_smtp_port',       '587'));
    $smtpUser        = trim((string) getSetting($pdo, 'email_smtp_user',       ''));
    $smtpPass        = trim((string) getSetting($pdo, 'email_smtp_pass',       ''));
    $smtpEncryption  = trim((string) getSetting($pdo, 'email_smtp_encryption', 'tls'));

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
