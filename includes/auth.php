<?php
declare(strict_types=1);

/* ======================================================
   RATE LIMITING
   Defaults can be overridden in config.local.php:
     define('AUTH_MAX_FAILURES', 5);
     define('AUTH_LOCKOUT_SECS', 900);
   ====================================================== */
if (!defined('AUTH_MAX_FAILURES')) define('AUTH_MAX_FAILURES', 5);
if (!defined('AUTH_LOCKOUT_SECS')) define('AUTH_LOCKOUT_SECS', 900);

/* ======================================================
   CLOUDFLARE ACCESS JWT VERIFICATION
   Optional. Enable by setting in config.local.php:
     define('CF_ACCESS_ENABLED', true);
     define('CF_ACCESS_AUD', 'your-application-audience-tag');
     define('CF_ACCESS_TEAM_DOMAIN', 'yourteam.cloudflareaccess.com');
   When CF_ACCESS_ENABLED is false (default), this is a no-op.
   When DEMO_MODE is true, verification is skipped entirely.
   ====================================================== */

/**
 * Generic access denial to avoid disclosing auth stack details.
 */
function denyAccess(): never
{
    http_response_code(403);
    exit('Access denied.');
}

/**
 * Log a protected /admin probe as a normal SignalTrace event.
 *
 * This reuses the normal request-data collection, scoring, click logging,
 * and alert/email pipeline so the attempt appears in SignalTrace like any
 * other suspicious request.
 */
function logProtectedAdminProbeAsTrackedAttempt(string $reason): void
{
    if (!defined('CF_ACCESS_ENABLED') || !CF_ACCESS_ENABLED) {
        return;
    }

    if (defined('DEMO_MODE') && DEMO_MODE) {
        return;
    }

    try {
        $pdo = db();

        $requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/admin', PHP_URL_PATH) ?: '/admin';

        // Reuse the normal request-data collection pipeline.
        $requestData = collectRequestData($requestPath, $pdo);

        // Force these probes to score as high-confidence bot activity.
        $existingReasons = trim((string) ($requestData['confidence_reason'] ?? ''));
        $reasonParts = [];

        if ($existingReasons !== '') {
            $reasonParts = array_filter(array_map('trim', explode(',', $existingReasons)));
        }

        if (!in_array($reason, $reasonParts, true)) {
            $reasonParts[] = $reason;
        }

        $requestData['confidence_score']  = 5;
        $requestData['confidence_label']  = 'bot';
        $requestData['confidence_reason'] = implode(', ', $reasonParts);

        // Insert as a regular unknown-path style attempt.
        logClick($pdo, [
            'id'          => null,
            'token'       => 'admin',
            'destination' => '',
        ], $requestData);

        maybeFireAlert($pdo, $requestData);
        maybeFireEmailAlert($pdo, $requestData);
        maybeRunAutoCleanup($pdo);
    } catch (\Throwable $e) {
        error_log('SignalTrace: failed to log protected admin probe: ' . $e->getMessage());
    }
}

function verifyCfAccessJwt(): void
{
    // Skip if CF Access is not enabled or this is a demo instance.
    if (!defined('CF_ACCESS_ENABLED') || !CF_ACCESS_ENABLED) {
        return;
    }
    if (defined('DEMO_MODE') && DEMO_MODE) {
        return;
    }

    // CF Access only applies to the admin panel. Feeds and export endpoints
    // use their own token-based authentication and must not require a CF
    // Access session — Splunk, Grafana, and firewalls hit those paths directly.
    $requestPath = strtok($_SERVER['REQUEST_URI'] ?? '', '?');
    if (!str_starts_with((string) $requestPath, '/admin')) {
        return;
    }

    $jwt = $_SERVER['HTTP_CF_ACCESS_JWT_ASSERTION'] ?? '';

    // No JWT at all: likely direct-origin access or opportunistic scanning.
    // Log it through SignalTrace, then return a generic denial to avoid
    // software disclosure and to prevent duplicate events via redirect chains.
    if ($jwt === '') {
        logProtectedAdminProbeAsTrackedAttempt('admin_path_without_access');
        denyAccess();
    }

    $aud        = defined('CF_ACCESS_AUD')         ? CF_ACCESS_AUD         : '';
    $teamDomain = defined('CF_ACCESS_TEAM_DOMAIN') ? CF_ACCESS_TEAM_DOMAIN : '';

    if ($aud === '' || $teamDomain === '') {
        error_log('SignalTrace: CF_ACCESS_ENABLED is true but CF_ACCESS_AUD or CF_ACCESS_TEAM_DOMAIN is not set.');
        http_response_code(500);
        exit('Server configuration error.');
    }

    // Fetch Cloudflare's public keys. Cached in a static variable for the
    // duration of the request so multiple admin sub-requests don't re-fetch.
    static $keySet = null;
    if ($keySet === null) {
        $certsUrl = 'https://' . rtrim($teamDomain, '/') . '/cdn-cgi/access/certs';
        $response = @file_get_contents($certsUrl);
        if ($response === false) {
            error_log('SignalTrace: Failed to fetch Cloudflare Access public keys from ' . $certsUrl);
            http_response_code(503);
            exit('Unable to verify identity. Please try again.');
        }
        $jwks = json_decode($response, true);
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            error_log('SignalTrace: Unexpected Cloudflare Access key response format.');
            http_response_code(503);
            exit('Unable to verify identity. Please try again.');
        }
        try {
            $keySet = \Firebase\JWT\JWK::parseKeySet($jwks);
        } catch (\Throwable $e) {
            error_log('SignalTrace: Failed to parse Cloudflare Access public keys: ' . $e->getMessage());
            http_response_code(503);
            exit('Unable to verify identity. Please try again.');
        }
    }

    // Allow 30 seconds of clock skew between your server and Cloudflare.
    \Firebase\JWT\JWT::$leeway = 30;

    try {
        $decoded = \Firebase\JWT\JWT::decode($jwt, $keySet);
    } catch (\Throwable $e) {
        error_log('SignalTrace: CF Access JWT validation failed: ' . $e->getMessage());
        logProtectedAdminProbeAsTrackedAttempt('admin_path_invalid_cf_access_token');
        denyAccess();
    }

    // Verify the audience claim matches this application.
    $tokenAud = $decoded->aud ?? null;
    $audMatches = false;

    if (is_array($tokenAud)) {
        $audMatches = in_array($aud, $tokenAud, true);
    } elseif (is_string($tokenAud)) {
        $audMatches = hash_equals($aud, $tokenAud);
    }

    if (!$audMatches) {
        error_log('SignalTrace: CF Access JWT audience mismatch.');
        logProtectedAdminProbeAsTrackedAttempt('admin_path_cf_access_audience_mismatch');
        denyAccess();
    }
}

function requireAdminAuth(): void
{
    // Cloudflare Access check — runs first, before Basic Auth.
    // No-op when CF_ACCESS_ENABLED is false or DEMO_MODE is true.
    verifyCfAccessJwt();

    // If CF Access is enabled and verification passed, skip Basic Auth entirely.
    // CF Access with MFA already provides strong identity assurance.
    if (defined('CF_ACCESS_ENABLED') && CF_ACCESS_ENABLED
        && !(defined('DEMO_MODE') && DEMO_MODE)) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $_SESSION['admin_authenticated'] = true;
        return;
    }

    $pdo = db();
    // SECURITY: Use getClientIp() so the lockout IP matches the IP recorded
    // everywhere else — important when behind a trusted proxy.
    $ip  = getClientIp();

    if (isAuthLockedOut($pdo, $ip)) {
        header('HTTP/1.0 429 Too Many Requests');
        header('Retry-After: ' . AUTH_LOCKOUT_SECS);
        exit('Too many failed login attempts. Try again in 15 minutes.');
    }

    if (!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        sendAuthRequest();
    }

    $username   = (string) $_SERVER['PHP_AUTH_USER'];
    $password   = (string) $_SERVER['PHP_AUTH_PW'];
    $usernameOk = hash_equals(ADMIN_USERNAME, $username);
    $passwordOk = password_verify($password, ADMIN_PASSWORD_HASH);

    if (!$usernameOk || !$passwordOk) {
        recordAuthFailure($pdo, $ip);
        sendAuthRequest();
    }

    clearAuthFailures($pdo, $ip);

    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $_SESSION['admin_authenticated'] = true;
}

function isAuthLockedOut(PDO $pdo, string $ip): bool
{
    ensureAuthTable($pdo);
    $since = time() - AUTH_LOCKOUT_SECS;
    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM auth_failures
        WHERE ip = :ip AND failed_at >= :since
    ");
    $stmt->execute([':ip' => $ip, ':since' => $since]);
    return (int) $stmt->fetchColumn() >= AUTH_MAX_FAILURES;
}

function recordAuthFailure(PDO $pdo, string $ip): void
{
    ensureAuthTable($pdo);
    $pdo->prepare("INSERT INTO auth_failures (ip, failed_at) VALUES (:ip, :now)")
        ->execute([':ip' => $ip, ':now' => time()]);
    // Pruning of expired records is handled probabilistically by
    // pruneExpiredAuthFailures() via maybeRunAutoCleanup() — not here,
    // to keep the auth hot path lean under brute-force conditions.
}

function clearAuthFailures(PDO $pdo, string $ip): void
{
    ensureAuthTable($pdo);
    $pdo->prepare("DELETE FROM auth_failures WHERE ip = :ip")->execute([':ip' => $ip]);
}

function ensureAuthTable(PDO $pdo): void
{
    static $ensured = false;
    if ($ensured) {
        return;
    }
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS auth_failures (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT NOT NULL,
            failed_at INTEGER NOT NULL
        )
    ");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_auth_failures_ip ON auth_failures(ip)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_auth_failures_at ON auth_failures(failed_at)");
    $ensured = true;
}

function sendAuthRequest(): void
{
    header('WWW-Authenticate: Basic realm="SignalTrace Admin"');
    header('HTTP/1.0 401 Unauthorized');
    exit('Unauthorized');
}