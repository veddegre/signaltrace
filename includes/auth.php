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

function requireAdminAuth(): void
{
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

    $username = (string) $_SERVER['PHP_AUTH_USER'];
    $password = (string) $_SERVER['PHP_AUTH_PW'];

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

    // Prune rows outside the lockout window so old failures cannot
    // re-trigger a lockout after the window has expired.
    $pdo->prepare("DELETE FROM auth_failures WHERE failed_at < :cutoff")
        ->execute([':cutoff' => time() - AUTH_LOCKOUT_SECS]);
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
