<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/admin_view.php';
require_once __DIR__ . '/../includes/admin_actions.php';
require_once __DIR__ . '/../includes/router.php';

/* ============================================================
   PATH — must be parsed first; everything else branches on it
   ============================================================ */
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

/* ============================================================
   SESSION — only for admin UI routes
   ============================================================ */

// Generate a per-request CSP nonce for admin routes. Generated here so it is
// available to both demo-banner.php (included below) and renderAdminPage().
$cspNonce = base64_encode(random_bytes(16));
$GLOBALS['cspNonce'] = $cspNonce;

if (str_starts_with($path, '/admin') && session_status() === PHP_SESSION_NONE) {
    session_start();
    if (defined('DEMO_MODE') && DEMO_MODE) {
        require_once __DIR__ . '/../includes/demo-banner.php';
    }
}

/* ============================================================
   SECURITY HEADERS
   ============================================================ */
$dataRoutes = ['/export/json', '/export/csv', '/feed/ips.txt', '/health'];

header('X-Content-Type-Options: nosniff');

if (!in_array($path, $dataRoutes, true)) {
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    if (str_starts_with($path, '/admin')) {
        // Strict CSP with per-request nonce for the admin panel.
        // Inline styles are permitted (lower risk than scripts).
        // Google Fonts allowed for IBM Plex typeface.
        header("Content-Security-Policy: "
            . "default-src 'self'; "
            . "script-src 'nonce-{$cspNonce}'; "
            . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            . "font-src 'self' https://fonts.gstatic.com; "
            . "img-src 'self' data:; "
            . "connect-src 'self'; "
            . "frame-ancestors 'none';"
        );
    } else {
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");
    }
}

/* ============================================================
   BOOTSTRAP
   ============================================================ */
$pdo = db();

if (str_starts_with($path, '/.well-known/acme-challenge/')) {
    http_response_code(404);
    exit;
}

$settings       = getAllSettings($pdo);
$pixelEnabled   = ($settings['pixel_enabled'] ?? '1') === '1';
$skipPatternMap = getActiveSkipPatternMap($pdo);

/* ============================================================
   EXPORT API TOKEN AUTH
   ============================================================ */
function requireExportAuth(): void
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($authHeader, 'Bearer ')) {
        $provided = substr($authHeader, 7);
        if (defined('EXPORT_API_TOKEN') && EXPORT_API_TOKEN !== '' && hash_equals(EXPORT_API_TOKEN, $provided)) {
            return;
        }
    }

    $queryToken = trim((string) ($_GET['api_key'] ?? ''));
    if ($queryToken !== '' && defined('EXPORT_API_TOKEN') && EXPORT_API_TOKEN !== '' && hash_equals(EXPORT_API_TOKEN, $queryToken)) {
        return;
    }

    requireAdminAuth();
}

/* ============================================================
   STATIC ASSETS
   ============================================================ */
if ($path === '/favicon.ico' || $path === '/favicon.png') {
    $logoPath = __DIR__ . '/signaltrace_transparent.png';
    if (is_file($logoPath)) {
        header('Content-Type: image/png');
        header('Cache-Control: public, max-age=86400');
        readfile($logoPath);
    } else {
        http_response_code(404);
    }
    exit;
}

if ($path === '/admin.css') {
    requireAdminAuth();
    $cssPath = __DIR__ . '/admin.css';
    if (is_file($cssPath)) {
        header('Content-Type: text/css');
        header('Cache-Control: private, max-age=3600');
        readfile($cssPath);
    } else {
        http_response_code(404);
    }
    exit;
}

if ($path === '/signaltrace_transparent.png') {
    requireAdminAuth();
    $logoPath = __DIR__ . '/signaltrace_transparent.png';
    if (is_file($logoPath)) {
        header('Content-Type: image/png');
        header('Cache-Control: private, max-age=86400');
        readfile($logoPath);
    } else {
        http_response_code(404);
    }
    exit;
}

/* ============================================================
   HEALTH CHECK
   ============================================================ */
if ($path === '/health') {
    header('Content-Type: application/json');
    echo json_encode(['status' => 'ok']);
    exit;
}

/* ============================================================
   THREAT FEED
   ============================================================ */
$feedPaths = [
    '/feed/ips.txt', '/feed/ips.nginx', '/feed/ips.iptables', '/feed/ips.cidr',
    '/feed/ipv6.txt', '/feed/ipv6.nginx', '/feed/ipv6.iptables', '/feed/ipv6.cidr',
    '/feed/misp.json', '/feed/stix.json',
];
if (in_array($path, $feedPaths, true)) {
    requireAdminAuth();
    handleThreatFeed($pdo, $settings, $path);
}

/* ============================================================
   EXPORTS
   ============================================================ */
if ($path === '/export/json') {
    requireExportAuth();
    handleExport($pdo, 'json');
}

if ($path === '/export/csv') {
    requireExportAuth();
    handleExport($pdo, 'csv');
}

if ($path === '/export/stats') {
    requireExportAuth();
    handleExportStats($pdo);
    exit;
}

if ($path === '/export/stats/extended') {
    requireExportAuth();
    handleExportStatsExtended($pdo);
    exit;
}

if ($path === '/export/by-ip') {
    requireExportAuth();
    handleExportByIp($pdo);
    exit;
}

if ($path === '/export/by-country') {
    requireExportAuth();
    handleExportByCountry($pdo);
    exit;
}

if ($path === '/export/by-token') {
    requireExportAuth();
    handleExportByToken($pdo);
    exit;
}

if ($path === '/export/by-org') {
    requireExportAuth();
    handleExportByOrg($pdo);
    exit;
}

if ($path === '/export/by-signal') {
    requireExportAuth();
    handleExportBySignal($pdo);
    exit;
}

if ($path === '/export/behavioral') {
    requireExportAuth();
    handleExportBehavioralSignals($pdo);
    exit;
}

if ($path === '/export/over-time') {
    requireExportAuth();
    handleExportOverTime($pdo);
    exit;
}

/* ============================================================
   ADMIN ACTIONS (POST)
   ============================================================ */
if (handleAdminActions($pdo, $path)) {
    exit;
}

/* ============================================================
   ADMIN GET ENDPOINTS
   ============================================================ */
if ($path === '/admin/webhook-preset') {
    requireAdminAuth();
    handleWebhookPreset();
    exit;
}

/* ============================================================
   PIXEL TRACKING
   ============================================================ */
if ($pixelEnabled && preg_match('#^/pixel/(.+)\.gif$#', $path)) {
    handlePixelRequest($pdo, $path);
}

/* ============================================================
   ADMIN UI
   ============================================================ */
if ($path === '/admin') {
    handleAdminPage($pdo, $settings);
}

/* ============================================================
   RESERVED ROUTES — excluded from honeypot tracking
   ============================================================ */
$reserved = [
    '/admin',
    '/admin/save-settings',
    '/admin/create-link',
    '/admin/update-link',
    '/admin/delete-link',
    '/admin/deactivate-link',
    '/admin/activate-link',
    '/admin/create-skip-pattern',
    '/admin/add-token-to-skip',
    '/admin/deactivate-skip-pattern',
    '/admin/activate-skip-pattern',
    '/admin/delete-skip-pattern',
    '/admin/delete-click',
    '/admin/delete-token-clicks',
    '/admin/delete-ip-clicks',
    '/admin/delete-filtered-clicks',
    '/admin/create-asn-rule',
    '/admin/update-asn-rule',
    '/admin/activate-asn-rule',
    '/admin/deactivate-asn-rule',
    '/admin/delete-asn-rule',
    '/admin/create-ip-override',
    '/admin/update-ip-override',
    '/admin/activate-ip-override',
    '/admin/deactivate-ip-override',
    '/admin/delete-ip-override',
    '/admin/create-country-rule',
    '/admin/update-country-rule',
    '/admin/activate-country-rule',
    '/admin/deactivate-country-rule',
    '/admin/delete-country-rule',
    '/admin/save-threat-feed-settings',
    '/admin/save-retention-settings',
    '/admin/save-rate-limit-settings',
    '/admin/run-cleanup',
    '/admin/test-threat-webhook',
    '/admin/test-token-webhook',
    '/admin/webhook-preset',
    '/health',
    '/admin.css',
    '/favicon.ico',
    '/favicon.png',
    '/signaltrace_transparent.png',
    '/feed/ips.txt',
    '/feed/ips.nginx',
    '/feed/ips.iptables',
    '/feed/ips.cidr',
    '/feed/ipv6.txt',
    '/feed/ipv6.nginx',
    '/feed/ipv6.iptables',
    '/feed/ipv6.cidr',
    '/export/json',
    '/export/csv',
    '/export/stats',
    '/export/stats/extended',
    '/export/by-ip',
    '/export/by-country',
    '/export/by-token',
    '/export/by-org',
    '/export/by-signal',
    '/export/behavioral',
    '/export/over-time',
    '/feed/misp.json',
    '/feed/stix.json',
];

/* ============================================================
   TRACKED REQUESTS
   ============================================================ */
if (!in_array($path, $reserved, true)) {
    handleTrackedRequest($pdo, $path, $settings, $skipPatternMap);
}

/* ============================================================
   FALLBACK
   ============================================================ */
http_response_code(404);
echo 'Not found';
