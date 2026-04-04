<?php
declare(strict_types=1);

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/admin_view.php';
require_once __DIR__ . '/../includes/admin_actions.php';
require_once __DIR__ . '/../includes/router.php';

$pdo = db();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (str_starts_with($path, '/.well-known/acme-challenge/')) {
    http_response_code(404);
    exit;
}

$settings = getAllSettings($pdo);
$pixelEnabled = ($settings['pixel_enabled'] ?? '1') === '1';
$skipPatternMap = getActiveSkipPatternMap($pdo);

/* ======================================================
   HEALTH CHECK
   ====================================================== */
if ($path === '/health') {
    header('Content-Type: application/json');
    echo json_encode(['status' => 'ok']);
    exit;
}

/* ======================================================
   🧠 THREAT FEED
   ====================================================== */
if ($path === '/feed/ips.txt') {
    handleThreatFeed($pdo, $settings);
}

/* ======================================================
   📦 JSON EXPORT
   ====================================================== */
if ($path === '/export/json') {
    handleJsonExport($pdo);
}

/* ======================================================
   ADMIN ACTIONS (POST)
   ====================================================== */
if (handleAdminActions($pdo, $path)) {
    exit;
}

/* ======================================================
   PIXEL TRACKING
   ====================================================== */
if ($pixelEnabled && preg_match('#^/pixel/(.+)\.gif$#', $path)) {
    handlePixelRequest($pdo, $path);
}

/* ======================================================
   ADMIN UI
   ====================================================== */
if ($path === '/admin') {
    handleAdminPage($pdo, $settings);
}

/* ======================================================
   RESERVED ROUTES
   ====================================================== */
$reserved = [
    '/admin',
    '/admin/save-settings',
    '/admin/create-link',
    '/admin/update-link',
    '/admin/delete-link',
    '/admin/deactivate-link',
    '/admin/activate-link',
    '/admin/create-skip-pattern',
    '/admin/deactivate-skip-pattern',
    '/admin/activate-skip-pattern',
    '/admin/delete-skip-pattern',
    '/admin/delete-click',
    '/admin/delete-token-clicks',
    '/health',
    '/feed/ips.txt',
    '/export/json'
];

/* ======================================================
   TRACKED REQUESTS
   ====================================================== */
if (!in_array($path, $reserved, true)) {
    handleTrackedRequest($pdo, $path, $settings, $skipPatternMap);
}

/* ======================================================
   FALLBACK
   ====================================================== */
http_response_code(404);
echo 'Not found';
