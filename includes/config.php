<?php

declare(strict_types=1);

const DB_PATH = __DIR__ . '/../data/database.db';
const APP_TIMEZONE = 'America/New_York';

date_default_timezone_set(APP_TIMEZONE);

$localConfig = __DIR__ . '/config.local.php';

if (!is_file($localConfig)) {
    http_response_code(500);
    exit('SignalTrace is not configured. Missing includes/config.local.php');
}

require $localConfig;

if (
    !defined('VISITOR_HASH_SALT') || VISITOR_HASH_SALT === ''
    || !defined('ADMIN_USERNAME') || ADMIN_USERNAME === ''
    || !defined('ADMIN_PASSWORD_HASH') || ADMIN_PASSWORD_HASH === ''
) {
    http_response_code(500);
    exit('SignalTrace is not configured. Required config values are missing.');
}

// Demo mode — set in config.local.php. When true the demo banner is shown
// and certain auth thresholds are relaxed for public access.
if (!defined('DEMO_MODE')) {
    define('DEMO_MODE', false);
}
