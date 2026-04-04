<?php
declare(strict_types=1);

function handleAdminActions(PDO $pdo, string $path): bool
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        return false;
    }

    switch ($path) {
        case '/admin/save-settings':
            requireAdminAuth();
            handleSaveSettings($pdo);
            return true;

        case '/admin/save-threat-feed-settings':
            requireAdminAuth();
            handleSaveThreatFeedSettings($pdo);
            return true;

        case '/admin/save-retention-settings':
            requireAdminAuth();
            handleSaveRetentionSettings($pdo);
            return true;

        case '/admin/run-cleanup':
            requireAdminAuth();
            handleRunCleanup($pdo);
            return true;

        case '/admin/create-link':
            requireAdminAuth();
            handleCreateLink($pdo);
            return true;

       case '/admin/update-link':
	    requireAdminAuth();
	    handleUpdateLink($pdo);
	    return true;

        case '/admin/delete-link':
            requireAdminAuth();
            handleDeleteLink($pdo);
            return true;

        case '/admin/deactivate-link':
            requireAdminAuth();
            handleDeactivateLink($pdo);
            return true;

        case '/admin/activate-link':
            requireAdminAuth();
            handleActivateLink($pdo);
            return true;

        case '/admin/create-skip-pattern':
            requireAdminAuth();
            handleCreateSkipPattern($pdo);
            return true;

        case '/admin/add-token-to-skip':
            requireAdminAuth();
            handleAddTokenToSkip($pdo);
            return true;

        case '/admin/delete-skip-pattern':
            requireAdminAuth();
            handleDeleteSkipPattern($pdo);
            return true;

        case '/admin/deactivate-skip-pattern':
            requireAdminAuth();
            handleToggleSkipPattern($pdo, false);
            return true;

        case '/admin/activate-skip-pattern':
            requireAdminAuth();
            handleToggleSkipPattern($pdo, true);
            return true;

        case '/admin/delete-click':
            requireAdminAuth();
            handleDeleteClick($pdo);
            return true;

        case '/admin/delete-token-clicks':
            requireAdminAuth();
            handleDeleteTokenClicks($pdo);
            return true;

        default:
            return false;
    }
}

function handleUpdateLink(PDO $pdo): void
{
    $id = (int)($_POST['id'] ?? 0);
    $token = trim((string)($_POST['token'] ?? ''), '/');
    $destination = trim((string)($_POST['destination'] ?? ''));
    $description = trim((string)($_POST['description'] ?? ''));

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid link id.';
        exit;
    }

    if ($token === '' || $destination === '') {
        http_response_code(400);
        echo 'Path/token and destination are required.';
        exit;
    }

    if (!filter_var($destination, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        echo 'Invalid destination URL.';
        exit;
    }

    if (!preg_match('#^[A-Za-z0-9./_-]+$#', $token)) {
        http_response_code(400);
        echo 'Path/token may contain only letters, numbers, dot, slash, underscore, and dash.';
        exit;
    }

    try {
        updateLink($pdo, $id, $token, $destination, $description);
        header('Location: /admin?tab=links', true, 302);
        exit;
    } catch (Throwable $e) {
        http_response_code(500);
        echo 'Unable to update link. The token/path may already exist.';
        exit;
    }
}

function handleSaveSettings(PDO $pdo): void
{
    $appNameInput = trim((string)($_POST['app_name'] ?? 'SignalTrace'));
    $baseUrlInput = trim((string)($_POST['base_url'] ?? ''));
    $defaultRedirectUrlInput = trim((string)($_POST['default_redirect_url'] ?? ''));
    $unknownPathBehaviorInput = trim((string)($_POST['unknown_path_behavior'] ?? 'redirect'));
    $pixelEnabledInput = isset($_POST['pixel_enabled']) ? '1' : '0';
    $noiseFilterEnabledInput = isset($_POST['noise_filter_enabled']) ? '1' : '0';

    $displayMinScoreInput = trim((string)($_POST['display_min_score'] ?? '20'));

    if ($displayMinScoreInput === '' || !is_numeric($displayMinScoreInput)) {
	    http_response_code(400);
	    echo 'Display minimum score must be numeric.';
	    exit;
    }
    
    $displayMinScoreInput = (string)max(0, min(100, (int)$displayMinScoreInput));

    if ($appNameInput === '') {
        http_response_code(400);
        echo 'App name is required.';
        exit;
    }

    if ($defaultRedirectUrlInput === '' || !filter_var($defaultRedirectUrlInput, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        echo 'A valid default redirect URL is required.';
        exit;
    }

    if ($baseUrlInput !== '' && !filter_var($baseUrlInput, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        echo 'Base URL must be blank or a valid URL.';
        exit;
    }

    if (!in_array($unknownPathBehaviorInput, ['redirect', '404'], true)) {
        http_response_code(400);
        echo 'Invalid unknown path behavior.';
        exit;
    }

    setSetting($pdo, 'app_name', $appNameInput);
    setSetting($pdo, 'base_url', $baseUrlInput);
    setSetting($pdo, 'default_redirect_url', $defaultRedirectUrlInput);
    setSetting($pdo, 'unknown_path_behavior', $unknownPathBehaviorInput);
    setSetting($pdo, 'pixel_enabled', $pixelEnabledInput);
    setSetting($pdo, 'noise_filter_enabled', $noiseFilterEnabledInput);
    setSetting($pdo, 'display_min_score', $displayMinScoreInput);

    header('Location: /admin', true, 302);
    exit;
}

function handleSaveThreatFeedSettings(PDO $pdo): void
{
    $enabledInput = isset($_POST['threat_feed_enabled']) ? '1' : '0';
    $windowHoursInput = max(1, (int)($_POST['threat_feed_window_hours'] ?? 168));
    $minConfidenceInput = strtolower(trim((string)($_POST['threat_feed_min_confidence'] ?? 'suspicious')));

    if (!in_array($minConfidenceInput, ['human', 'likely-human', 'suspicious', 'bot'], true)) {
        http_response_code(400);
        echo 'Invalid minimum confidence value.';
        exit;
    }

    setSetting($pdo, 'threat_feed_enabled', $enabledInput);
    setSetting($pdo, 'threat_feed_window_hours', (string)$windowHoursInput);
    setSetting($pdo, 'threat_feed_min_confidence', $minConfidenceInput);

    header('Location: /admin', true, 302);
    exit;
}

function handleSaveRetentionSettings(PDO $pdo): void
{
    $retentionDaysInput = max(0, (int)($_POST['data_retention_days'] ?? 0));

    setSetting($pdo, 'data_retention_days', (string)$retentionDaysInput);

    header('Location: /admin', true, 302);
    exit;
}

function handleRunCleanup(PDO $pdo): void
{
    $days = (int)getSetting($pdo, 'data_retention_days', '0');

    if ($days <= 0) {
        header('Location: /admin', true, 302);
        exit;
    }

    cleanupOldClicks($pdo, $days);

    header('Location: /admin', true, 302);
    exit;
}

function handleCreateLink(PDO $pdo): void
{
    $token = trim((string)($_POST['token'] ?? ''), '/');
    $destination = trim((string)($_POST['destination'] ?? ''));
    $description = trim((string)($_POST['description'] ?? ''));

    if ($token === '' || $destination === '') {
        http_response_code(400);
        echo 'Path/token and destination are required.';
        exit;
    }

    if (!filter_var($destination, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        echo 'Invalid destination URL.';
        exit;
    }

    if (!preg_match('#^[A-Za-z0-9./_-]+$#', $token)) {
        http_response_code(400);
        echo 'Path/token may contain only letters, numbers, dot, slash, underscore, and dash.';
        exit;
    }

    try {
        createLink($pdo, $token, $destination, $description);
        header('Location: /admin', true, 302);
        exit;
    } catch (Throwable $e) {
        http_response_code(500);
        echo 'Unable to create link. It may already exist.';
        exit;
    }
}

function handleDeleteLink(PDO $pdo): void
{
    $id = (int)($_POST['id'] ?? 0);
    $deleteClicks = isset($_POST['delete_clicks']) && $_POST['delete_clicks'] === '1';

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid link id.';
        exit;
    }

    deleteLink($pdo, $id, $deleteClicks);
    header('Location: /admin', true, 302);
    exit;
}

function handleDeactivateLink(PDO $pdo): void
{
    $id = (int)($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid link id.';
        exit;
    }

    deactivateLink($pdo, $id);
    header('Location: /admin', true, 302);
    exit;
}

function handleActivateLink(PDO $pdo): void
{
    $id = (int)($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid link id.';
        exit;
    }

    activateLink($pdo, $id);
    header('Location: /admin', true, 302);
    exit;
}

function handleCreateSkipPattern(PDO $pdo): void
{
    $type = strtolower(trim((string)($_POST['type'] ?? '')));
    $pattern = strtolower(trim((string)($_POST['pattern'] ?? '')));

    if (!in_array($type, ['exact', 'contains', 'prefix'], true)) {
        http_response_code(400);
        echo 'Invalid skip pattern type.';
        exit;
    }

    if ($pattern === '') {
        http_response_code(400);
        echo 'Pattern is required.';
        exit;
    }

    createSkipPattern($pdo, $type, $pattern);
    header('Location: /admin', true, 302);
    exit;
}

function handleAddTokenToSkip(PDO $pdo): void
{
    $token = strtolower(trim((string)($_POST['token'] ?? '')));
    $redirectToken = trim((string)($_POST['redirect_token'] ?? $token));

    if ($token === '') {
        http_response_code(400);
        echo 'Token is required.';
        exit;
    }

    createSkipPattern($pdo, 'exact', $token);

    if ($redirectToken !== '') {
        header('Location: /admin?token=' . urlencode($redirectToken), true, 302);
    } else {
        header('Location: /admin', true, 302);
    }
    exit;
}

function handleDeleteSkipPattern(PDO $pdo): void
{
    $id = (int)($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid skip pattern id.';
        exit;
    }

    deleteSkipPattern($pdo, $id);
    header('Location: /admin', true, 302);
    exit;
}

function handleToggleSkipPattern(PDO $pdo, bool $active): void
{
    $id = (int)($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid skip pattern id.';
        exit;
    }

    setSkipPatternActive($pdo, $id, $active);
    header('Location: /admin', true, 302);
    exit;
}

function handleDeleteClick(PDO $pdo): void
{
    $id = (int)($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid click id.';
        exit;
    }

    $stmt = $pdo->prepare("DELETE FROM clicks WHERE id = :id");
    $stmt->execute([':id' => $id]);

    header('Location: /admin', true, 302);
    exit;
}

function handleDeleteTokenClicks(PDO $pdo): void
{
    $token = trim((string)($_POST['token'] ?? ''));
    $mode = trim((string)($_POST['mode'] ?? 'unknown_only'));

    if ($token === '') {
        http_response_code(400);
        echo 'Token is required.';
        exit;
    }

    if (!in_array($mode, ['unknown_only', 'all'], true)) {
        http_response_code(400);
        echo 'Invalid delete mode.';
        exit;
    }

    if ($mode === 'unknown_only') {
        $stmt = $pdo->prepare("
            DELETE FROM clicks
            WHERE token = :token
              AND link_id IS NULL
        ");
        $stmt->execute([':token' => $token]);
    } else {
        $stmt = $pdo->prepare("
            DELETE FROM clicks
            WHERE token = :token
        ");
        $stmt->execute([':token' => $token]);
    }

    header('Location: /admin?token=' . urlencode($token), true, 302);
    exit;
}
