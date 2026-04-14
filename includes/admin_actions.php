<?php

declare(strict_types=1);

function handleAdminActions(PDO $pdo, string $path): bool
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        return false;
    }

    // CSRF verification on every POST before dispatching.
    verifyCsrfToken();

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

        case '/admin/create-asn-rule':
            requireAdminAuth();
            handleCreateAsnRule($pdo);
            return true;

        case '/admin/update-asn-rule':
            requireAdminAuth();
            handleUpdateAsnRule($pdo);
            return true;

        case '/admin/activate-asn-rule':
            requireAdminAuth();
            handleToggleAsnRule($pdo, true);
            return true;

        case '/admin/deactivate-asn-rule':
            requireAdminAuth();
            handleToggleAsnRule($pdo, false);
            return true;

        case '/admin/delete-asn-rule':
            requireAdminAuth();
            handleDeleteAsnRule($pdo);
            return true;

        case '/admin/delete-ip-clicks':
            requireAdminAuth();
            handleDeleteIpClicks($pdo);
            return true;

        case '/admin/delete-filtered-clicks':
            requireAdminAuth();
            handleDeleteFilteredClicks($pdo);
            return true;

        case '/admin/create-ip-override':
            requireAdminAuth();
            handleCreateIpOverride($pdo);
            return true;

        case '/admin/update-ip-override':
            requireAdminAuth();
            handleUpdateIpOverride($pdo);
            return true;

        case '/admin/activate-ip-override':
            requireAdminAuth();
            handleToggleIpOverride($pdo, true);
            return true;

        case '/admin/deactivate-ip-override':
            requireAdminAuth();
            handleToggleIpOverride($pdo, false);
            return true;

        case '/admin/delete-ip-override':
            requireAdminAuth();
            handleDeleteIpOverride($pdo);
            return true;

        default:
            return false;
    }
}

function handleUpdateLink(PDO $pdo): void
{
    $id = (int) ($_POST['id'] ?? 0);
    $token = trim((string) ($_POST['token'] ?? ''), '/');
    $destination = trim((string) ($_POST['destination'] ?? ''));
    $description = trim((string) ($_POST['description'] ?? ''));
    $excludeFromFeed = isset($_POST['exclude_from_feed']) && $_POST['exclude_from_feed'] === '1';

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

    // SECURITY: isSafeRedirectUrl enforces an http/https allowlist in addition
    // to basic URL validation. FILTER_VALIDATE_URL alone accepts javascript: URIs.
    if (!isSafeRedirectUrl($destination)) {
        http_response_code(400);
        echo 'Invalid destination URL. Only http and https are allowed.';
        exit;
    }

    if (!preg_match('#^[A-Za-z0-9./_-]+$#', $token)) {
        http_response_code(400);
        echo 'Path/token may contain only letters, numbers, dot, slash, underscore, and dash.';
        exit;
    }

    try {
        updateLink($pdo, $id, $token, $destination, $description, $excludeFromFeed);
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
    $appNameInput            = trim((string) ($_POST['app_name']            ?? 'SignalTrace'));
    $baseUrlInput            = trim((string) ($_POST['base_url']            ?? ''));
    $defaultRedirectUrlInput = trim((string) ($_POST['default_redirect_url'] ?? ''));
    $unknownPathBehaviorInput = trim((string) ($_POST['unknown_path_behavior'] ?? 'redirect'));
    $pixelEnabledInput       = isset($_POST['pixel_enabled'])       ? '1' : '0';
    $noiseFilterEnabledInput = isset($_POST['noise_filter_enabled']) ? '1' : '0';
    $displayMinScoreInput    = trim((string) ($_POST['display_min_score']   ?? '20'));
    $pageSizeInput           = max(10, min(500, (int) ($_POST['page_size']  ?? 50)));
    $autoRefreshInput        = max(0,  (int) ($_POST['auto_refresh_secs']   ?? 0));
    $webhookUrlInput         = trim((string) ($_POST['webhook_url']         ?? ''));
    $webhookTemplateInput    = trim((string) ($_POST['webhook_template']    ?? ''));
    $exportMinConfidenceInput = strtolower(trim((string) ($_POST['export_min_confidence'] ?? 'suspicious')));
    $exportWindowHoursInput  = max(1, (int) ($_POST['export_window_hours'] ?? 168));
    $exportMinScoreInput     = max(0, min(100, (int) ($_POST['export_min_score'] ?? 0)));

    if ($displayMinScoreInput === '' || !is_numeric($displayMinScoreInput)) {
        http_response_code(400);
        echo 'Display minimum score must be numeric.';
        exit;
    }

    $displayMinScoreInput = (string) max(0, min(100, (int) $displayMinScoreInput));

    if ($appNameInput === '') {
        http_response_code(400);
        echo 'App name is required.';
        exit;
    }

    if ($defaultRedirectUrlInput === '' || !isSafeRedirectUrl($defaultRedirectUrlInput)) {
        http_response_code(400);
        echo 'A valid default redirect URL (http or https) is required.';
        exit;
    }

    if ($baseUrlInput !== '' && !isSafeRedirectUrl($baseUrlInput)) {
        http_response_code(400);
        echo 'Base URL must be blank or a valid http/https URL.';
        exit;
    }

    if (!in_array($unknownPathBehaviorInput, ['redirect', '404'], true)) {
        http_response_code(400);
        echo 'Invalid unknown path behavior.';
        exit;
    }

    if ($webhookUrlInput !== '' && !isSafeRedirectUrl($webhookUrlInput)) {
        http_response_code(400);
        echo 'Webhook URL must be blank or a valid http/https URL.';
        exit;
    }

    if ($webhookTemplateInput !== '') {
        // Validate template produces valid JSON by substituting dummy values.
        $dummyReplacements = [
            '{{ip}}'       => '1.2.3.4',
            '{{token}}'    => '/test',
            '{{label}}'    => 'bot',
            '{{score}}'    => '0',
            '{{org}}'      => 'Test Org',
            '{{asn}}'      => '12345',
            '{{country}}'  => 'US',
            '{{ua}}'       => 'test/1.0',
            '{{time}}'     => date('Y-m-d H:i:s T'),
            '{{triggers}}' => 'bot_classification',
        ];
        $testJson = str_replace(array_keys($dummyReplacements), array_values($dummyReplacements), $webhookTemplateInput);
        if (json_decode($testJson) === null) {
            http_response_code(400);
            echo 'Webhook template does not produce valid JSON. Check your template syntax.';
            exit;
        }
    }

    if (!in_array($exportMinConfidenceInput, ['human', 'likely-human', 'suspicious', 'bot'], true)) {
        http_response_code(400);
        echo 'Invalid export minimum confidence value.';
        exit;
    }

    setSetting($pdo, 'app_name',             $appNameInput);
    setSetting($pdo, 'base_url',             $baseUrlInput);
    setSetting($pdo, 'default_redirect_url', $defaultRedirectUrlInput);
    setSetting($pdo, 'unknown_path_behavior', $unknownPathBehaviorInput);
    setSetting($pdo, 'pixel_enabled',        $pixelEnabledInput);
    setSetting($pdo, 'noise_filter_enabled', $noiseFilterEnabledInput);
    setSetting($pdo, 'display_min_score',    $displayMinScoreInput);
    setSetting($pdo, 'page_size',            (string) $pageSizeInput);
    setSetting($pdo, 'auto_refresh_secs',    (string) $autoRefreshInput);
    setSetting($pdo, 'webhook_url',          $webhookUrlInput);
    setSetting($pdo, 'webhook_template',     $webhookTemplateInput);
    setSetting($pdo, 'export_min_confidence', $exportMinConfidenceInput);
    setSetting($pdo, 'export_window_hours',  (string) $exportWindowHoursInput);
    setSetting($pdo, 'export_min_score',     (string) $exportMinScoreInput);

    header('Location: /admin', true, 302);
    exit;
}

function handleSaveThreatFeedSettings(PDO $pdo): void
{
    $enabledInput = isset($_POST['threat_feed_enabled']) ? '1' : '0';
    $windowHoursInput = max(1, (int) ($_POST['threat_feed_window_hours'] ?? 168));
    $minConfidenceInput = strtolower(trim((string) ($_POST['threat_feed_min_confidence'] ?? 'suspicious')));

    if (!in_array($minConfidenceInput, ['human', 'likely-human', 'suspicious', 'bot'], true)) {
        http_response_code(400);
        echo 'Invalid minimum confidence value.';
        exit;
    }

    setSetting($pdo, 'threat_feed_enabled', $enabledInput);
    setSetting($pdo, 'threat_feed_window_hours', (string) $windowHoursInput);
    setSetting($pdo, 'threat_feed_min_confidence', $minConfidenceInput);

    header('Location: /admin', true, 302);
    exit;
}

function handleSaveRetentionSettings(PDO $pdo): void
{
    $retentionDaysInput = max(0, (int) ($_POST['data_retention_days'] ?? 0));

    setSetting($pdo, 'data_retention_days', (string) $retentionDaysInput);

    header('Location: /admin', true, 302);
    exit;
}

function handleRunCleanup(PDO $pdo): void
{
    $days = (int) getSetting($pdo, 'data_retention_days', '0');

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
    $token = trim((string) ($_POST['token'] ?? ''), '/');
    $destination = trim((string) ($_POST['destination'] ?? ''));
    $description = trim((string) ($_POST['description'] ?? ''));
    $excludeFromFeed = isset($_POST['exclude_from_feed']) && $_POST['exclude_from_feed'] === '1';

    if ($token === '' || $destination === '') {
        http_response_code(400);
        echo 'Path/token and destination are required.';
        exit;
    }

    // SECURITY: Enforce http/https allowlist.
    if (!isSafeRedirectUrl($destination)) {
        http_response_code(400);
        echo 'Invalid destination URL. Only http and https are allowed.';
        exit;
    }

    if (!preg_match('#^[A-Za-z0-9./_-]+$#', $token)) {
        http_response_code(400);
        echo 'Path/token may contain only letters, numbers, dot, slash, underscore, and dash.';
        exit;
    }

    try {
        createLink($pdo, $token, $destination, $description, $excludeFromFeed);
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
    $id = (int) ($_POST['id'] ?? 0);
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
    $id = (int) ($_POST['id'] ?? 0);

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
    $id = (int) ($_POST['id'] ?? 0);

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
    $type = strtolower(trim((string) ($_POST['type'] ?? '')));
    $pattern = strtolower(trim((string) ($_POST['pattern'] ?? '')));

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
    $token = strtolower(trim((string) ($_POST['token'] ?? '')));
    $redirectToken = trim((string) ($_POST['redirect_token'] ?? $token));

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
    $id = (int) ($_POST['id'] ?? 0);

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
    $id = (int) ($_POST['id'] ?? 0);

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
    $id = (int) ($_POST['id'] ?? 0);

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
    $token = trim((string) ($_POST['token'] ?? ''));
    $mode = trim((string) ($_POST['mode'] ?? 'unknown_only'));

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

function handleCreateAsnRule(PDO $pdo): void
{
    $asn = trim((string) ($_POST['asn'] ?? ''));
    $label = trim((string) ($_POST['label'] ?? ''));
    $penalty = (int) ($_POST['penalty'] ?? 10);
    $excludeFromFeed = isset($_POST['exclude_from_feed']) && $_POST['exclude_from_feed'] === '1';

    if ($asn === '' || !ctype_digit($asn)) {
        http_response_code(400);
        echo 'ASN must be numeric.';
        exit;
    }

    $penalty = max(1, min(100, $penalty));

    try {
        createAsnRule($pdo, $asn, $label, $penalty, $excludeFromFeed);
        header('Location: /admin?tab=asn', true, 302);
        exit;
    } catch (Throwable $e) {
        http_response_code(500);
        echo 'Unable to create ASN rule. It may already exist.';
        exit;
    }
}

function handleUpdateAsnRule(PDO $pdo): void
{
    $id = (int) ($_POST['id'] ?? 0);
    $asn = trim((string) ($_POST['asn'] ?? ''));
    $label = trim((string) ($_POST['label'] ?? ''));
    $penalty = (int) ($_POST['penalty'] ?? 10);
    $excludeFromFeed = isset($_POST['exclude_from_feed']) && $_POST['exclude_from_feed'] === '1';

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid ASN rule id.';
        exit;
    }

    if ($asn === '' || !ctype_digit($asn)) {
        http_response_code(400);
        echo 'ASN must be numeric.';
        exit;
    }

    $penalty = max(1, min(100, $penalty));

    try {
        updateAsnRule($pdo, $id, $asn, $label, $penalty, $excludeFromFeed);
        header('Location: /admin?tab=asn', true, 302);
        exit;
    } catch (Throwable $e) {
        http_response_code(500);
        echo 'Unable to update ASN rule. The ASN may already exist on another rule.';
        exit;
    }
}

function handleToggleAsnRule(PDO $pdo, bool $active): void
{
    $id = (int) ($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid ASN rule id.';
        exit;
    }

    setAsnRuleActive($pdo, $id, $active);
    header('Location: /admin?tab=asn', true, 302);
    exit;
}

function handleDeleteAsnRule(PDO $pdo): void
{
    $id = (int) ($_POST['id'] ?? 0);

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid ASN rule id.';
        exit;
    }

    deleteAsnRule($pdo, $id);
    header('Location: /admin?tab=asn', true, 302);
    exit;
}

function handleDeleteIpClicks(PDO $pdo): void
{
    $ip = trim((string) ($_POST['ip'] ?? ''));
    $mode = trim((string) ($_POST['mode'] ?? 'unknown_only'));

    if ($ip === '') {
        http_response_code(400);
        echo 'IP is required.';
        exit;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo 'Invalid IP address.';
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
            WHERE ip = :ip
              AND link_id IS NULL
        ");
        $stmt->execute([':ip' => $ip]);
    } else {
        $stmt = $pdo->prepare("
            DELETE FROM clicks
            WHERE ip = :ip
        ");
        $stmt->execute([':ip' => $ip]);
    }

    header('Location: /admin?ip=' . urlencode($ip), true, 302);
    exit;
}

/* ======================================================
   IP OVERRIDE HANDLERS
   ====================================================== */

function handleCreateIpOverride(PDO $pdo): void
{
    $ip    = trim((string) ($_POST['ip']    ?? ''));
    $mode  = trim((string) ($_POST['mode']  ?? 'block'));
    $notes = trim((string) ($_POST['notes'] ?? ''));

    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo 'Invalid IP address.';
        exit;
    }

    if (!in_array($mode, ['allow', 'block'], true)) {
        http_response_code(400);
        echo 'Invalid mode.';
        exit;
    }

    createIpOverride($pdo, $ip, $mode, $notes);
    header('Location: /admin?tab=overrides', true, 302);
    exit;
}

function handleUpdateIpOverride(PDO $pdo): void
{
    $id    = (int) ($_POST['id']    ?? 0);
    $ip    = trim((string) ($_POST['ip']    ?? ''));
    $mode  = trim((string) ($_POST['mode']  ?? 'block'));
    $notes = trim((string) ($_POST['notes'] ?? ''));

    if ($id <= 0) {
        http_response_code(400);
        echo 'Invalid id.';
        exit;
    }

    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo 'Invalid IP address.';
        exit;
    }

    if (!in_array($mode, ['allow', 'block'], true)) {
        http_response_code(400);
        echo 'Invalid mode.';
        exit;
    }

    updateIpOverride($pdo, $id, $ip, $mode, $notes);
    header('Location: /admin?tab=overrides', true, 302);
    exit;
}

function handleToggleIpOverride(PDO $pdo, bool $active): void
{
    $id = (int) ($_POST['id'] ?? 0);
    if ($id <= 0) {
        http_response_code(400);
        exit;
    }
    setIpOverrideActive($pdo, $id, $active);
    header('Location: /admin?tab=overrides', true, 302);
    exit;
}

function handleDeleteIpOverride(PDO $pdo): void
{
    $id = (int) ($_POST['id'] ?? 0);
    if ($id <= 0) {
        http_response_code(400);
        exit;
    }
    deleteIpOverride($pdo, $id);
    header('Location: /admin?tab=overrides', true, 302);
    exit;
}

function handleDeleteFilteredClicks(PDO $pdo): void
{
    $tokenFilter   = trim((string) ($_POST['token']     ?? ''));
    $ipFilter      = trim((string) ($_POST['ip']        ?? ''));
    $visitorFilter = trim((string) ($_POST['visitor']   ?? ''));
    $knownOnly     = isset($_POST['known']) && $_POST['known'] === '1';
    $dateFrom      = trim((string) ($_POST['date_from'] ?? ''));
    $dateTo        = trim((string) ($_POST['date_to']   ?? ''));

    // Require at least one filter — refuse to delete everything with no filter
    if ($tokenFilter === '' && $ipFilter === '' && $visitorFilter === ''
        && !$knownOnly && $dateFrom === '' && $dateTo === '') {
        http_response_code(400);
        echo 'At least one filter is required for bulk delete.';
        exit;
    }

    $where  = ['1=1'];
    $params = [];

    if ($tokenFilter !== '') {
        $where[]  = 'token LIKE :token';
        $params[':token'] = '%' . $tokenFilter . '%';
    }
    if ($ipFilter !== '') {
        $where[]  = 'ip = :ip';
        $params[':ip'] = $ipFilter;
    }
    if ($visitorFilter !== '') {
        $where[]  = 'visitor_hash = :visitor';
        $params[':visitor'] = $visitorFilter;
    }
    if ($knownOnly) {
        $where[] = 'link_id IS NOT NULL';
    }
    if ($dateFrom !== '') {
        $where[]  = 'clicked_at >= :date_from';
        $params[':date_from'] = $dateFrom;
    }
    if ($dateTo !== '') {
        $where[]  = 'clicked_at <= :date_to';
        $params[':date_to'] = $dateTo . ' 23:59:59';
    }

    $sql  = 'DELETE FROM clicks WHERE ' . implode(' AND ', $where);
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    // Redirect back to dashboard with filters cleared
    header('Location: /admin', true, 302);
    exit;
}
