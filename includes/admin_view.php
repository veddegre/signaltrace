<?php
declare(strict_types=1);

function renderAdminPage(
    string $appName,
    string $baseUrl,
    string $defaultRedirectUrl,
    string $unknownPathBehavior,
    bool $pixelEnabled,
    bool $noiseFilterEnabled,
    string $tokenFilter,
    string $ipFilter,
    string $visitorFilter,
    bool $knownOnly,
    array $clicks,
    int $totalCount,
    int $totalPages,
    int $currentPage,
    int $pageSize,
    array $links,
    array $tokenCounts,
    array $skipPatterns,
    array $asnRules,
    string $refreshUrl,
    ?array $ipSummary = null,
): void {
    $pdo       = db();
    $csrfToken = generateCsrfToken();
    $isDemo    = defined('DEMO_MODE') && DEMO_MODE;

    $autoRefreshSecs  = max(0, (int) getSetting($pdo, 'auto_refresh_secs', '0'));
    $webhookUrl       = (string) getSetting($pdo, 'webhook_url', '');
    $webhookTemplate  = (string) getSetting($pdo, 'webhook_template', '');
    $pageSizeSetting  = (string) getSetting($pdo, 'page_size', '50');
    $exportMinConf    = (string) getSetting($pdo, 'export_min_confidence', 'suspicious');
    $exportWinHours   = (string) getSetting($pdo, 'export_window_hours', '168');
    $exportMinScore   = (string) getSetting($pdo, 'export_min_score', '0');

    $dateFrom = trim((string) ($_GET['date_from'] ?? ''));
    $dateTo   = trim((string) ($_GET['date_to']   ?? ''));
    $showAll  = isset($_GET['show_all']) && $_GET['show_all'] === '1';

    $activeTab  = trim((string) ($_GET['tab'] ?? ''));
    $editLinkId = (int) ($_GET['edit_link_id'] ?? 0);

    $editLink = null;
    if ($editLinkId > 0) {
        foreach ($links as $candidateLink) {
            if ((int) $candidateLink['id'] === $editLinkId) {
                $editLink = $candidateLink;
                break;
            }
        }
    }

    $editAsnRuleId = (int) ($_GET['edit_asn_rule_id'] ?? 0);
    $editAsnRule = null;
    if ($editAsnRuleId > 0) {
        foreach ($asnRules as $candidateRule) {
            if ((int) $candidateRule['id'] === $editAsnRuleId) {
                $editAsnRule = $candidateRule;
                break;
            }
        }
    }

    $hasActiveFilter = (
        $tokenFilter !== ''
        || $ipFilter !== ''
        || $visitorFilter !== ''
    || $knownOnly
    || $showAll
        || $dateFrom !== ''
        || $dateTo !== ''
    );
    $exportUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . '/export/json';

    $threatFeedEnabled = getSetting($pdo, 'threat_feed_enabled', '1') === '1';
    $threatFeedWindowHours = (string) (getSetting($pdo, 'threat_feed_window_hours', '168') ?? '168');
    $threatFeedMinConfidence = (string) (getSetting($pdo, 'threat_feed_min_confidence', 'suspicious') ?? 'suspicious');
    $threatFeedMinHits = (string) (getSetting($pdo, 'threat_feed_min_hits', '1') ?? '1');
    $dataRetentionDays = (string) (getSetting($pdo, 'data_retention_days', '0') ?? '0');

    $ipOverrides       = getIpOverrides($pdo);
    $behavioralFlags   = getBehaviorallyFlaggedIps($pdo, 24);
    $ipOverrideMap     = getActiveIpOverrideMap($pdo);
    $countryRules      = getCountryRules($pdo);

    $editOverrideId = (int) ($_GET['edit_override_id'] ?? 0);
    $editOverride   = null;
    if ($editOverrideId > 0) {
        foreach ($ipOverrides as $candidate) {
            if ((int) $candidate['id'] === $editOverrideId) {
                $editOverride = $candidate;
                break;
            }
        }
    }

    $editCountryId   = (int) ($_GET['edit_country_id'] ?? 0);
    $editCountryRule = null;
    if ($editCountryId > 0) {
        foreach ($countryRules as $candidate) {
            if ((int) $candidate['id'] === $editCountryId) {
                $editCountryRule = $candidate;
                break;
            }
        }
    }

    $buildAdminUrl = function (array $overrides = []) use ($tokenFilter, $ipFilter, $visitorFilter, $knownOnly, $dateFrom, $dateTo, $showAll, $activeTab): string {
        $params = [];

        if ($tokenFilter !== '') {
            $params['token'] = $tokenFilter;
        }
        if ($ipFilter !== '') {
            $params['ip'] = $ipFilter;
        }
        if ($visitorFilter !== '') {
            $params['visitor'] = $visitorFilter;
        }
        if ($knownOnly) {
            $params['known'] = '1';
        }
        if ($dateFrom !== '') {
            $params['date_from'] = $dateFrom;
        }
        if ($dateTo !== '') {
            $params['date_to'] = $dateTo;
        }
        if ($showAll) {
            $params['show_all'] = '1';
        }

        if ($activeTab !== '') {
            $params['tab'] = $activeTab;
        }

        foreach ($overrides as $key => $value) {
            if ($value === null || $value === '') {
                unset($params[$key]);
            } else {
                $params[$key] = $value;
            }
        }

        return '/admin' . (!empty($params) ? '?' . http_build_query($params) : '');
    };

    $buildExportUrl = function () use ($tokenFilter, $ipFilter, $visitorFilter, $knownOnly, $dateFrom, $dateTo, $showAll, $activeTab): string {
        $params = [];

        if ($tokenFilter !== '') {
            $params['token'] = $tokenFilter;
        }
        if ($ipFilter !== '') {
            $params['ip'] = $ipFilter;
        }
        if ($visitorFilter !== '') {
            $params['visitor'] = $visitorFilter;
        }
        if ($knownOnly) {
            $params['known'] = '1';
        }
        if ($dateFrom !== '') {
            $params['date_from'] = $dateFrom;
        }
        if ($dateTo !== '') {
            $params['date_to'] = $dateTo;
        }

        return '/expor/json' . (!empty($params) ? '?' . http_build_query($params) : '');
    };

    $threatFeedUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . '/feed/ips.txt';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title><?= h($appName) ?></title>
	<link rel="stylesheet" href="/admin.css">
        <link rel="icon" type="image/png" href="/signaltrace_transparent.png">
        <link rel="apple-touch-icon" href="/signaltrace_transparent.png">
    </head>
    <body>
        <header class="page-header">
            <div class="page-header-left">
                <a href="/admin" class="header-home-link">
                    <img src="/signaltrace_transparent.png" alt="SignalTrace" class="header-logo">
                    <h1><?= h($appName) ?></h1>
                </a>
                <span class="header-tag">Admin</span>
            </div>
            <button type="button" class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" title="Toggle dark mode">
                <span class="theme-icon" id="theme-icon">☀️</span>
                <span id="theme-label">Light</span>
            </button>
        </header>
        <div class="page-body">

        <div class="tabs">
            <div class="tab" id="tab-dashboard" onclick="showTab('dashboard')">Dashboard</div>
            <div class="tab" id="tab-links" onclick="showTab('links')">Tokens</div>
	    <div class="tab" id="tab-skip" onclick="showTab('skip')">Skip Patterns</div>
            <div class="tab" id="tab-asn" onclick="showTab('asn')">ASN Rules</div>
            <div class="tab" id="tab-countries" onclick="showTab('countries')">Country Rules</div>
            <div class="tab" id="tab-overrides" onclick="showTab('overrides')">IP Overrides</div>
            <div class="tab" id="tab-settings" onclick="showTab('settings')">Settings</div>
        </div>

        <div class="tab-content" id="content-dashboard">
            <form method="get" action="/admin" class="inline-form">
		<h2>Filter Activity</h2>
		<div class="filter-container">
                    <div class="filter-inputs">
	                <input type="text" name="token" value="<?= h($tokenFilter) ?>" placeholder="Filter by token or path">
	                <input type="text" name="ip" value="<?= h($ipFilter) ?>" placeholder="Filter by IP">
	                <input type="text" name="visitor" value="<?= h($visitorFilter) ?>" placeholder="Filter by visitor hash">
	                <label class="date-filter-label">
	                    <span class="date-filter-hint">📅 From</span>
	                    <input type="date" name="date_from" value="<?= h($dateFrom) ?>">
	                </label>
	                <label class="date-filter-label">
	                    <span class="date-filter-hint">📅 To</span>
	                    <input type="date" name="date_to" value="<?= h($dateTo) ?>">
	                </label>
		    </div>
                    <div class="filter-toggles">
	                <label>
	                    <input type="checkbox" name="known" value="1" <?= $knownOnly ? 'checked' : '' ?>>
	                    Known tokens only
			</label>
			<label>
			    <input type="checkbox" name="show_top_tokens" value="1"
			        <?= (isset($_GET['show_top_tokens']) && $_GET['show_top_tokens'] === '1') ? 'checked' : '' ?>>
			    Show Top Tokens
			</label>
			<label>
			    <input type="checkbox" name="show_all" value="1" <?= (isset($_GET['show_all']) && $_GET['show_all'] === '1') ? 'checked' : '' ?>>
			    Show all
			</label>
                </div>
                <div class="filter-actions">
                    <button type="submit">Apply Filter</button>
                    <a class="button-link" href="/admin">Clear Filter</a>
                    <a class="button-link" href="<?= h($refreshUrl) ?>">Refresh</a>
                    <?php
                    $exportParams = [];
                    if ($tokenFilter   !== '') $exportParams['token']    = $tokenFilter;
                    if ($ipFilter      !== '') $exportParams['ip']       = $ipFilter;
                    if ($visitorFilter !== '') $exportParams['visitor']  = $visitorFilter;
                    if ($knownOnly)            $exportParams['known']    = '1';
                    if ($dateFrom      !== '') $exportParams['date_from'] = $dateFrom;
                    if ($dateTo        !== '') $exportParams['date_to']   = $dateTo;
                    $exportHref = '/export/json' . (!empty($exportParams) ? '?' . http_build_query($exportParams) : '');
                    ?>
                    <a class="button-link" href="<?= h($exportHref) ?>" target="_blank" rel="noopener">Export JSON</a>
                    <a class="button-link" href="<?= h(str_replace('/export/json', '/export/csv', $exportHref)) ?>" target="_blank" rel="noopener">Export CSV</a>
		</div>
               </div>
            </form>

            <?php if ($hasActiveFilter): ?>
                <div class="active-filters">
                    <?php if ($tokenFilter !== ''): ?>
                        <span class="filter-pill">
                            token: <?= h($tokenFilter) ?>
                            <a href="<?= h($buildAdminUrl(['token' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($ipFilter !== ''): ?>
                        <span class="filter-pill">
                            ip: <?= h($ipFilter) ?>
                            <a href="<?= h($buildAdminUrl(['ip' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($visitorFilter !== ''): ?>
                        <span class="filter-pill">
                            visitor: <?= h($visitorFilter) ?>
                            <a href="<?= h($buildAdminUrl(['visitor' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($dateFrom !== ''): ?>
                        <span class="filter-pill">
                            from: <?= h($dateFrom) ?>
                            <a href="<?= h($buildAdminUrl(['date_from' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($dateTo !== ''): ?>
                        <span class="filter-pill">
                            to: <?= h($dateTo) ?>
                            <a href="<?= h($buildAdminUrl(['date_to' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>

                    <?php if ($knownOnly): ?>
                        <span class="filter-pill">
                            known only
                            <a href="<?= h($buildAdminUrl(['known' => null])) ?>">×</a>
                        </span>
		    <?php endif; ?>

		    <?php if ($showAll): ?>
			<span class="filter-pill">
		            show all
		            <a href="<?= h($buildAdminUrl(['show_all' => null])) ?>">×</a>
		       </span>
		    <?php endif; ?>
                </div>
            <?php endif; ?>



<?php if ($tokenFilter !== '' && !$knownOnly && $ipFilter === '' && $visitorFilter === '' && $dateFrom === '' && $dateTo === ''): ?>
    <form method="post" action="/admin/delete-token-clicks" class="inline-form">
        <h2>Token Cleanup</h2>
        <input type="hidden" name="token" value="<?= h($tokenFilter) ?>">

        <div class="filter-actions" style="margin-left: 0;">
            <button type="submit"
                    name="mode"
                    value="unknown_only"
                    class="warning-button"
                    onclick="return confirm('Delete unknown-only clicks for this token/path?');">
                Delete Unknown Token Hits
            </button>

            <button type="submit"
                    name="mode"
                    value="all"
                    class="danger-button"
                    onclick="return confirm('Delete ALL clicks for this token/path?');">
                Delete All Clicks for Token
            </button>
        </div>
    </form>
<?php endif; ?>

<?php if ($ipFilter !== '' && !$knownOnly && $tokenFilter === '' && $visitorFilter === '' && $dateFrom === '' && $dateTo === ''): ?>
    <form method="post" action="/admin/delete-ip-clicks" class="inline-form">
        <h2>IP Cleanup</h2>
        <input type="hidden" name="ip" value="<?= h($ipFilter) ?>">

        <div class="filter-actions" style="margin-left: 0;">
            <button type="submit"
                    name="mode"
                    value="unknown_only"
                    class="warning-button"
                    onclick="return confirm('Delete unknown-only clicks for this IP?');">
                Delete Unknown IP Hits
            </button>

            <button type="submit"
                    name="mode"
                    value="all"
                    class="danger-button"
                    onclick="return confirm('Delete ALL clicks for this IP?');">
                Delete All Clicks for IP
            </button>
        </div>
    </form>
<?php endif; ?>

<?php if ($hasActiveFilter): ?>
    <form method="post" action="/admin/delete-filtered-clicks" class="inline-form">
        <h2>Bulk Delete</h2>
        <p class="muted">Delete all <?= number_format($totalCount) ?> click<?= $totalCount !== 1 ? 's' : '' ?> matching the current filter.</p>
        <?php if ($tokenFilter   !== ''): ?><input type="hidden" name="token"     value="<?= h($tokenFilter) ?>"><?php endif; ?>
        <?php if ($ipFilter      !== ''): ?><input type="hidden" name="ip"        value="<?= h($ipFilter) ?>"><?php endif; ?>
        <?php if ($visitorFilter !== ''): ?><input type="hidden" name="visitor"   value="<?= h($visitorFilter) ?>"><?php endif; ?>
        <?php if ($knownOnly):            ?><input type="hidden" name="known"     value="1"><?php endif; ?>
        <?php if ($dateFrom      !== ''): ?><input type="hidden" name="date_from" value="<?= h($dateFrom) ?>"><?php endif; ?>
        <?php if ($dateTo        !== ''): ?><input type="hidden" name="date_to"   value="<?= h($dateTo) ?>"><?php endif; ?>
        <div class="filter-actions" style="margin-left: 0;">
            <button type="submit"
                    class="danger-button"
                    onclick="return confirm('Delete ALL <?= number_format($totalCount) ?> click<?= $totalCount !== 1 ? 's' : '' ?> matching the current filter? This cannot be undone.');">
                Delete All Matching Clicks
            </button>
        </div>
    </form>
<?php endif; ?>



	    <?php $showTopTokens = isset($_GET['show_top_tokens']) && $_GET['show_top_tokens'] === '1'; ?>
            <?php if ($showTopTokens): ?>
            <h2>Top Tokens</h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>Token</th>
                        <th>Hits</th>
                        <th>Last Seen</th>
                        <th>Known?</th>
                    </tr>
                    <?php foreach ($tokenCounts as $row): ?>
                        <tr>
                            <td class="mono">
                                <a class="table-link mono-link" href="<?= h($buildAdminUrl(['token' => (string) $row['token']])) ?>">
                                    <?= h((string) $row['token']) ?>
                                </a>
                            </td>
                            <td><?= (int) $row['hit_count'] ?></td>
                            <td><?= h((string) $row['last_seen']) ?></td>
                            <td><?= ((int) $row['is_known'] === 1) ? 'Yes' : 'No' ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
	    </div>
            <?php endif; ?>

            <?php if (!empty($behavioralFlags)): ?>
            <h2>Behaviorally Flagged IPs <span class="muted" style="font-size:0.8rem;font-weight:400;">(last 24h)</span></h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>IP</th>
                        <th>Org</th>
                        <th>Country</th>
                        <th>Hits</th>
                        <th>Burst</th>
                        <th>Rapid</th>
                        <th>Multi-token</th>
                        <th>Lowest Score</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                    </tr>
                    <?php foreach ($behavioralFlags as $flag): ?>
                        <?php $flagIp = (string) ($flag['ip'] ?? ''); ?>
                        <tr>
                            <td class="mono ip-col">
                                <a class="table-link mono-link" href="<?= h($buildAdminUrl(['ip' => $flagIp])) ?>">
                                    <?= h($flagIp) ?>
                                </a>
                            </td>
                            <td><?= h((string) ($flag['ip_org'] ?? '')) ?></td>
                            <td><?= h((string) ($flag['ip_country'] ?? '')) ?></td>
                            <td><?= (int) ($flag['total_hits'] ?? 0) ?></td>
                            <td><?= (int) ($flag['burst_hits'] ?? 0) > 0 ? '<span class="badge badge-bot">' . (int)$flag['burst_hits'] . '</span>' : '—' ?></td>
                            <td><?= (int) ($flag['rapid_hits'] ?? 0) > 0 ? '<span class="badge badge-suspicious">' . (int)$flag['rapid_hits'] . '</span>' : '—' ?></td>
                            <td><?= (int) ($flag['multi_hits'] ?? 0) > 0 ? '<span class="badge badge-suspicious">' . (int)$flag['multi_hits'] . '</span>' : '—' ?></td>
                            <td><?= h((string) ($flag['lowest_score'] ?? '')) ?></td>
                            <td><?= h((string) ($flag['first_seen'] ?? '')) ?></td>
                            <td><?= h((string) ($flag['last_seen'] ?? '')) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>

            <?php if ($ipSummary !== null && (int) ($ipSummary['total_hits'] ?? 0) > 0): ?>
            <div class="ip-summary">
                <strong>IP Summary: <?= h($ipFilter) ?></strong>
                <div class="details-grid" style="margin-top: 8px;">
                    <div>
                        <div><span class="mono">First seen:</span> <?= h((string) ($ipSummary['first_seen'] ?? '—')) ?></div>
                        <div><span class="mono">Last seen:</span>  <?= h((string) ($ipSummary['last_seen']  ?? '—')) ?></div>
                        <div><span class="mono">Total hits:</span> <?= (int) ($ipSummary['total_hits'] ?? 0) ?></div>
                        <div><span class="mono">Distinct tokens:</span> <?= (int) ($ipSummary['distinct_tokens'] ?? 0) ?></div>
                    </div>
                    <div>
                        <div><span class="mono">Bot hits:</span>          <?= (int) ($ipSummary['bot_count']          ?? 0) ?></div>
                        <div><span class="mono">Suspicious hits:</span>   <?= (int) ($ipSummary['suspicious_count']   ?? 0) ?></div>
                        <div><span class="mono">Likely-human hits:</span> <?= (int) ($ipSummary['likely_human_count'] ?? 0) ?></div>
                        <div><span class="mono">Human hits:</span>        <?= (int) ($ipSummary['human_count']        ?? 0) ?></div>
                    </div>
                    <div>
                        <div><span class="mono">Org:</span>     <?= h((string) ($ipSummary['ip_org']     ?? '—')) ?></div>
                        <div><span class="mono">ASN:</span>     <?= h((string) ($ipSummary['ip_asn']     ?? '—')) ?></div>
                        <div><span class="mono">Country:</span> <?= h((string) ($ipSummary['ip_country'] ?? '—')) ?></div>
                        <?php if (!empty($ipSummary['asn_rule'])): ?>
                            <div><span class="badge badge-suspicious">ASN rule active — penalty <?= (int) $ipSummary['asn_rule']['penalty'] ?></span></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <h2>Activity</h2>
            <p class="muted">
                <?= $knownOnly ? 'Showing only known tokens.' : 'Showing all clicks that were not suppressed as noise.' ?>
                <?php if ($totalCount > 0): ?>
                    <span style="margin-left: 8px;"><?= number_format($totalCount) ?> total &mdash; page <?= $currentPage ?> of <?= $totalPages ?></span>
                <?php endif; ?>
            </p>

            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th class="time-col">Time</th>
                        <th class="type-col">Type</th>
                        <th class="token-col">Token / Path</th>
                        <th class="ip-col">IP</th>
                        <th>Org</th>
                        <th class="classification-col">Classification</th>
                        <th class="details-col">Details</th>
                    </tr>
                    <?php foreach ($clicks as $i => $c): ?>
                        <?php
                        $confidenceLabel = (string) ($c['confidence_label'] ?? '');
                        $badgeClass = match ($confidenceLabel) {
                            'human'        => 'badge badge-human',
                            'likely-human' => 'badge badge-likely-human',
                            'suspicious'   => 'badge badge-suspicious',
                            'bot'          => 'badge badge-bot',
                            default        => 'badge',
                        };
                        $detailsId    = 'details-' . $i;
                        $rowToken     = (string) ($c['token'] ?? '');
                        $displayToken = ($rowToken === 'root') ? '/' : $rowToken;
                        $rowIp        = (string) ($c['ip'] ?? '');
                        $rowVisitor   = (string) ($c['visitor_hash'] ?? '');
                        $rowUa        = (string) ($c['user_agent'] ?? '');

                        // Display timestamp from unix_ms if available, fall back to clicked_at string.
                        $tsMs      = $c['clicked_at_unix_ms'] ?? null;
                        $tsDisplay = $tsMs !== null
                            ? date('Y-m-d H:i:s', (int) ($tsMs / 1000))
                            : (string) ($c['clicked_at'] ?? '');
                        ?>
                        <tr class="<?= $confidenceLabel === 'bot' ? 'bot' : '' ?>">
                            <td class="time-col" title="<?= h((string) ($c['clicked_at'] ?? '')) ?>"><?= h($tsDisplay) ?></td>
                            <td class="type-col"><?= h((string) ($c['event_type'] ?? 'click')) ?></td>
                            <td class="mono token-col">
                                <a class="table-link mono-link" href="<?= h($buildAdminUrl(['token' => $rowToken])) ?>">
                                    <?= h($rowToken) ?>
                                </a>
                            </td>
                            <td class="mono ip-col">
                                <a class="table-link mono-link" href="<?= h($buildAdminUrl(['ip' => $rowIp])) ?>">
                                    <?= h($rowIp) ?>
                                </a>
                            </td>
			    <td><?= h((string) ($c['ip_org'] ?? '')) ?></td>
			    <?php $rowScore = (int) ($c['confidence_score'] ?? 0); ?>
                            <td class="classification-col">
			        <span class="<?= h($badgeClass) ?>">
			            <?= h($confidenceLabel) ?>
			        </span>
			        <span class="score-pill"><?= $rowScore ?></span>
			    </td>
			    <td class="details-col">
                                <button type="button" class="details-button" onclick="toggleDetails('<?= h($detailsId) ?>', this)">Details</button>
                            </td>
                        </tr>
                        <tr id="<?= h($detailsId) ?>" class="details-row">
                            <td colspan="7" class="details-cell">
                                <div class="details-grid">
                                    <div class="detail-box">
                                        <strong>Identity</strong>
                                        <div>
                                            <span class="mono">Click ID:</span> <?= h((string) ($c['id'] ?? '')) ?>
                                        </div>
					<div>
					    <span class="mono">IP:</span>
					    <a class="pill-link mono" href="<?= h($buildAdminUrl(['ip' => $rowIp])) ?>"><?= h($rowIp) ?></a>
					    <button type="button" class="copy-button" onclick="copyText('<?= h($rowIp) ?>')" title="Copy IP">Copy</button>
					    <a class="copy-button" href="https://www.virustotal.com/gui/ip-address/<?= h($rowIp) ?>" target="_blank" rel="noopener" title="Open in VirusTotal">VT</a>
					    <a class="copy-button" href="https://www.abuseipdb.com/check/<?= h($rowIp) ?>" target="_blank" rel="noopener" title="Check AbuseIPDB">Abuse</a>
					    <a class="copy-button" href="https://ipinfo.io/<?= h($rowIp) ?>" target="_blank" rel="noopener" title="View IPInfo">Info</a>
					</div>
					<?php
                        $rowAsn = (string) ($c['ip_asn'] ?? '');
                        $asnRule = $rowAsn !== '' ? getAsnRuleByAsn($pdo, $rowAsn) : null;
                        ?>
					<div>
					    <span class="mono">ASN:</span> <?= h($rowAsn) ?>

					    <?php if ($rowAsn !== '' && $asnRule === null): ?>
					        <form method="post" action="/admin/create-asn-rule" class="inline-action-form" style="display:inline-block;">
					            <input type="hidden" name="asn" value="<?= h($rowAsn) ?>">
					            <input type="hidden" name="label" value="<?= h((string) ($c['ip_org'] ?? '')) ?>">
					            <input type="hidden" name="penalty" value="10">
					            <button type="submit" class="copy-button">Add ASN Rule</button>
					        </form>
					    <?php elseif ($asnRule !== null): ?>
					        <span class="badge badge-suspicious">ASN rule active</span>
					    <?php endif; ?>
					</div>
                                        <div><span class="mono">Org:</span> <?= h((string) ($c['ip_org'] ?? '')) ?></div>
                                        <div><span class="mono">Country:</span> <?= h((string) ($c['ip_country'] ?? '')) ?></div>
                                        <div>
                                            <span class="mono">Visitor:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['visitor' => $rowVisitor])) ?>"><?= h($rowVisitor) ?></a>
                                            <button type="button" class="copy-button" onclick="copyText('<?= h($rowVisitor) ?>')">Copy</button>
                                        </div>
                                        <div><span class="mono">XFF:</span> <?= h((string) ($c['x_forwarded_for'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box">
					<strong>Scoring</strong>
					<?php
                                                $score = (int) ($c['confidence_score'] ?? 0);
                        if ($score <= 10) {
                            $confidenceLevel = 'high';
                        } elseif ($score <= 30) {
                            $confidenceLevel = 'medium';
                        } elseif ($score <= 60) {
                            $confidenceLevel = 'low';
                        } else {
                            $confidenceLevel = 'very low';
                        }
                        ?>
					<div><span class="mono">Classification:</span> <?= h((string) ($c['confidence_label'] ?? '')) ?> (<?= h((string) ($c['confidence_score'] ?? '')) ?>)</div>
                                        <div><span class="mono">Reason:</span> <span class="wrap"><?= h((string) ($c['confidence_reason'] ?? '')) ?></span></div>
                                        <div><span class="mono">First for token:</span> <?= !empty($c['first_for_token']) ? 'Yes' : 'No' ?></div>
                                        <div><span class="mono">Prior events for token:</span> <?= h((string) ($c['prior_events_for_token'] ?? '0')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Request</strong>
                                        <div>
                                            <span class="mono">Token / Path:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['token' => $rowToken])) ?>"><?= h($rowToken) ?></a>
                                            <button type="button" class="copy-button" onclick="copyText('<?= h($rowToken) ?>')">Copy</button>
                                        </div>
                                        <div><span class="mono">Method:</span> <?= h((string) ($c['request_method'] ?? '')) ?></div>
                                        <div><span class="mono">Host:</span> <?= h((string) ($c['host'] ?? '')) ?></div>
                                        <div><span class="mono">Scheme:</span> <?= h((string) ($c['scheme'] ?? '')) ?></div>
                                        <div><span class="mono">URI:</span> <span class="wrap"><?= h((string) ($c['request_uri'] ?? '')) ?></span></div>
                                        <div><span class="mono">Query:</span> <span class="wrap"><?= h((string) ($c['query_string'] ?? '')) ?></span></div>
                                        <div><span class="mono">Remote port:</span> <?= h((string) ($c['remote_port'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Headers</strong>
                                        <div><span class="mono">Referer:</span> <span class="wrap"><?= h((string) ($c['referer'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept:</span> <span class="wrap"><?= h((string) ($c['accept'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept-Language:</span> <span class="wrap"><?= h((string) ($c['accept_language'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept-Encoding:</span> <span class="wrap"><?= h((string) ($c['accept_encoding'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Site:</span> <span class="wrap"><?= h((string) ($c['sec_fetch_site'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Mode:</span> <span class="wrap"><?= h((string) ($c['sec_fetch_mode'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Dest:</span> <span class="wrap"><?= h((string) ($c['sec_fetch_dest'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-CH-UA:</span> <span class="wrap"><?= h((string) ($c['sec_ch_ua'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-CH-UA-Platform:</span> <span class="wrap"><?= h((string) ($c['sec_ch_ua_platform'] ?? '')) ?></span></div>
                                    </div>

                                    <div class="detail-box" style="grid-column: 1 / -1;">
                                        <strong>User-Agent</strong>
                                        <div class="wrap">
                                            <?= h($rowUa) ?>
                                            <button type="button" class="copy-button" onclick="copyText('<?= h($rowUa) ?>')">Copy</button>
                                        </div>
                                    </div>

                                    <div class="detail-box" style="grid-column: 1 / -1;">
                                        <strong>Actions</strong>
                                        <?php
                                        // Hidden filter fields included in every action form so the
                                        // handler can redirect back to the current filtered view.
                                        $filterHiddens = '';
                                        if ($tokenFilter   !== '') $filterHiddens .= '<input type="hidden" name="_filter_token"     value="' . h($tokenFilter)   . '">';
                                        if ($ipFilter      !== '') $filterHiddens .= '<input type="hidden" name="_filter_ip"        value="' . h($ipFilter)      . '">';
                                        if ($visitorFilter !== '') $filterHiddens .= '<input type="hidden" name="_filter_visitor"   value="' . h($visitorFilter) . '">';
                                        if ($knownOnly)            $filterHiddens .= '<input type="hidden" name="_filter_known"     value="1">';
                                        if ($dateFrom      !== '') $filterHiddens .= '<input type="hidden" name="_filter_date_from" value="' . h($dateFrom)      . '">';
                                        if ($dateTo        !== '') $filterHiddens .= '<input type="hidden" name="_filter_date_to"   value="' . h($dateTo)        . '">';
                                        ?>

                                        <form method="post" action="/admin/delete-click" class="inline-action-form" onsubmit="return confirm('Delete this click?');">
                                            <?= $filterHiddens ?>
                                            <input type="hidden" name="id" value="<?= h((string) ($c['id'] ?? '')) ?>">
                                            <button type="submit" class="danger-button">Delete This Click</button>
                                        </form>

                                        <form method="post" action="/admin/add-token-to-skip" class="inline-action-form" onsubmit="return confirm('Add this token/path to skip patterns?');">
                                            <?= $filterHiddens ?>
                                            <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                            <button type="submit" class="warning-button">Skip Exact Token</button>
                                        </form>

                                        <?php if (empty($c['link_id'])): ?>
                                            <form method="post" action="/admin/delete-token-clicks" class="inline-action-form" onsubmit="return confirm('Delete unknown-only clicks for this token/path?');">
                                                <?= $filterHiddens ?>
                                                <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                                <input type="hidden" name="mode" value="unknown_only">
                                                <button type="submit" class="warning-button">Delete Unknown Token Hits</button>
                                            </form>
                                        <?php endif; ?>

                                        <form method="post" action="/admin/delete-token-clicks" class="inline-action-form" onsubmit="return confirm('Delete ALL clicks for this token/path?');">
                                            <?= $filterHiddens ?>
                                            <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                            <input type="hidden" name="mode" value="all">
                                            <button type="submit" class="danger-button">Delete All Clicks for Token</button>
                                        </form>

                                        <?php $existingOverrideMode = $ipOverrideMap[$rowIp] ?? null; ?>
                                        <?php if ($existingOverrideMode === null): ?>
                                            <form method="post" action="/admin/create-ip-override" class="inline-action-form">
                                                <?= $filterHiddens ?>
                                                <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
                                                <input type="hidden" name="mode" value="block">
                                                <input type="hidden" name="notes" value="Added from activity feed">
                                                <button type="submit" class="danger-button">Block IP</button>
                                            </form>
                                            <form method="post" action="/admin/create-ip-override" class="inline-action-form">
                                                <?= $filterHiddens ?>
                                                <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
                                                <input type="hidden" name="mode" value="allow">
                                                <input type="hidden" name="notes" value="Added from activity feed">
                                                <button type="submit" class="warning-button">Allow IP</button>
                                            </form>
                                        <?php else: ?>
                                            <span class="badge <?= $existingOverrideMode === 'block' ? 'badge-bot' : 'badge-human' ?>">
                                                IP override: <?= h($existingOverrideMode) ?>
                                            </span>
                                            <a class="copy-button" href="/admin?tab=overrides">Manage →</a>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>

            <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($currentPage > 1): ?>
                    <a class="button-link" href="<?= h($buildAdminUrl(['page' => (string) ($currentPage - 1)])) ?>">&larr; Prev</a>
                <?php endif; ?>

                <?php
                $start = max(1, $currentPage - 2);
                $end   = min($totalPages, $currentPage + 2);
                for ($p = $start; $p <= $end; $p++):
                ?>
                    <?php if ($p === $currentPage): ?>
                        <span class="page-current"><?= $p ?></span>
                    <?php else: ?>
                        <a class="button-link" href="<?= h($buildAdminUrl(['page' => (string) $p])) ?>"><?= $p ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($currentPage < $totalPages): ?>
                    <a class="button-link" href="<?= h($buildAdminUrl(['page' => (string) ($currentPage + 1)])) ?>">Next &rarr;</a>
                <?php endif; ?>

                <span class="muted">
                    <?= number_format($totalCount) ?> total &mdash; page <?= $currentPage ?> of <?= $totalPages ?>
                </span>
            </div>
            <?php endif; ?>

        </div>

	<div class="tab-content" id="content-links">
	    <?php if ($editLink !== null): ?>
	    <form method="post" action="/admin/update-link">
	        <h2>Edit Token</h2>

	        <input type="hidden" name="id" value="<?= (int) $editLink['id'] ?>">

	        <label for="edit_token">Token / Path</label>
	        <input id="edit_token" type="text" name="token" required value="<?= h((string) $editLink['token']) ?>">

	        <label for="edit_destination">Destination URL</label>
	        <input id="edit_destination" type="url" name="destination" required value="<?= h((string) $editLink['destination']) ?>">

	        <label for="edit_description">Description</label>
	        <input id="edit_description" type="text" name="description" value="<?= h((string) ($editLink['description'] ?? '')) ?>">

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="exclude_from_feed" value="1" <?= ((int) ($editLink['exclude_from_feed'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Exclude from threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">IPs that hit this token will never appear in the feed, even if classified as suspicious or bot.</p>
	        </div>

	        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
	            <button type="submit">Save Changes</button>
	            <form method="get" action="/admin" class="inline-action-form">
	                <input type="hidden" name="tab" value="links">
	                <button type="submit">Cancel</button>
	            </form>
	        </div>
	    </form>
	<?php endif; ?>
            <form method="post" action="/admin/create-link">
                <h2>Create Token</h2>
                <label for="token">Token / Path</label>
                <input id="token" type="text" name="token" required placeholder="payroll or abc123">

                <label for="destination">Destination URL</label>
                <input id="destination" type="url" name="destination" required placeholder="https://www.example.com/">

                <label for="description">Description</label>
                <input id="description" type="text" name="description" placeholder="Optional description">

                <div style="margin-bottom: 12px;">
                    <label style="display: inline-flex; align-items: center; gap: 6px;">
                        <input type="checkbox" name="exclude_from_feed" value="1">
                        <span>Exclude from threat feed</span>
                    </label>
                    <p class="muted" style="margin: 4px 0 0 0;">IPs that hit this token will never appear in the feed, even if classified as suspicious or bot.</p>
                </div>

                <button type="submit">Create Token</button>
            </form>

            <h2>Token Summary</h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>ID</th>
                        <th>Token / Path</th>
                        <th>Description</th>
                        <th>Destination</th>
                        <th>Active</th>
			<th>Clicks</th>
                        <th>Excl. Feed</th>
                        <th>Path URL</th>
                        <th>Pixel URL</th>
                        <th class="actions-col">Actions</th>
                    </tr>
		    <?php foreach ($links as $link): ?>
		   <?php
            $tokenUrl = $baseUrl !== ''
                ? rtrim($baseUrl, '/') . '/' . ltrim((string) $link['token'], '/')
                : '';

		        $pixelUrl = $baseUrl !== ''
		            ? rtrim($baseUrl, '/') . '/pixel/' . $link['token'] . '.gif'
		            : '';
		        ?>
		<tr>
		    <td><?= (int) $link['id'] ?></td>
		    <td class="mono">
		        <a class="table-link mono-link" href="<?= h($buildAdminUrl(['token' => (string) $link['token'], 'tab' => 'links'])) ?>">
		            <?= h((string) $link['token']) ?>
		        </a>
		    </td>
		    <td><?= h((string) ($link['description'] ?? '')) ?></td>
		    <td class="wrap"><?= h((string) $link['destination']) ?></td>
		    <td><?= ((int) $link['active'] === 1) ? 'Yes' : 'No' ?></td>
		    <td><?= (int) $link['click_count'] ?></td>
		    <td>
		        <?php if ((int) ($link['exclude_from_feed'] ?? 0) === 1): ?>
		            <span class="badge badge-suspicious" title="IPs hitting this token are excluded from the threat feed">Yes</span>
		        <?php else: ?>
		            No
		        <?php endif; ?>
		    </td>

		    <td class="mono wrap">
		        <?php if ($tokenUrl !== ''): ?>
		            <div class="url-cell">
		                <span><?= h($tokenUrl) ?></span>
		                <button type="button" class="copy-button" onclick="copyText('<?= h($tokenUrl) ?>')">Copy</button>
		            </div>
		        <?php endif; ?>
		    </td>

		    <td class="mono wrap">
		        <?php if ($pixelUrl !== ''): ?>
		            <div class="url-cell">
		                <span><?= h($pixelUrl) ?></span>
		                <button type="button" class="copy-button" onclick="copyText('<?= h($pixelUrl) ?>')">Copy</button>
		            </div>
		        <?php endif; ?>
		    </td>

		    <td class="actions-col">

			   <form method="get" action="/admin" class="inline-action-form">
			       <input type="hidden" name="tab" value="links">
			       <input type="hidden" name="edit_link_id" value="<?= (int) $link['id'] ?>">
	 		       <button type="submit">Edit</button>
			   </form>

		        <?php if ((int) $link['active'] === 1): ?>
		            <form method="post" action="/admin/deactivate-link" class="inline-action-form">
               			 <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
		                <button type="submit">Deactivate</button>
		            </form>
		        <?php else: ?>
		            <form method="post" action="/admin/activate-link" class="inline-action-form">
		                <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
		                <button type="submit">Activate</button>
   		         </form>
     			 <?php endif; ?>

		        <form method="post" action="/admin/delete-link" class="inline-action-form" onsubmit="return confirm('Delete this token/path?');">
		            <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
		            <button type="submit">Delete</button>
		        </form>

		        <form method="post" action="/admin/delete-link" class="inline-action-form" onsubmit="return confirm('Delete this token/path and all related clicks?');">
		            <input type="hidden" name="id" value="<?= (int) $link['id'] ?>">
		            <input type="hidden" name="delete_clicks" value="1">
		            <button type="submit" class="danger-button">Delete + Clicks</button>
		        </form>
		    </td>
		</tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>

	<div class="tab-content" id="content-asn">

	    <?php if ($editAsnRule !== null): ?>
	    <form method="post" action="/admin/update-asn-rule">
	        <h2>Edit ASN Rule</h2>
	        <input type="hidden" name="id" value="<?= (int) $editAsnRule['id'] ?>">

	        <label for="edit_asn_asn">ASN</label>
	        <input id="edit_asn_asn" type="text" name="asn" required value="<?= h((string) $editAsnRule['asn']) ?>">

	        <label for="edit_asn_label">Label</label>
	        <input id="edit_asn_label" type="text" name="label" value="<?= h((string) ($editAsnRule['label'] ?? '')) ?>">

	        <label for="edit_asn_penalty">Penalty</label>
	        <input id="edit_asn_penalty" type="number" name="penalty" min="1" max="100" value="<?= (int) $editAsnRule['penalty'] ?>">

	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="exclude_from_feed" value="1" <?= ((int) ($editAsnRule['exclude_from_feed'] ?? 0) === 1) ? 'checked' : '' ?>>
	                <span>Never add to threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">Score penalty still applies. Use this for your own infrastructure, CDNs, or monitoring services.</p>
	        </div>

	        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
	            <button type="submit">Save Changes</button>
	            <form method="get" action="/admin" class="inline-action-form">
	                <input type="hidden" name="tab" value="asn">
	                <button type="submit">Cancel</button>
	            </form>
	        </div>
	    </form>
	    <?php endif; ?>

	    <form method="post" action="/admin/create-asn-rule">
	        <h2>Create ASN Rule</h2>
	        <label for="asn">ASN</label>
	        <input id="asn" type="text" name="asn" required placeholder="8075">
	        <label for="asn_label">Label</label>
	        <input id="asn_label" type="text" name="label" placeholder="Microsoft">
	        <label for="asn_penalty">Penalty</label>
	        <input id="asn_penalty" type="number" name="penalty" min="1" max="100" value="10">
	        <div style="margin-bottom: 12px;">
	            <label style="display: inline-flex; align-items: center; gap: 6px;">
	                <input type="checkbox" name="exclude_from_feed" value="1">
	                <span>Never add to threat feed</span>
	            </label>
	            <p class="muted" style="margin: 4px 0 0 0;">Score penalty still applies. Use this for your own infrastructure, CDNs, or monitoring services.</p>
	        </div>
	        <button type="submit">Add ASN Rule</button>
	    </form>

	    <h2>ASN Rules</h2>
	    <div class="table-wrap">
	        <table class="compact-table">
	            <tr>
	                <th>ID</th>
	                <th>ASN</th>
	                <th>Label</th>
	                <th>Penalty</th>
	                <th>Active</th>
	                <th>Excl. Feed</th>
	                <th class="actions-col">Actions</th>
	            </tr>
	            <?php foreach ($asnRules as $rule): ?>
	                <tr>
	                    <td><?= (int) $rule['id'] ?></td>
	                    <td class="mono"><?= h((string) $rule['asn']) ?></td>
	                    <td><?= h((string) ($rule['label'] ?? '')) ?></td>
	                    <td><?= (int) $rule['penalty'] ?></td>
	                    <td><?= ((int) $rule['active'] === 1) ? 'Yes' : 'No' ?></td>
	                    <td>
	                        <?php if ((int) ($rule['exclude_from_feed'] ?? 0) === 1): ?>
	                            <span class="badge badge-suspicious" title="This ASN will never appear in the threat feed">Yes</span>
	                        <?php else: ?>
	                            No
	                        <?php endif; ?>
	                    </td>
	                    <td class="actions-col">
	                        <form method="get" action="/admin" class="inline-action-form">
	                            <input type="hidden" name="tab" value="asn">
	                            <input type="hidden" name="edit_asn_rule_id" value="<?= (int) $rule['id'] ?>">
	                            <button type="submit">Edit</button>
	                        </form>
	                        <?php if ((int) $rule['active'] === 1): ?>
	                            <form method="post" action="/admin/deactivate-asn-rule" class="inline-action-form">
	                                <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
	                                <button type="submit">Deactivate</button>
	                            </form>
	                        <?php else: ?>
	                            <form method="post" action="/admin/activate-asn-rule" class="inline-action-form">
	                                <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
	                                <button type="submit">Activate</button>
	                            </form>
	                        <?php endif; ?>
	                        <form method="post" action="/admin/delete-asn-rule" class="inline-action-form" onsubmit="return confirm('Delete this ASN rule?');">
	                            <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
	                            <button type="submit">Delete</button>
	                        </form>
	                    </td>
	                </tr>
	            <?php endforeach; ?>
	        </table>
	    </div>
	</div>

        <div class="tab-content" id="content-countries">

            <?php if ($editCountryRule !== null): ?>
            <form method="post" action="/admin/update-country-rule">
                <h2>Edit Country Rule</h2>
                <input type="hidden" name="id" value="<?= (int) $editCountryRule['id'] ?>">

                <label for="edit_country_code">Country Code</label>
                <input id="edit_country_code" type="text" name="country_code" required maxlength="2" style="text-transform:uppercase;" value="<?= h((string) $editCountryRule['country_code']) ?>">

                <label for="edit_country_label">Label (optional)</label>
                <input id="edit_country_label" type="text" name="label" value="<?= h((string) ($editCountryRule['label'] ?? '')) ?>" placeholder="e.g. High-risk region">

                <label for="edit_country_penalty">Score Penalty (1–100)</label>
                <input id="edit_country_penalty" type="number" name="penalty" min="1" max="100" value="<?= (int) $editCountryRule['penalty'] ?>">

                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                    <button type="submit">Save Changes</button>
                    <form method="get" action="/admin" class="inline-action-form">
                        <input type="hidden" name="tab" value="countries">
                        <button type="submit">Cancel</button>
                    </form>
                </div>
            </form>
            <?php endif; ?>

            <form method="post" action="/admin/create-country-rule">
                <h2>Add Country Rule</h2>
                <p class="muted">Applies a score penalty to all requests from the specified country. Use 2-letter ISO country codes (e.g. CN, RU, KP). Only affects scoring — does not exclude IPs from the threat feed.</p>

                <label for="country_code">Country Code</label>
                <input id="country_code" type="text" name="country_code" required maxlength="2" style="text-transform:uppercase; width: 80px;" placeholder="CN">

                <label for="country_label">Label (optional)</label>
                <input id="country_label" type="text" name="label" placeholder="e.g. High-risk region">

                <label for="country_penalty">Score Penalty (1–100)</label>
                <input id="country_penalty" type="number" name="penalty" min="1" max="100" value="15">

                <button type="submit">Add Country Rule</button>
            </form>

            <h2>Country Rules</h2>
            <?php if (empty($countryRules)): ?>
                <p class="muted">No country rules configured.</p>
            <?php else: ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>Code</th>
                        <th>Label</th>
                        <th>Penalty</th>
                        <th>Active</th>
                        <th>Created</th>
                        <th class="actions-col">Actions</th>
                    </tr>
                    <?php foreach ($countryRules as $rule): ?>
                        <tr>
                            <td class="mono"><?= h((string) $rule['country_code']) ?></td>
                            <td><?= h((string) ($rule['label'] ?? '')) ?></td>
                            <td>-<?= (int) $rule['penalty'] ?></td>
                            <td><?= ((int) $rule['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td><?= h((string) ($rule['created_at'] ?? '')) ?></td>
                            <td class="actions-col">
                                <form method="get" action="/admin" class="inline-action-form">
                                    <input type="hidden" name="tab" value="countries">
                                    <input type="hidden" name="edit_country_id" value="<?= (int) $rule['id'] ?>">
                                    <button type="submit">Edit</button>
                                </form>
                                <?php if ((int) $rule['active'] === 1): ?>
                                    <form method="post" action="/admin/deactivate-country-rule" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
                                        <button type="submit">Deactivate</button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="/admin/activate-country-rule" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
                                        <button type="submit">Activate</button>
                                    </form>
                                <?php endif; ?>
                                <form method="post" action="/admin/delete-country-rule" class="inline-action-form" onsubmit="return confirm('Delete this country rule?');">
                                    <input type="hidden" name="id" value="<?= (int) $rule['id'] ?>">
                                    <button type="submit">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>
        </div>

        <div class="tab-content" id="content-overrides">

            <?php if ($editOverride !== null): ?>
            <form method="post" action="/admin/update-ip-override">
                <h2>Edit IP Override</h2>
                <input type="hidden" name="id" value="<?= (int) $editOverride['id'] ?>">

                <label for="edit_override_ip">IP Address</label>
                <input id="edit_override_ip" type="text" name="ip" required value="<?= h((string) $editOverride['ip']) ?>">

                <label for="edit_override_mode">Mode</label>
                <select id="edit_override_mode" name="mode">
                    <option value="block" <?= $editOverride['mode'] === 'block' ? 'selected' : '' ?>>Block — always classify as bot (score 0)</option>
                    <option value="allow" <?= $editOverride['mode'] === 'allow' ? 'selected' : '' ?>>Allow — always classify as human (score 100)</option>
                </select>

                <label for="edit_override_notes">Notes</label>
                <input id="edit_override_notes" type="text" name="notes" value="<?= h((string) ($editOverride['notes'] ?? '')) ?>" placeholder="Optional note">

                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                    <button type="submit">Save Changes</button>
                    <form method="get" action="/admin" class="inline-action-form">
                        <input type="hidden" name="tab" value="overrides">
                        <button type="submit">Cancel</button>
                    </form>
                </div>
            </form>
            <?php endif; ?>

            <form method="post" action="/admin/create-ip-override">
                <h2>Add IP Override</h2>
                <p class="muted">Overrides bypass scoring entirely. Blocked IPs are always classified as bot (score 0). Allowed IPs are always classified as human (score 100). Applies to future requests only.</p>

                <label for="override_ip">IP Address</label>
                <input id="override_ip" type="text" name="ip" required placeholder="1.2.3.4 or 2001:db8::1">

                <label for="override_mode">Mode</label>
                <select id="override_mode" name="mode">
                    <option value="block">Block — always classify as bot (score 0)</option>
                    <option value="allow">Allow — always classify as human (score 100)</option>
                </select>

                <label for="override_notes">Notes</label>
                <input id="override_notes" type="text" name="notes" placeholder="Optional note (e.g. monitoring service, your office IP)">

                <button type="submit">Add Override</button>
            </form>

            <h2>IP Overrides</h2>
            <?php if (empty($ipOverrides)): ?>
                <p class="muted">No IP overrides configured.</p>
            <?php else: ?>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>IP</th>
                        <th>Mode</th>
                        <th>Notes</th>
                        <th>Active</th>
                        <th>Created</th>
                        <th class="actions-col">Actions</th>
                    </tr>
                    <?php foreach ($ipOverrides as $override): ?>
                        <tr>
                            <td class="mono"><?= h((string) $override['ip']) ?></td>
                            <td>
                                <span class="badge <?= $override['mode'] === 'block' ? 'badge-bot' : 'badge-human' ?>">
                                    <?= h((string) $override['mode']) ?>
                                </span>
                            </td>
                            <td><?= h((string) ($override['notes'] ?? '')) ?></td>
                            <td><?= ((int) $override['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td><?= h((string) ($override['created_at'] ?? '')) ?></td>
                            <td class="actions-col">
                                <form method="get" action="/admin" class="inline-action-form">
                                    <input type="hidden" name="tab" value="overrides">
                                    <input type="hidden" name="edit_override_id" value="<?= (int) $override['id'] ?>">
                                    <button type="submit">Edit</button>
                                </form>
                                <?php if ((int) $override['active'] === 1): ?>
                                    <form method="post" action="/admin/deactivate-ip-override" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int) $override['id'] ?>">
                                        <button type="submit">Deactivate</button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="/admin/activate-ip-override" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int) $override['id'] ?>">
                                        <button type="submit">Activate</button>
                                    </form>
                                <?php endif; ?>
                                <form method="post" action="/admin/delete-ip-override" class="inline-action-form" onsubmit="return confirm('Delete this IP override?');">
                                    <input type="hidden" name="id" value="<?= (int) $override['id'] ?>">
                                    <button type="submit">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php endif; ?>
        </div>

        <div class="tab-content" id="content-settings">
            <div class="two-column-settings">
                <form method="post" action="/admin/save-settings">
                    <h2>Settings</h2>

                    <label for="app_name">App Name</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= h((string) $appName) ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="app_name" type="text" name="app_name" value="<?= h((string) $appName) ?>" required>
                    <?php endif; ?>

                    <label for="base_url">Base URL</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= h((string) $baseUrl) ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="base_url" type="url" name="base_url" value="<?= h((string) $baseUrl) ?>" placeholder="https://yourdomain.example">
                    <?php endif; ?>

                    <label for="default_redirect_url">Default Redirect URL</label>
                    <?php if ($isDemo): ?>
                        <div class="demo-locked-field"><?= h((string) $defaultRedirectUrl) ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
                    <?php else: ?>
                        <input id="default_redirect_url" type="url" name="default_redirect_url" value="<?= h((string) $defaultRedirectUrl) ?>" required>
                    <?php endif; ?>

                    <label for="unknown_path_behavior">Unknown Path Behavior</label>
                    <select id="unknown_path_behavior" name="unknown_path_behavior">
                        <option value="redirect" <?= $unknownPathBehavior === 'redirect' ? 'selected' : '' ?>>Redirect</option>
                        <option value="404" <?= $unknownPathBehavior === '404' ? 'selected' : '' ?>>404</option>
                    </select>

		    <div style="margin-bottom: 12px;">
		         <label style="display: inline-flex; align-items: center; gap: 6px; margin-right: 16px;">
			        <input type="checkbox" name="pixel_enabled" value="1" <?= $pixelEnabled ? 'checked' : '' ?>>
			        <span>Pixel enabled</span>
			 </label>
                         <label style="display: inline-flex; align-items: center; gap: 6px;">
			        <input type="checkbox" name="noise_filter_enabled" value="1" <?= $noiseFilterEnabled ? 'checked' : '' ?>>
			        <span>Noise filter enabled</span>
		         </label>
		   </div>

		   <label for="display_min_score">Minimum Display Score</label>
		   <input id="display_min_score" type="number"  min="0" max="100" name="display_min_score" value="<?= h((string) getSetting($pdo, 'display_min_score', '20')) ?>">

		   <p class="muted">Hide lower-scored events from the dashboard unless “Show all” is checked.</p>


		   <label for="page_size">Rows Per Page</label>
		   <input id="page_size" type="number" min="10" max="500" name="page_size" value="<?= h($pageSizeSetting) ?>">
		   <p class="muted">Number of activity rows shown per page (10-500).</p>

		   <label for="auto_refresh_secs">Auto-Refresh Interval (seconds)</label>
		   <input id="auto_refresh_secs" type="number" min="0" name="auto_refresh_secs" value="<?= h((string) $autoRefreshSecs) ?>">
		   <p class="muted">Reload the dashboard after this many seconds. Set to 0 to disable.</p>

		   <label for="webhook_url">Threat Webhook URL</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= h($webhookUrl) ?: '(not set)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <input id="webhook_url" type="url" name="webhook_url" value="<?= h($webhookUrl) ?>" placeholder="https://hooks.slack.com/...">
		   <?php endif; ?>
		   <p class="muted">Fires when an unknown-path hit meets the threshold below. Slack/Discord URLs auto-detected; others receive generic JSON.</p>

		   <label for="webhook_template">Threat Webhook Payload Template (optional)</label>
		   <?php if ($isDemo): ?>
		       <div class="demo-locked-field"><?= $webhookTemplate !== '' ? h($webhookTemplate) : '(none)' ?> <span class="demo-lock-note">Not configurable in demo mode</span></div>
		   <?php else: ?>
		       <textarea id="webhook_template" name="webhook_template" rows="8" style="font-family: var(--font-mono); font-size: 0.8125rem; width: 100%; resize: vertical;" placeholder='{"event": "signaltrace_alert", "ip": "{{ip}}", "label": "{{label}}", "score": {{score}}}'><?= h($webhookTemplate) ?></textarea>
		   <?php endif; ?>
		   <p class="muted">
		       JSON template with placeholders. When set, overrides Slack/Discord auto-detection.<br>
		       Available: <code>{{ip}}</code> <code>{{token}}</code> <code>{{label}}</code> <code>{{score}}</code> <code>{{org}}</code> <code>{{asn}}</code> <code>{{country}}</code> <code>{{ua}}</code> <code>{{time}}</code> <code>{{triggers}}</code>
		   </p>

		   <label for="export_min_confidence">Export Minimum Confidence</label>
		   <select id="export_min_confidence" name="export_min_confidence">
		       <option value="human"        <?= $exportMinConf === 'human'        ? 'selected' : '' ?>>human</option>
		       <option value="uncertain" <?= $exportMinConf === 'uncertain' ? 'selected' : '' ?>>uncertain</option>
		       <option value="suspicious"   <?= $exportMinConf === 'suspicious'   ? 'selected' : '' ?>>suspicious</option>
		       <option value="bot"          <?= $exportMinConf === 'bot'          ? 'selected' : '' ?>>bot</option>
		   </select>
		   <p class="muted">Minimum classification label for exports when no dashboard filters are active.</p>

		   <label for="export_min_score">Export Minimum Score (0–100)</label>
		   <input id="export_min_score" type="number" min="0" max="100" name="export_min_score" value="<?= h($exportMinScore) ?>">
		   <p class="muted">Minimum numeric confidence score for exports. Acts as a second filter alongside the label — both conditions must be met. Set to 0 to disable score filtering.</p>

		   <label for="export_window_hours">Export Time Window (hours)</label>
		   <input id="export_window_hours" type="number" min="1" name="export_window_hours" value="<?= h($exportWinHours) ?>">
		   <p class="muted">How far back to look when no date filters are active (168 = 7 days). Use 87600 to export everything.</p>

		   <?php if ($baseUrl !== ''): ?>
		   <div style="margin-top: 1rem; padding: 0.875rem 1rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius);">
		       <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.6rem;">Export Endpoints</strong>
		       <p class="muted" style="margin-bottom: 0.5rem;">Authenticate with admin Basic Auth, or set <code>EXPORT_API_TOKEN</code> in <code>config.local.php</code> and use <code>Authorization: Bearer YOUR_TOKEN</code> (recommended — not logged) or <code>?api_key=YOUR_TOKEN</code> (appears in access logs).</p>
		       <div style="margin-bottom: 0.4rem;">
		           <span class="mono"><?= h(rtrim($baseUrl, '/') . '/export/json') ?></span>
		           <button type="button" class="copy-button" onclick="copyText('<?= h(rtrim($baseUrl, '/') . '/export/json') ?>')">Copy</button>
		       </div>
		       <div>
		           <span class="mono"><?= h(rtrim($baseUrl, '/') . '/export/csv') ?></span>
		           <button type="button" class="copy-button" onclick="copyText('<?= h(rtrim($baseUrl, '/') . '/export/csv') ?>')">Copy</button>
		       </div>
		   </div>
		   <?php endif; ?>

                    <button type="submit">Save Settings</button>
                </form>

                <div>
                    <form method="post" action="/admin/save-threat-feed-settings">
                        <h2>Threat Feed</h2>

                        <label>
                            <input type="checkbox" name="threat_feed_enabled" value="1" <?= $threatFeedEnabled ? 'checked' : '' ?>>
                            Enable threat feed
                        </label>

                        <label for="threat_feed_window_hours">Keep IPs on feed for this many hours</label>
                        <input id="threat_feed_window_hours" type="number" min="1" name="threat_feed_window_hours" value="<?= h($threatFeedWindowHours) ?>">

                        <label for="threat_feed_min_confidence">Minimum confidence to include</label>
                        <select id="threat_feed_min_confidence" name="threat_feed_min_confidence">
                            <option value="human" <?= $threatFeedMinConfidence === 'human' ? 'selected' : '' ?>>human</option>
                            <option value="likely-human" <?= $threatFeedMinConfidence === 'likely-human' ? 'selected' : '' ?>>likely-human</option>
                            <option value="suspicious" <?= $threatFeedMinConfidence === 'suspicious' ? 'selected' : '' ?>>suspicious</option>
                            <option value="bot" <?= $threatFeedMinConfidence === 'bot' ? 'selected' : '' ?>>bot</option>
                        </select>

                        <label for="threat_feed_min_hits">Minimum hits before adding to feed</label>
                        <input id="threat_feed_min_hits" type="number" min="1" name="threat_feed_min_hits" value="<?= h($threatFeedMinHits) ?>">
                        <p class="muted">An IP must be seen at least this many times within the window before appearing in the feed. Set to 1 to include on first hit.</p>

                        <button type="submit">Save Threat Feed Settings</button>
                    </form>

                    <?php
                    $feedCount = getThreatFeedCount($pdo);
                    ?>
                    <div style="margin-top: 1rem; padding: 0.875rem 1rem; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius);">
                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.6rem;">
                            Feed Preview
                        </strong>
                        <p class="muted" style="margin-bottom: 0.75rem;">
                            Currently <strong><?= (int) $feedCount['ipv4'] ?></strong> IPv4
                            and <strong><?= (int) $feedCount['ipv6'] ?></strong> IPv6
                            addresses in the feed
                            (<?= (int) $feedCount['total'] ?> total).
                        </p>

                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.5rem;">IPv4 Feeds</strong>
                        <?php
                        $ipv4Feeds = [
                            'Plain text'    => '/feed/ips.txt',
                            'Nginx deny'    => '/feed/ips.nginx',
                            'iptables'      => '/feed/ips.iptables',
                            'CIDR (/32)'    => '/feed/ips.cidr',
                        ];
                        $ipv6Feeds = [
                            'Plain text'    => '/feed/ipv6.txt',
                            'Nginx deny'    => '/feed/ipv6.nginx',
                            'ip6tables'     => '/feed/ipv6.iptables',
                            'CIDR (/128)'   => '/feed/ipv6.cidr',
                        ];
                        foreach ($ipv4Feeds as $label => $feedPath):
                            $fullUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . $feedPath;
                        ?>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <span style="font-size: 0.75rem; color: var(--text-secondary); min-width: 90px;"><?= h($label) ?></span>
                            <span class="mono" style="font-size: 0.75rem;"><?= h($fullUrl) ?></span>
                            <button type="button" class="copy-button" onclick="copyText('<?= h($fullUrl) ?>')">Copy</button>
                            <?php if ($baseUrl !== ''): ?>
                                <a class="copy-button" href="<?= h($fullUrl) ?>" target="_blank" rel="noopener">Open</a>
                            <?php endif; ?>
                        </div>
                        <?php endforeach; ?>

                        <strong style="display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-top: 0.75rem; margin-bottom: 0.5rem;">IPv6 Feeds</strong>
                        <?php foreach ($ipv6Feeds as $label => $feedPath):
                            $fullUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . $feedPath;
                        ?>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <span style="font-size: 0.75rem; color: var(--text-secondary); min-width: 90px;"><?= h($label) ?></span>
                            <span class="mono" style="font-size: 0.75rem;"><?= h($fullUrl) ?></span>
                            <button type="button" class="copy-button" onclick="copyText('<?= h($fullUrl) ?>')">Copy</button>
                            <?php if ($baseUrl !== ''): ?>
                                <a class="copy-button" href="<?= h($fullUrl) ?>" target="_blank" rel="noopener">Open</a>
                            <?php endif; ?>
                        </div>
                        <?php endforeach; ?>
                    </div>

                    <form method="post" action="/admin/save-retention-settings">
                        <h2>Data Retention</h2>

                        <label for="data_retention_days">Delete click data older than this many days</label>
                        <input id="data_retention_days" type="number" min="0" name="data_retention_days" value="<?= h($dataRetentionDays) ?>">

                        <p class="muted">
                            Set to 0 to disable automatic cleanup.
                        </p>

                        <button type="submit">Save Retention Settings</button>
                    </form>

                    <form method="post" action="/admin/run-cleanup" onsubmit="return confirm('Run cleanup using the current retention setting?');">
                        <h2>Manual Cleanup</h2>
                        <p class="muted">Run cleanup now using the saved retention setting.</p>
                        <button type="submit" class="warning-button">Run Cleanup Now</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="tab-content" id="content-skip">
            <form method="post" action="/admin/create-skip-pattern">
                <h2>Create Skip Pattern</h2>

                <label for="skip_type">Pattern Type</label>
                <select id="skip_type" name="type">
                    <option value="exact">Exact</option>
                    <option value="contains">Contains</option>
                    <option value="prefix">Prefix</option>
                </select>

                <label for="skip_pattern">Pattern</label>
                <input id="skip_pattern" type="text" name="pattern" required placeholder=".env or api/">

                <button type="submit">Add Skip Pattern</button>
            </form>

            <h2>Skip Patterns</h2>
            <div class="table-wrap">
                <table class="compact-table">
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Pattern</th>
                        <th>Active</th>
                        <th class="skip-actions-col">Actions</th>
                    </tr>
                    <?php foreach ($skipPatterns as $pattern): ?>
                        <tr>
                            <td><?= (int) $pattern['id'] ?></td>
                            <td><?= h((string) $pattern['type']) ?></td>
                            <td class="mono"><?= h((string) $pattern['pattern']) ?></td>
                            <td><?= ((int) $pattern['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td class="skip-actions-col">
                                <?php if ((int) $pattern['active'] === 1): ?>
                                    <form method="post" action="/admin/deactivate-skip-pattern" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int) $pattern['id'] ?>">
                                        <button type="submit">Deactivate</button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="/admin/activate-skip-pattern" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int) $pattern['id'] ?>">
                                        <button type="submit">Activate</button>
                                    </form>
                                <?php endif; ?>

                                <form method="post" action="/admin/delete-skip-pattern" class="inline-action-form" onsubmit="return confirm('Delete this skip pattern?');">
                                    <input type="hidden" name="id" value="<?= (int) $pattern['id'] ?>">
                                    <button type="submit">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>

        <script>
        /* --------------------------------------------------------
           THEME TOGGLE
           Persists choice in localStorage; applies to <html>
           so the CSS [data-theme] selectors pick it up.
           -------------------------------------------------------- */
        (function () {
            var saved = localStorage.getItem('st-theme');
            var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            var theme = saved || (prefersDark ? 'dark' : 'light');
            document.documentElement.setAttribute('data-theme', theme);
        })();

        function toggleTheme() {
            var current = document.documentElement.getAttribute('data-theme') || 'light';
            var next    = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('st-theme', next);
            updateThemeButton(next);
        }

        function updateThemeButton(theme) {
            var icon  = document.getElementById('theme-icon');
            var label = document.getElementById('theme-label');
            if (!icon || !label) return;
            if (theme === 'dark') {
                icon.textContent  = '🌙';
                label.textContent = 'Dark';
            } else {
                icon.textContent  = '☀️';
                label.textContent = 'Light';
            }
        }

        /* --------------------------------------------------------
           CSRF TOKEN INJECTION
           Injects the CSRF hidden field into every POST form.
           -------------------------------------------------------- */
        const CSRF_TOKEN = <?= json_encode($csrfToken) ?>;

        function injectCsrf() {
            document.querySelectorAll('form[method="post"], form[method="POST"]').forEach(function (form) {
                if (!form.querySelector('input[name="csrf_token"]')) {
                    var input   = document.createElement('input');
                    input.type  = 'hidden';
                    input.name  = 'csrf_token';
                    input.value = CSRF_TOKEN;
                    form.appendChild(input);
                }
            });
        }

        /* Run immediately for forms already in the DOM */
        injectCsrf();

        /* --------------------------------------------------------
           TAB MANAGEMENT
           -------------------------------------------------------- */
        function showTab(name) {
            document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
            document.querySelectorAll('.tab-content').forEach(function (c) { c.classList.remove('active'); });
            var tab     = document.getElementById('tab-' + name);
            var content = document.getElementById('content-' + name);
            if (tab && content) {
                tab.classList.add('active');
                content.classList.add('active');
                localStorage.setItem('activeTab', name);
            }
        }

        function toggleDetails(id, button) {
            var row  = document.getElementById(id);
            if (!row) return;
            var open = row.classList.toggle('open');
            if (button) { button.textContent = open ? 'Hide' : 'Details'; }
        }

        /* --------------------------------------------------------
           COPY TO CLIPBOARD
           -------------------------------------------------------- */
        async function copyText(value) {
            try {
                await navigator.clipboard.writeText(value);
            } catch (e) {
                var temp = document.createElement('textarea');
                temp.value = value;
                document.body.appendChild(temp);
                temp.select();
                document.execCommand('copy');
                document.body.removeChild(temp);
            }
        }

        /* --------------------------------------------------------
           DOMContentLoaded — tab restore, CSRF re-injection,
           auto-refresh, theme button sync
           -------------------------------------------------------- */
        document.addEventListener('DOMContentLoaded', function () {

            /* Sync button label with current theme */
            var currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            updateThemeButton(currentTheme);

            /* Inject CSRF into any forms rendered after the initial parse */
            injectCsrf();

            /* Tab restore — URL param beats localStorage */
            var urlParams  = new URLSearchParams(window.location.search);
            var tabFromUrl = urlParams.get('tab');
            var saved      = tabFromUrl || localStorage.getItem('activeTab') || 'dashboard';
            showTab(saved);

            /* Auto-refresh — only fires when the dashboard tab is active */
            var refreshSecs = <?= (int) $autoRefreshSecs ?>;
            if (refreshSecs > 0) {
                setTimeout(function () {
                    var active = document.querySelector('.tab.active');
                    if (active && active.id === 'tab-dashboard') {
                        window.location.reload();
                    }
                }, refreshSecs * 1000);
            }
        });
        </script>
    </div><!-- /.page-body -->
    </body>
    </html>
    <?php
}
