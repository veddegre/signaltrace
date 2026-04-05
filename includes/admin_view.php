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
    array $links,
    array $tokenCounts,
    array $skipPatterns,
    array $asnRules,
    string $refreshUrl
): void {
    $pdo = db();

    $dateFrom = trim((string)($_GET['date_from'] ?? ''));
    $dateTo = trim((string)($_GET['date_to'] ?? ''));
    $showAll = isset($_GET['show_all']) && $_GET['show_all'] === '1';

    $activeTab = trim((string)($_GET['tab'] ?? ''));
    $editLinkId = (int)($_GET['edit_link_id'] ?? 0);

    $editLink = null;
    if ($editLinkId > 0) {
        foreach ($links as $candidateLink) {
            if ((int)$candidateLink['id'] === $editLinkId) {
                $editLink = $candidateLink;
                break;
            }
        }
    }

    $hasActiveFilter = (
        $tokenFilter !== '' ||
        $ipFilter !== '' ||
        $visitorFilter !== '' ||
	$knownOnly ||
	$showAll ||
        $dateFrom !== '' ||
        $dateTo !== ''
    );
    $exportUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . '/export/json';

    $threatFeedEnabled = getSetting($pdo, 'threat_feed_enabled', '1') === '1';
    $threatFeedWindowHours = (string)(getSetting($pdo, 'threat_feed_window_hours', '168') ?? '168');
    $threatFeedMinConfidence = (string)(getSetting($pdo, 'threat_feed_min_confidence', 'suspicious') ?? 'suspicious');
    $dataRetentionDays = (string)(getSetting($pdo, 'data_retention_days', '0') ?? '0');

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

        return '/expor//json' . (!empty($params) ? '?' . http_build_query($params) : '');
    };

    $threatFeedUrl = ($baseUrl !== '' ? rtrim($baseUrl, '/') : '') . '/feed/ips.txt';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title><?= h($appName) ?></title>
        <style>
            body { font-family: Arial, sans-serif; margin: 2rem; background: #f7f7f7; color: #222; }
            h1, h2 { margin-top: 0; }
            table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 2rem; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
            th { background: #f0f0f0; }
            .bot { background: #fff2f2; }
            .mono { font-family: Consolas, Monaco, monospace; font-size: 0.92rem; }
            .small { font-size: 0.9rem; color: #555; }
            .wrap { white-space: normal; overflow-wrap: anywhere; word-break: break-word; }

            form { background: #fff; padding: 1rem; border: 1px solid #ddd; margin-bottom: 2rem; }
            input[type="text"], input[type="url"], input[type="date"], input[type="number"], select {
                width: 100%;
                padding: 8px;
                margin-bottom: 10px;
                box-sizing: border-box;
            }

            .inline-form input[type="text"],
            .inline-form input[type="date"] {
                width: auto;
                min-width: 180px;
                margin-right: 8px;
                margin-bottom: 0;
            }

            .inline-form label { margin-right: 10px; }
            .muted { color: #666; }

            .inline-action-form {
                display: inline-block;
                background: transparent;
                padding: 0;
                border: 0;
                margin: 0 4px 4px 0;
            }

            .filter-container {
		display: flex;
                flex-direction: column;
                gap: 10px;
            }

            .filter-inputs {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
            }

	    .filter-inputs input[type="text"],
	    .filter-inputs input[type="date"] {
                width: auto;
                min-width: 220px;
                margin-bottom: 0;
            }

            .filter-toggles {
                display: flex;
                flex-wrap: wrap;
                gap: 16px;
                align-items: center;
            }

	    .filter-toggles label {
	        display: inline-flex;
	        align-items: center;
	        gap: 6px;
	        margin-right: 0;
	        white-space: nowrap;
            }

	    .filter-actions {
	        display: flex;
	        gap: 8px;
 	        align-items: center;
	        flex-wrap: wrap;
	        margin-left: 0;
            }

            .tabs {
                display: flex;
                border-bottom: 2px solid #ddd;
                margin-bottom: 1rem;
                gap: 6px;
                flex-wrap: wrap;
            }

            .tab {
                padding: 10px 15px;
                cursor: pointer;
                border: 1px solid #ddd;
                border-bottom: none;
                background: #f0f0f0;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }

            .tab.active {
                background: #fff;
                font-weight: bold;
            }

            .tab-content {
                display: none;
            }

            .tab-content.active {
                display: block;
            }

            .badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 999px;
                font-size: 0.85rem;
                font-weight: bold;
            }

            .badge-human { background: #dff5e1; color: #1e6b2c; }
            .badge-likely-human { background: #e8f1ff; color: #1b4d9b; }
            .badge-suspicious { background: #fff3cd; color: #8a6d1f; }
            .badge-bot { background: #f8d7da; color: #8a1f2d; }

            .table-wrap {
                overflow-x: auto;
            }

            .compact-table {
                table-layout: fixed;
            }

            .compact-table th,
            .compact-table td {
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                max-width: 180px;
            }

            .compact-table th.time-col,
            .compact-table td.time-col {
                max-width: none;
                width: 210px;
                min-width: 210px;
                overflow: visible;
                text-overflow: clip;
                white-space: nowrap;
            }

            .compact-table th.type-col,
            .compact-table td.type-col {
                width: 90px;
                min-width: 90px;
                max-width: 90px;
            }

            .compact-table th.token-col,
            .compact-table td.token-col {
                width: 230px;
                min-width: 230px;
                max-width: 230px;
            }

            .compact-table th.ip-col,
            .compact-table td.ip-col {
                max-width: none;
                width: 155px;
                min-width: 155px;
                overflow: visible;
                text-overflow: clip;
                white-space: nowrap;
            }

            .compact-table th.details-col,
            .compact-table td.details-col {
                width: 110px;
                min-width: 110px;
                max-width: 110px;
	    }

            .compact-table th.actions-col,
            .compact-table td.actions-col {
		width: 230px;
                min-width: 230px;
                max-width: 230px;
                white-space: normal;
                overflow: visible;
                text-overflow: unset;
            }

            .compact-table th.skip-actions-col,
            .compact-table td.skip-actions-col {
	        width: 170px;
	        min-width: 170px;
                max-width: 170px;
                white-space: normal;
                overflow: visible;
                text-overflow: unset;
            }


	    .compact-table th.classification-col,
	    .compact-table td.classification-col {
	        width: 220px;
		min-width: 220px;
	        max-width: 220px;
		white-space: nowrap;
		overflow: visible;
		text-overflow: unset;
	    }

	    .score-pill {
		display: inline-block;
		margin-left: 6px;
		padding: 1px 5px;
		font-size: 0.7em;
		line-height: 1;
		border-radius: 999px;
		background: #f0f0f0;
		color: #666;
		white-space: nowrap;
		vertical-align: middle;
	    }

	    .actions-col form,
	    .skip-actions-col form {
	        display: inline-block;
	        margin: 2px 4px 2px 0;
            }

	    .url-cell {
	        display: flex;
	        align-items: center;
                gap: 6px;
                flex-wrap: wrap;
            }

            .url-cell .copy-button {
                margin-left: 0;
	    }


	    .actions-col .button-link,
   	    form .button-link {
   	        display: inline-block;
		padding: 6px 10px;
	        background: #f3f4f6;
 	        color: #111827;
	        border: 1px solid #d1d5db;
	        border-radius: 4px;
	        text-decoration: none;
	        line-height: 1.2;
	        font-size: 14px;
 	        cursor: pointer;
            }

	    .actions-col .button-link:hover,
	    form .button-link:hover {
	        background: #e5e7eb;
	        color: #111827;
	        text-decoration: none;
	    }

            .table-link {
                color: #1d4ed8;
                text-decoration: none;
                font-weight: 500;
            }

            .table-link:hover {
                text-decoration: underline;
                color: #1e40af;
            }

            .mono-link {
                font-family: Consolas, Monaco, monospace;
                font-size: 0.92rem;
            }

            .details-row {
                display: none;
                background: #fafafa;
            }

            .details-row.open {
                display: table-row;
            }

            .details-cell {
                padding: 14px;
                background: #fafafa;
            }

            .details-grid {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
                align-items: start;
            }

            .detail-box {
                background: #fff;
                border: 1px solid #ddd;
                padding: 10px;
                min-width: 0;
                overflow: hidden;
            }

            .detail-box strong {
                display: block;
                margin-bottom: 6px;
            }

            .detail-box,
            .detail-box div,
            .detail-box span,
            .wrap {
                white-space: normal;
                overflow-wrap: anywhere;
                word-break: break-word;
            }

            .details-button,
            .copy-button {
                padding: 6px 10px;
                font-size: 0.9rem;
            }
	    .copy-button {
		display: inline-block;
		padding: 3px 6px;
		margin-left: 6px;
		background: #f3f4f6;
		color: #111827;
		border: 1px solid #d1d5db;
		border-radius: 4px;
		text-decoration: none; /* remove underline */
		font-family: Consolas, Monaco, monospace;
		font-size: 11px;
		line-height: 1.2;
		cursor: pointer;
	    }

	    .copy-button:hover {
		background: #e5e7eb;
		color: #111827;        /* prevent link blue */
		text-decoration: none; /* prevent underline on hover */
	    }

	    .copy-button:active {
		background: #d1d5db;
	   }

            .filter-actions {
                display: inline-flex;
                gap: 8px;
                align-items: center;
                flex-wrap: wrap;
                margin-left: 8px;
            }

            .filter-actions button,
            .button-link {
                display: inline-block;
                padding: 10px 14px;
                background: #f3f4f6;
                color: #111827;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                text-decoration: none;
                line-height: 1.2;
                font-size: 14px;
                cursor: pointer;
            }

            .filter-actions button:hover,
            .button-link:hover {
                background: #e5e7eb;
            }

            .danger-button {
                background: #b91c1c;
                color: #fff;
                border: 0;
                border-radius: 4px;
            }

            .danger-button:hover {
                background: #991b1b;
            }

            .warning-button {
                background: #d97706;
                color: #fff;
                border: 0;
                border-radius: 4px;
            }

            .warning-button:hover {
                background: #b45309;
            }

            .pill-link {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 999px;
                border: 1px solid #d1d5db;
                background: #f9fafb;
                color: #111827;
                text-decoration: none;
            }

            .pill-link:hover {
                background: #eef2f7;
            }

            .active-filters {
                margin: 0 0 1rem 0;
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                align-items: center;
            }

            .filter-pill {
                display: inline-flex;
                gap: 6px;
                align-items: center;
                padding: 6px 10px;
                border-radius: 999px;
                background: #e5e7eb;
                color: #111827;
                font-size: 0.9rem;
            }

            .filter-pill a {
                color: #111827;
                text-decoration: none;
                font-weight: bold;
            }

            .utility-links {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                margin: 0 0 1rem 0;
            }

            .two-column-settings {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 16px;
            }

            @media (max-width: 1100px) {
                .details-grid,
                .two-column-settings {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <h1><?= h($appName) ?></h1>

        <div class="tabs">
            <div class="tab" id="tab-dashboard" onclick="showTab('dashboard')">Dashboard</div>
            <div class="tab" id="tab-links" onclick="showTab('links')">Tokens</div>
            <div class="tab" id="tab-settings" onclick="showTab('settings')">Settings</div>
	    <div class="tab" id="tab-skip" onclick="showTab('skip')">Skip Patterns</div>
            <div class="tab" id="tab-asn" onclick="showTab('asn')">ASN Rules</div>
        </div>

        <div class="tab-content" id="content-dashboard">
            <form method="get" action="/admin" class="inline-form">
		<h2>Filter Activity</h2>
		<div class="filter-container">
                    <div class="filter-input">
	                <input type="text" name="token" value="<?= h($tokenFilter) ?>" placeholder="Filter by token or path">
	                <input type="text" name="ip" value="<?= h($ipFilter) ?>" placeholder="Filter by IP">
	                <input type="text" name="visitor" value="<?= h($visitorFilter) ?>" placeholder="Filter by visitor hash">
	                <input type="date" name="date_from" value="<?= h($dateFrom) ?>" placeholder="From date">
			<input type="date" name="date_to" value="<?= h($dateTo) ?>" placeholder="To date">
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
                <form method="post" action="/admin/delete-token-clicks" class="inline-form" onsubmit="return confirm('Delete unknown-only clicks for this token/path?');">
                    <h2>Token Cleanup</h2>
                    <input type="hidden" name="token" value="<?= h($tokenFilter) ?>">
                    <input type="hidden" name="mode" value="unknown_only">
                    <button type="submit" class="warning-button">Delete Unknown Token Hits</button>
		</form>

		<form method="post" action="/admin/delete-ip-clicks" class="inline-action-form" onsubmit="return confirm('Delete unknown-only clicks for this IP?');">
		    <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
		    <input type="hidden" name="mode" value="unknown_only">
		    <button type="submit" class="warning-button">Delete Unknown IP Hits</button>
		</form>

		<form method="post" action="/admin/delete-ip-clicks" class="inline-action-form" onsubmit="return confirm('Delete ALL clicks for this IP?');">
		    <input type="hidden" name="ip" value="<?= h($rowIp) ?>">
		    <input type="hidden" name="mode" value="all">
		    <button type="submit" class="danger-button">Delete All Clicks for IP</button>
		</form>
		
                <form method="post" action="/admin/delete-token-clicks" class="inline-form" onsubmit="return confirm('Delete ALL clicks for this token/path?');">
                    <input type="hidden" name="token" value="<?= h($tokenFilter) ?>">
                    <input type="hidden" name="mode" value="all">
                    <button type="submit" class="danger-button">Delete All Clicks for Token</button>
                </form>
	    <?php endif; ?>


	    <?php if ($ipFilter !== '' && !$knownOnly && $tokenFilter === '' && $visitorFilter === '' && $dateFrom === '' && $dateTo === ''): ?>
	       <form method="post" action="/admin/delete-ip-clicks" class="inline-form">
                  <h2>IP Cleanup</h2>
	             <input type="hidden" name="ip" value="<?= h($ipFilter) ?>">
        		<div class="filter-actions" style="margin-left: 0;">
		            <button type="submit" name="mode" value="unknown_only" class="warning-button" onclick="return confirm('Delete unknown-only clicks for this IP?');">
		                Delete Unknown IP Hits
		            </button>

		            <button type="submit" name="mode" value="all" class="danger-button" onclick="return confirm('Delete ALL clicks for this IP?');">
		                Delete All Clicks for IP
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
                                <a class="table-link mono-link" href="<?= h($buildAdminUrl(['token' => (string)$row['token']])) ?>">
                                    <?= h((string)$row['token']) ?>
                                </a>
                            </td>
                            <td><?= (int)$row['hit_count'] ?></td>
                            <td><?= h((string)$row['last_seen']) ?></td>
                            <td><?= ((int)$row['is_known'] === 1) ? 'Yes' : 'No' ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
	    </div>
            <?php endif; ?>

            <h2>Activity</h2>
            <p class="muted">
                <?= $knownOnly ? 'Showing only known tokens.' : 'Showing all clicks that were not suppressed as noise.' ?>
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
                        $confidenceLabel = (string)($c['confidence_label'] ?? '');
                        $badgeClass = match ($confidenceLabel) {
                            'human' => 'badge badge-human',
                            'likely-human' => 'badge badge-likely-human',
                            'suspicious' => 'badge badge-suspicious',
                            'bot' => 'badge badge-bot',
                            default => 'badge'
                        };
                        $detailsId = 'details-' . $i;
			$rowToken = (string)($c['token'] ?? '');
			$displayToken = ($rowToken === 'root') ? '/' : $rowToken;
                        $rowIp = (string)($c['ip'] ?? '');
                        $rowVisitor = (string)($c['visitor_hash'] ?? '');
                        $rowUa = (string)($c['user_agent'] ?? '');
                        ?>
                        <tr class="<?= $confidenceLabel === 'bot' ? 'bot' : '' ?>">
                            <td class="time-col"><?= h((string)($c['clicked_at'] ?? '')) ?></td>
                            <td class="type-col"><?= h((string)($c['event_type'] ?? 'click')) ?></td>
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
			    <td><?= h((string)($c['ip_org'] ?? '')) ?></td>
			    <?php $rowScore = (int)($c['confidence_score'] ?? 0); ?>
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
                                            <span class="mono">Click ID:</span> <?= h((string)($c['id'] ?? '')) ?>
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
					    $rowAsn = (string)($c['ip_asn'] ?? '');
					    $asnRule = $rowAsn !== '' ? getAsnRuleByAsn($pdo, $rowAsn) : null;
?>
					<div>
					    <span class="mono">ASN:</span> <?= h($rowAsn) ?>

					    <?php if ($rowAsn !== '' && $asnRule === null): ?>
					        <form method="post" action="/admin/create-asn-rule" class="inline-action-form" style="display:inline-block;">
					            <input type="hidden" name="asn" value="<?= h($rowAsn) ?>">
					            <input type="hidden" name="label" value="<?= h((string)($c['ip_org'] ?? '')) ?>">
					            <input type="hidden" name="penalty" value="10">
					            <button type="submit" class="copy-button">Add ASN Rule</button>
					        </form>
					    <?php elseif ($asnRule !== null): ?>
					        <span class="badge badge-suspicious">ASN rule active</span>
					    <?php endif; ?>
					</div>
                                        <div><span class="mono">Org:</span> <?= h((string)($c['ip_org'] ?? '')) ?></div>
                                        <div><span class="mono">Country:</span> <?= h((string)($c['ip_country'] ?? '')) ?></div>
                                        <div>
                                            <span class="mono">Visitor:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['visitor' => $rowVisitor])) ?>"><?= h($rowVisitor) ?></a>
                                            <button type="button" class="copy-button" onclick="copyText('<?= h($rowVisitor) ?>')">Copy</button>
                                        </div>
                                        <div><span class="mono">XFF:</span> <?= h((string)($c['x_forwarded_for'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box">
					<strong>Scoring</strong>
					<?php
						$score = (int)($c['confidence_score'] ?? 0);
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
					<div><span class="mono">Classification:</span> <?= h((string)($c['confidence_label'] ?? '')) ?> (<?= h((string)($c['confidence_score'] ?? '')) ?>)</div>
                                        <div><span class="mono">Reason:</span> <span class="wrap"><?= h((string)($c['confidence_reason'] ?? '')) ?></span></div>
                                        <div><span class="mono">First for token:</span> <?= !empty($c['first_for_token']) ? 'Yes' : 'No' ?></div>
                                        <div><span class="mono">Prior events for token:</span> <?= h((string)($c['prior_events_for_token'] ?? '0')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Request</strong>
                                        <div>
                                            <span class="mono">Token / Path:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['token' => $rowToken])) ?>"><?= h($rowToken) ?></a>
                                            <button type="button" class="copy-button" onclick="copyText('<?= h($rowToken) ?>')">Copy</button>
                                        </div>
                                        <div><span class="mono">Method:</span> <?= h((string)($c['request_method'] ?? '')) ?></div>
                                        <div><span class="mono">Host:</span> <?= h((string)($c['host'] ?? '')) ?></div>
                                        <div><span class="mono">Scheme:</span> <?= h((string)($c['scheme'] ?? '')) ?></div>
                                        <div><span class="mono">URI:</span> <span class="wrap"><?= h((string)($c['request_uri'] ?? '')) ?></span></div>
                                        <div><span class="mono">Query:</span> <span class="wrap"><?= h((string)($c['query_string'] ?? '')) ?></span></div>
                                        <div><span class="mono">Remote port:</span> <?= h((string)($c['remote_port'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Headers</strong>
                                        <div><span class="mono">Referer:</span> <span class="wrap"><?= h((string)($c['referer'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept:</span> <span class="wrap"><?= h((string)($c['accept'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept-Language:</span> <span class="wrap"><?= h((string)($c['accept_language'] ?? '')) ?></span></div>
                                        <div><span class="mono">Accept-Encoding:</span> <span class="wrap"><?= h((string)($c['accept_encoding'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Site:</span> <span class="wrap"><?= h((string)($c['sec_fetch_site'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Mode:</span> <span class="wrap"><?= h((string)($c['sec_fetch_mode'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-Fetch-Dest:</span> <span class="wrap"><?= h((string)($c['sec_fetch_dest'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-CH-UA:</span> <span class="wrap"><?= h((string)($c['sec_ch_ua'] ?? '')) ?></span></div>
                                        <div><span class="mono">Sec-CH-UA-Platform:</span> <span class="wrap"><?= h((string)($c['sec_ch_ua_platform'] ?? '')) ?></span></div>
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
                                        <form method="post" action="/admin/delete-click" class="inline-action-form" onsubmit="return confirm('Delete this click?');">
                                            <input type="hidden" name="id" value="<?= h((string)($c['id'] ?? '')) ?>">
                                            <button type="submit" class="danger-button">Delete This Click</button>
                                        </form>

                                        <form method="post" action="/admin/add-token-to-skip" class="inline-action-form" onsubmit="return confirm('Add this token/path to skip patterns?');">
                                            <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                            <input type="hidden" name="redirect_token" value="<?= h($rowToken) ?>">
                                            <button type="submit" class="warning-button">Skip Exact Token</button>
                                        </form>

                                        <?php if (empty($c['link_id'])): ?>
                                            <form method="post" action="/admin/delete-token-clicks" class="inline-action-form" onsubmit="return confirm('Delete unknown-only clicks for this token/path?');">
                                                <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                                <input type="hidden" name="mode" value="unknown_only">
                                                <button type="submit" class="warning-button">Delete Unknown Token Hits</button>
                                            </form>
                                        <?php endif; ?>

                                        <form method="post" action="/admin/delete-token-clicks" class="inline-action-form" onsubmit="return confirm('Delete ALL clicks for this token/path?');">
                                            <input type="hidden" name="token" value="<?= h($rowToken) ?>">
                                            <input type="hidden" name="mode" value="all">
                                            <button type="submit" class="danger-button">Delete All Clicks for Token</button>
                                        </form>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>

	<div class="tab-content" id="content-links">
	    <?php if ($editLink !== null): ?>
	    <form method="post" action="/admin/update-link">
	        <h2>Edit Token</h2>

	        <input type="hidden" name="id" value="<?= (int)$editLink['id'] ?>">

	        <label for="edit_token">Token / Path</label>
	        <input id="edit_token" type="text" name="token" required value="<?= h((string)$editLink['token']) ?>">

	        <label for="edit_destination">Destination URL</label>
	        <input id="edit_destination" type="url" name="destination" required value="<?= h((string)$editLink['destination']) ?>">

	        <label for="edit_description">Description</label>
	        <input id="edit_description" type="text" name="description" value="<?= h((string)($editLink['description'] ?? '')) ?>">
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
                        <th>Path URL</th>
                        <th>Pixel URL</th>
                        <th class="actions-col">Actions</th>
                    </tr>
		    <?php foreach ($links as $link): ?>
		   <?php
			$tokenUrl = $baseUrl !== ''
			    ? rtrim($baseUrl, '/') . '/' . ltrim((string)$link['token'], '/')
			    : '';

			$pixelUrl = $baseUrl !== ''
			    ? rtrim($baseUrl, '/') . '/pixel/' . $link['token'] . '.gif'
			    : '';
		?>
		<tr>
		    <td><?= (int)$link['id'] ?></td>
		    <td class="mono">
		        <a class="table-link mono-link" href="<?= h($buildAdminUrl(['token' => (string)$link['token'], 'tab' => 'links'])) ?>">
		            <?= h((string)$link['token']) ?>
		        </a>
		    </td>
		    <td><?= h((string)($link['description'] ?? '')) ?></td>
		    <td class="wrap"><?= h((string)$link['destination']) ?></td>
		    <td><?= ((int)$link['active'] === 1) ? 'Yes' : 'No' ?></td>
		    <td><?= (int)$link['click_count'] ?></td>

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
			       <input type="hidden" name="edit_link_id" value="<?= (int)$link['id'] ?>">
	 		       <button type="submit">Edit</button>
			   </form>

		        <?php if ((int)$link['active'] === 1): ?>
		            <form method="post" action="/admin/deactivate-link" class="inline-action-form">
               			 <input type="hidden" name="id" value="<?= (int)$link['id'] ?>">
		                <button type="submit">Deactivate</button>
		            </form>
		        <?php else: ?>
		            <form method="post" action="/admin/activate-link" class="inline-action-form">
		                <input type="hidden" name="id" value="<?= (int)$link['id'] ?>">
		                <button type="submit">Activate</button>
   		         </form>
     			 <?php endif; ?>

		        <form method="post" action="/admin/delete-link" class="inline-action-form" onsubmit="return confirm('Delete this token/path?');">
		            <input type="hidden" name="id" value="<?= (int)$link['id'] ?>">
		            <button type="submit">Delete</button>
		        </form>

		        <form method="post" action="/admin/delete-link" class="inline-action-form" onsubmit="return confirm('Delete this token/path and all related clicks?');">
		            <input type="hidden" name="id" value="<?= (int)$link['id'] ?>">
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
	    <form method="post" action="/admin/create-asn-rule">
	        <h2>Create ASN Rule</h2>
	        <label for="asn">ASN</label>
	        <input id="asn" type="text" name="asn" required placeholder="8075">
	        <label for="asn_label">Label</label>
	        <input id="asn_label" type="text" name="label" placeholder="Microsoft">
	        <label for="asn_penalty">Penalty</label>
	        <input id="asn_penalty" type="number" name="penalty" min="1" max="100" value="10">
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
	                <th class="skip-actions-col">Actions</th>
	            </tr>
	            <?php foreach ($asnRules as $rule): ?>
	                <tr>
	                    <td><?= (int)$rule['id'] ?></td>
	                    <td class="mono"><?= h((string)$rule['asn']) ?></td>
	                    <td><?= h((string)($rule['label'] ?? '')) ?></td>
	                    <td><?= (int)$rule['penalty'] ?></td>
	                    <td><?= ((int)$rule['active'] === 1) ? 'Yes' : 'No' ?></td>
	                    <td class="skip-actions-col">
	                        <?php if ((int)$rule['active'] === 1): ?>
	                            <form method="post" action="/admin/deactivate-asn-rule" class="inline-action-form">
	                                <input type="hidden" name="id" value="<?= (int)$rule['id'] ?>">
	                                <button type="submit">Deactivate</button>
	                            </form>
	                        <?php else: ?>
	                            <form method="post" action="/admin/activate-asn-rule" class="inline-action-form">
	                                <input type="hidden" name="id" value="<?= (int)$rule['id'] ?>">
	                                <button type="submit">Activate</button>
	                            </form>
	                        <?php endif; ?>
	                        <form method="post" action="/admin/delete-asn-rule" class="inline-action-form" onsubmit="return confirm('Delete this ASN rule?');">
	                            <input type="hidden" name="id" value="<?= (int)$rule['id'] ?>">
	                            <button type="submit">Delete</button>
	                        </form>
	                    </td>
	                </tr>
	            <?php endforeach; ?>
	        </table>
	    </div>
	</div>

        <div class="tab-content" id="content-settings">
            <div class="two-column-settings">
                <form method="post" action="/admin/save-settings">
                    <h2>Settings</h2>

                    <label for="app_name">App Name</label>
                    <input id="app_name" type="text" name="app_name" value="<?= h((string)$appName) ?>" required>

                    <label for="base_url">Base URL</label>
                    <input id="base_url" type="url" name="base_url" value="<?= h((string)$baseUrl) ?>" placeholder="https://yourdomain.example">

                    <label for="default_redirect_url">Default Redirect URL</label>
                    <input id="default_redirect_url" type="url" name="default_redirect_url" value="<?= h((string)$defaultRedirectUrl) ?>" required>

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
		   <input id="display_min_score" type="number"  min="0" max="100" name="display_min_score" value="<?= h((string)getSetting($pdo, 'display_min_score', '20')) ?>">

		   <p class="muted">Hide lower-scored events from the dashboard unless “Show all” is checked.</p>

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

                        <p class="muted">
                            Feed URL:
                            <span class="mono"><?= h($threatFeedUrl) ?></span>
			</p>

			<p class="muted">
			    Export URL:
			    <span class="mono"><?= h($exportUrl) ?></span>
			</p>

			<div class="utility-links">
			    <button type="button" class="button-link" onclick="copyText('<?= h($threatFeedUrl) ?>')">
			        Copy Feed URL
			    </button>

			    <?php if ($baseUrl !== ''): ?>
			        <a class="button-link" href="<?= h($threatFeedUrl) ?>" target="_blank" rel="noopener">
			            Open Feed
			        </a>
			    <?php endif; ?>

			    <button type="button" class="button-link" onclick="copyText('<?= h($exportUrl) ?>')">
			        Copy Export URL
			    </button>

			    <a class="button-link" href="<?= h($exportUrl) ?>" target="_blank" rel="noopener">
			        Open Export
			    </a>
			</div>

                        <button type="submit">Save Threat Feed Settings</button>
                    </form>

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
                            <td><?= (int)$pattern['id'] ?></td>
                            <td><?= h((string)$pattern['type']) ?></td>
                            <td class="mono"><?= h((string)$pattern['pattern']) ?></td>
                            <td><?= ((int)$pattern['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td class="skip-actions-col">
                                <?php if ((int)$pattern['active'] === 1): ?>
                                    <form method="post" action="/admin/deactivate-skip-pattern" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int)$pattern['id'] ?>">
                                        <button type="submit">Deactivate</button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="/admin/activate-skip-pattern" class="inline-action-form">
                                        <input type="hidden" name="id" value="<?= (int)$pattern['id'] ?>">
                                        <button type="submit">Activate</button>
                                    </form>
                                <?php endif; ?>

                                <form method="post" action="/admin/delete-skip-pattern" class="inline-action-form" onsubmit="return confirm('Delete this skip pattern?');">
                                    <input type="hidden" name="id" value="<?= (int)$pattern['id'] ?>">
                                    <button type="submit">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>

        <script>
        function showTab(name) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            const tab = document.getElementById('tab-' + name);
            const content = document.getElementById('content-' + name);

            if (tab && content) {
                tab.classList.add('active');
                content.classList.add('active');
                localStorage.setItem('activeTab', name);
            }
        }

        function toggleDetails(id, button) {
            const row = document.getElementById(id);
            if (!row) return;

            const open = row.classList.toggle('open');
            if (button) {
                button.textContent = open ? 'Hide' : 'Details';
            }
        }

        async function copyText(value) {
            try {
                await navigator.clipboard.writeText(value);
            } catch (e) {
                const temp = document.createElement('textarea');
                temp.value = value;
                document.body.appendChild(temp);
                temp.select();
                document.execCommand('copy');
                document.body.removeChild(temp);
            }
        }

        document.addEventListener('DOMContentLoaded', function () {
            const saved = localStorage.getItem('activeTab') || 'dashboard';
            showTab(saved);
        });
        </script>
    </body>
    </html>
    <?php
}
