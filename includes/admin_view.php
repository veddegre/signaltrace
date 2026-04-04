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
    string $refreshUrl
): void {
    $pdo = db();

    $hasActiveFilter = ($tokenFilter !== '' || $ipFilter !== '' || $visitorFilter !== '' || $knownOnly);

    $threatFeedEnabled = getSetting($pdo, 'threat_feed_enabled', '1') === '1';
    $threatFeedWindowHours = (string)(getSetting($pdo, 'threat_feed_window_hours', '168') ?? '168');
    $threatFeedMinConfidence = (string)(getSetting($pdo, 'threat_feed_min_confidence', 'suspicious') ?? 'suspicious');

    $buildAdminUrl = function (array $overrides = []) use ($tokenFilter, $ipFilter, $visitorFilter, $knownOnly): string {
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

        foreach ($overrides as $key => $value) {
            if ($value === null || $value === '') {
                unset($params[$key]);
            } else {
                $params[$key] = $value;
            }
        }

        return '/admin' . (!empty($params) ? '?' . http_build_query($params) : '');
    };
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
            input[type="text"], input[type="url"], select {
                width: 100%;
                padding: 8px;
                margin-bottom: 10px;
                box-sizing: border-box;
            }

            .inline-form input[type="text"] {
                width: auto;
                min-width: 220px;
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

            .page-subtitle {
                margin-top: -0.5rem;
                margin-bottom: 1.25rem;
                color: #666;
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

            .details-button {
                padding: 6px 10px;
                font-size: 0.9rem;
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

            @media (max-width: 1100px) {
                .details-grid {
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
        </div>

        <div class="tab-content" id="content-dashboard">
            <form method="get" action="/admin" class="inline-form">
                <h2>Filter Activity</h2>
                <input type="text" name="token" value="<?= h($tokenFilter) ?>" placeholder="Filter by token or path">
                <input type="text" name="ip" value="<?= h($ipFilter) ?>" placeholder="Filter by IP">
                <input type="text" name="visitor" value="<?= h($visitorFilter) ?>" placeholder="Filter by visitor hash">
                <label>
                    <input type="checkbox" name="known" value="1" <?= $knownOnly ? 'checked' : '' ?>>
                    Known tokens only
                </label>
                <span class="filter-actions">
                    <button type="submit">Apply Filter</button>
                    <a class="button-link" href="/admin">Clear Filter</a>
                    <a class="button-link" href="<?= h($refreshUrl) ?>">Refresh</a>
                </span>
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

                    <?php if ($knownOnly): ?>
                        <span class="filter-pill">
                            known only
                            <a href="<?= h($buildAdminUrl(['known' => null])) ?>">×</a>
                        </span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if ($tokenFilter !== ''): ?>
                <form method="post" action="/admin/delete-token-clicks" class="inline-form" onsubmit="return confirm('Delete unknown-only clicks for this token/path?');">
                    <h2>Token Cleanup</h2>
                    <input type="hidden" name="token" value="<?= h($tokenFilter) ?>">
                    <input type="hidden" name="mode" value="unknown_only">
                    <button type="submit" class="warning-button">Delete Unknown Token Hits</button>
                </form>

                <form method="post" action="/admin/delete-token-clicks" class="inline-form" onsubmit="return confirm('Delete ALL clicks for this token/path?');">
                    <input type="hidden" name="token" value="<?= h($tokenFilter) ?>">
                    <input type="hidden" name="mode" value="all">
                    <button type="submit" class="danger-button">Delete All Clicks for Token</button>
                </form>
            <?php endif; ?>

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
                        <th>Classification</th>
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
                        $rowIp = (string)($c['ip'] ?? '');
                        $rowVisitor = (string)($c['visitor_hash'] ?? '');
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
                            <td>
                                <span class="<?= h($badgeClass) ?>">
                                    <?= h((string)($c['confidence_label'] ?? '')) ?>
                                    <?= ($c['confidence_score'] ?? null) !== null ? ' (' . h((string)$c['confidence_score']) . ')' : '' ?>
                                </span>
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
                                        <div><span class="mono">Click ID:</span> <?= h((string)($c['id'] ?? '')) ?></div>
                                        <div><span class="mono">IP:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['ip' => $rowIp])) ?>">
                                                <?= h($rowIp) ?>
                                            </a>
                                        </div>
                                        <div><span class="mono">ASN:</span> <?= h((string)($c['ip_asn'] ?? '')) ?></div>
                                        <div><span class="mono">Org:</span> <?= h((string)($c['ip_org'] ?? '')) ?></div>
                                        <div><span class="mono">Country:</span> <?= h((string)($c['ip_country'] ?? '')) ?></div>
                                        <div><span class="mono">Visitor:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['visitor' => $rowVisitor])) ?>">
                                                <?= h($rowVisitor) ?>
                                            </a>
                                        </div>
                                        <div><span class="mono">XFF:</span> <?= h((string)($c['x_forwarded_for'] ?? '')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Scoring</strong>
                                        <div><span class="mono">Classification:</span>
                                            <?= h((string)($c['confidence_label'] ?? '')) ?>
                                            (<?= h((string)($c['confidence_score'] ?? '')) ?>)
                                        </div>
                                        <div><span class="mono">Reason:</span>
                                            <span class="wrap"><?= h((string)($c['confidence_reason'] ?? '')) ?></span>
                                        </div>
                                        <div><span class="mono">First for token:</span> <?= !empty($c['first_for_token']) ? 'Yes' : 'No' ?></div>
                                        <div><span class="mono">Prior events for token:</span> <?= h((string)($c['prior_events_for_token'] ?? '0')) ?></div>
                                    </div>

                                    <div class="detail-box">
                                        <strong>Request</strong>
                                        <div><span class="mono">Token / Path:</span>
                                            <a class="pill-link mono" href="<?= h($buildAdminUrl(['token' => $rowToken])) ?>">
                                                <?= h($rowToken) ?>
                                            </a>
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
                                        <div class="wrap"><?= h((string)($c['user_agent'] ?? '')) ?></div>
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
                        <th>Pixel URL</th>
                        <th>Actions</th>
                    </tr>
                    <?php foreach ($links as $link): ?>
                        <tr>
                            <td><?= (int)$link['id'] ?></td>
                            <td class="mono">
                                <a class="table-link mono-link" href="<?= h($buildAdminUrl(['token' => (string)$link['token']])) ?>">
                                    <?= h((string)$link['token']) ?>
                                </a>
                            </td>
                            <td><?= h((string)($link['description'] ?? '')) ?></td>
                            <td class="wrap"><?= h((string)$link['destination']) ?></td>
                            <td><?= ((int)$link['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td><?= (int)$link['click_count'] ?></td>
                            <td class="mono wrap">
                                <?php if ($baseUrl !== ''): ?>
                                    <?= h(rtrim($baseUrl, '/') . '/pixel/' . $link['token'] . '.gif') ?>
                                <?php endif; ?>
                            </td>
                            <td>
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

        <div class="tab-content" id="content-settings">
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

                <label>
                    <input type="checkbox" name="pixel_enabled" value="1" <?= $pixelEnabled ? 'checked' : '' ?>>
                    Pixel enabled
                </label>

                <label>
                    <input type="checkbox" name="noise_filter_enabled" value="1" <?= $noiseFilterEnabled ? 'checked' : '' ?>>
                    Noise filter enabled
                </label>

                <button type="submit">Save Settings</button>
            </form>

            <form method="post" action="/admin/save-threat-feed-settings">
                <h2>Threat Feed</h2>

                <label>
                    <input type="checkbox" name="threat_feed_enabled" value="1" <?= $threatFeedEnabled ? 'checked' : '' ?>>
                    Enable threat feed
                </label>

                <label for="threat_feed_window_hours">Keep IPs on feed for this many hours</label>
                <input id="threat_feed_window_hours" type="text" name="threat_feed_window_hours" value="<?= h($threatFeedWindowHours) ?>">

                <label for="threat_feed_min_confidence">Minimum confidence to include</label>
                <select id="threat_feed_min_confidence" name="threat_feed_min_confidence">
                    <option value="human" <?= $threatFeedMinConfidence === 'human' ? 'selected' : '' ?>>human</option>
                    <option value="likely-human" <?= $threatFeedMinConfidence === 'likely-human' ? 'selected' : '' ?>>likely-human</option>
                    <option value="suspicious" <?= $threatFeedMinConfidence === 'suspicious' ? 'selected' : '' ?>>suspicious</option>
                    <option value="bot" <?= $threatFeedMinConfidence === 'bot' ? 'selected' : '' ?>>bot</option>
                </select>

                <p class="muted">
                    Feed URL:
                    <span class="mono">
                        <?= h(rtrim($baseUrl !== '' ? $baseUrl : '', '/')) ?><?= $baseUrl !== '' ? '/feed/ips.txt' : '/feed/ips.txt' ?>
                    </span>
                </p>

                <button type="submit">Save Threat Feed Settings</button>
            </form>
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
                        <th>Actions</th>
                    </tr>
                    <?php foreach ($skipPatterns as $pattern): ?>
                        <tr>
                            <td><?= (int)$pattern['id'] ?></td>
                            <td><?= h((string)$pattern['type']) ?></td>
                            <td class="mono"><?= h((string)$pattern['pattern']) ?></td>
                            <td><?= ((int)$pattern['active'] === 1) ? 'Yes' : 'No' ?></td>
                            <td>
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

        document.addEventListener('DOMContentLoaded', function () {
            const saved = localStorage.getItem('activeTab') || 'dashboard';
            showTab(saved);
        });
        </script>
    </body>
    </html>
    <?php
}
