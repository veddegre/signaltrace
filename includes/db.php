<?php

/**
 * ============================================================
 * ADD THESE FUNCTIONS TO THE BOTTOM OF includes/db.php
 * ============================================================
 *
 * These provide server-side aggregated endpoints for Grafana.
 * They share the same filter logic as exportClicks() so the
 * Grafana token can be scoped identically to the export.
 */

/**
 * Build the shared WHERE clause and params used by all aggregation
 * queries. Mirrors the logic in exportClicks() exactly.
 *
 * Returns [$whereSql, $params] where $whereSql begins with " AND "
 * (safe to append after "WHERE 1=1").
 */
function buildExportWhere(PDO $pdo, bool $manualFilters, ?string $dateFrom, ?string $dateTo): array
{
    $where  = '';
    $params = [];

    if ($manualFilters) {
        // Manual date filters from the admin dashboard
        if ($dateFrom !== null && $dateFrom !== '') {
            $where .= " AND substr(c.clicked_at, 1, 10) >= :dateFrom ";
            $params[':dateFrom'] = $dateFrom;
        }
        if ($dateTo !== null && $dateTo !== '') {
            $where .= " AND substr(c.clicked_at, 1, 10) <= :dateTo ";
            $params[':dateTo'] = $dateTo;
        }
    } else {
        // Use configured export window + confidence threshold
        $minConfidence = strtolower((string) getSetting($pdo, 'export_min_confidence', 'suspicious'));
        $windowHours   = max(1, (int) getSetting($pdo, 'export_window_hours', '168'));
        $minScore      = max(0, min(100, (int) getSetting($pdo, 'export_min_score', '0')));

        $allowedLabels = match ($minConfidence) {
            'bot'          => ['bot'],
            'likely-human' => ['likely-human', 'suspicious', 'bot'],
            'human'        => ['human', 'likely-human', 'suspicious', 'bot'],
            default        => ['suspicious', 'bot'],
        };

        $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));

        $where .= " AND c.clicked_at >= datetime('now', ?) ";
        $where .= " AND c.confidence_label IN ($placeholders) ";
        $where .= " AND (c.confidence_score IS NULL OR c.confidence_score >= ?) ";

        $params = array_merge(
            ['-' . $windowHours . ' hours'],
            $allowedLabels,
            [$minScore],
        );
    }

    return [$where, $params];
}

/**
 * Summary stats for the Grafana stat panels.
 * Returns total, bot_count, suspicious_count, likely_human_count,
 * human_count, unique_ips, avg_confidence_score.
 */
function exportStats(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);

    $sql = "
        SELECT
            COUNT(*)                                                              AS total,
            SUM(CASE WHEN c.confidence_label = 'bot'          THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN c.confidence_label = 'suspicious'   THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN c.confidence_label = 'likely-human' THEN 1 ELSE 0 END) AS likely_human_count,
            SUM(CASE WHEN c.confidence_label = 'human'        THEN 1 ELSE 0 END) AS human_count,
            COUNT(DISTINCT c.ip)                                                  AS unique_ips,
            ROUND(AVG(c.confidence_score), 1)                                     AS avg_confidence_score
        FROM clicks c
        WHERE 1=1
        $where
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();

    // Cast everything to the right types so JSON encodes cleanly
    return [
        'total'                => (int)   ($row['total']                ?? 0),
        'bot_count'            => (int)   ($row['bot_count']            ?? 0),
        'suspicious_count'     => (int)   ($row['suspicious_count']     ?? 0),
        'likely_human_count'   => (int)   ($row['likely_human_count']   ?? 0),
        'human_count'          => (int)   ($row['human_count']          ?? 0),
        'unique_ips'           => (int)   ($row['unique_ips']           ?? 0),
        'avg_confidence_score' => (float) ($row['avg_confidence_score'] ?? 0.0),
    ];
}

/**
 * Top IPs by hit count, pre-aggregated for Grafana bar chart.
 */
function exportByIp(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 20,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);
    $params[] = $limit;

    $sql = "
        SELECT
            c.ip,
            MAX(c.ip_org)     AS ip_org,
            MAX(c.ip_country) AS ip_country,
            COUNT(*)          AS hits
        FROM clicks c
        WHERE c.ip IS NOT NULL
          AND c.ip <> ''
          $where
        GROUP BY c.ip
        ORDER BY hits DESC
        LIMIT ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Top countries by hit count, pre-aggregated for Grafana bar chart.
 */
function exportByCountry(
    PDO $pdo,
    bool $manualFilters = false,
    ?string $dateFrom = null,
    ?string $dateTo = null,
    int $limit = 20,
): array {
    [$where, $params] = buildExportWhere($pdo, $manualFilters, $dateFrom, $dateTo);
    $params[] = $limit;

    $sql = "
        SELECT
            c.ip_country      AS country,
            COUNT(*)          AS hits
        FROM clicks c
        WHERE c.ip_country IS NOT NULL
          AND c.ip_country <> ''
          $where
        GROUP BY c.ip_country
        ORDER BY hits DESC
        LIMIT ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}
