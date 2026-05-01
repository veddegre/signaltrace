<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/classification.php';

function runFeedOverrideIntegrationTests(): void
{
    if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
        // Keep regression runner portable in environments without pdo_sqlite.
        return;
    }

    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $pdo->exec("
        CREATE TABLE links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exclude_from_feed INTEGER NOT NULL DEFAULT 0,
            force_include_in_feed INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            link_id INTEGER,
            event_type TEXT,
            confidence_label TEXT,
            confidence_score INTEGER,
            clicked_at_unix_ms INTEGER
        );
        CREATE TABLE asn_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            exclude_from_feed INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE ip_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            mode TEXT
        );
    ");

    $nowMs = (int) round(microtime(true) * 1000);
    $windowHours = 24;
    $minHits = 1;
    $allowedLabels = confidenceLabelsAtOrAbove('suspicious');
    $placeholders = implode(',', array_fill(0, count($allowedLabels), '?'));

    $sql = "
        SELECT c.ip, COUNT(*) AS hit_count
        FROM clicks c
        LEFT JOIN asn_rules ar
            ON ar.asn = ''
           AND ar.active = 1
           AND ar.exclude_from_feed = 1
        LEFT JOIN links lk
            ON lk.id = c.link_id
        LEFT JOIN ip_overrides io
            ON io.ip = c.ip
           AND io.active = 1
           AND io.mode IN ('allow', 'feed_exclude')
        WHERE c.ip IS NOT NULL
          AND c.ip <> ''
          AND c.event_type = 'click'
          AND c.clicked_at_unix_ms >= (strftime('%s', 'now') - ? * 3600) * 1000
          AND c.confidence_label IS NOT NULL
          AND c.confidence_label <> ''
          AND c.confidence_score IS NOT NULL
          AND ar.id IS NULL
          AND io.id IS NULL
          AND (
              (
                  (lk.id IS NULL OR lk.exclude_from_feed = 0)
                  AND (lk.id IS NULL OR lk.force_include_in_feed = 0)
                  AND c.confidence_label IN ($placeholders)
              )
              OR
              (lk.force_include_in_feed = 1)
          )
        GROUP BY c.ip
        HAVING COUNT(*) >= {$minHits}

        UNION

        SELECT ip, 0 AS hit_count
        FROM ip_overrides
        WHERE active = 1
          AND mode IN ('block', 'feed_include')
          AND ip IS NOT NULL
          AND ip <> ''
        ORDER BY ip ASC
    ";

    // Seed links and clicks
    $pdo->exec("INSERT INTO links (id, exclude_from_feed, force_include_in_feed) VALUES (1,0,0)");
    $stmt = $pdo->prepare("
        INSERT INTO clicks (ip, link_id, event_type, confidence_label, confidence_score, clicked_at_unix_ms)
        VALUES (:ip, 1, 'click', :label, :score, :ts)
    ");
    $stmt->execute([':ip' => '203.0.113.10', ':label' => 'bot', ':score' => 5, ':ts' => $nowMs]); // baseline include
    $stmt->execute([':ip' => '203.0.113.11', ':label' => 'bot', ':score' => 5, ':ts' => $nowMs]); // will be feed_exclude
    $stmt->execute([':ip' => '203.0.113.12', ':label' => 'human', ':score' => 95, ':ts' => $nowMs]); // below threshold unless forced

    // Explicit include and exclude overrides
    $pdo->exec("INSERT INTO ip_overrides (ip, active, mode) VALUES ('203.0.113.11', 1, 'feed_exclude')");
    $pdo->exec("INSERT INTO ip_overrides (ip, active, mode) VALUES ('203.0.113.13', 1, 'feed_include')");

    $q = $pdo->prepare($sql);
    $q->execute(array_merge([$windowHours], $allowedLabels));
    $rows = $q->fetchAll();
    $ips = array_map(static fn(array $r): string => (string) $r['ip'], $rows);

    if (!in_array('203.0.113.10', $ips, true)) {
        throw new RuntimeException('Expected baseline bot IP to be included in threat feed.');
    }
    if (in_array('203.0.113.11', $ips, true)) {
        throw new RuntimeException('Expected feed_exclude IP to be excluded from threat feed.');
    }
    if (!in_array('203.0.113.13', $ips, true)) {
        throw new RuntimeException('Expected feed_include IP to be present in threat feed.');
    }
    if (in_array('203.0.113.12', $ips, true)) {
        throw new RuntimeException('Expected below-threshold human IP to be excluded from threat feed.');
    }
}
