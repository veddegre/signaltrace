<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/scheduler.php';

function runSchedulerRegressionTests(): void
{
    $now = 1_700_000_000;

    if (hasIntervalElapsed($now - 60, 300, $now) !== false) {
        throw new RuntimeException('Interval should not be elapsed before threshold.');
    }
    if (hasIntervalElapsed($now - 300, 300, $now) !== true) {
        throw new RuntimeException('Interval should be elapsed at threshold.');
    }

    if (shouldRunSqliteMaintenanceWindow(false, 0, 360, $now) !== false) {
        throw new RuntimeException('Maintenance must not run when disabled.');
    }
    if (shouldRunSqliteMaintenanceWindow(true, $now - (5 * 60), 15, $now) !== false) {
        throw new RuntimeException('Maintenance must not run before min interval.');
    }
    if (shouldRunSqliteMaintenanceWindow(true, $now - (15 * 60), 15, $now) !== true) {
        throw new RuntimeException('Maintenance should run once interval elapsed.');
    }

    if (shouldRunSqliteVacuumWindow(false, 0, 24, $now) !== false) {
        throw new RuntimeException('VACUUM must not run when disabled.');
    }
    if (shouldRunSqliteVacuumWindow(true, $now - (5 * 3600), 6, $now) !== false) {
        throw new RuntimeException('VACUUM must honor minimum interval.');
    }
    if (shouldRunSqliteVacuumWindow(true, $now - (6 * 3600), 6, $now) !== true) {
        throw new RuntimeException('VACUUM should run at interval boundary.');
    }
}
