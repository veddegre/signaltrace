<?php

declare(strict_types=1);

function hasIntervalElapsed(int $lastRunTs, int $intervalSecs, int $nowTs): bool
{
    $last = max(0, $lastRunTs);
    $interval = max(1, $intervalSecs);
    return ($nowTs - $last) >= $interval;
}

function shouldRunSqliteMaintenanceWindow(bool $enabled, int $lastRunTs, int $intervalMinutes, int $nowTs): bool
{
    if (!$enabled) {
        return false;
    }
    $interval = max(15, min(10080, $intervalMinutes));
    return hasIntervalElapsed($lastRunTs, $interval * 60, $nowTs);
}

function shouldRunSqliteVacuumWindow(bool $enabled, int $lastRunTs, int $intervalHours, int $nowTs): bool
{
    if (!$enabled) {
        return false;
    }
    $interval = max(6, min(720, $intervalHours));
    return hasIntervalElapsed($lastRunTs, $interval * 3600, $nowTs);
}
