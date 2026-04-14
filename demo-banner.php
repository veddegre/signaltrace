<?php
/**
 * SignalTrace Demo Banner
 *
 * Included automatically when DEMO_MODE is set to true in config.local.php.
 * Displays a sticky banner indicating this is a live demo instance.
 *
 * If data/.last_reset exists (written by the demo reset cron job), a live
 * countdown to the next reset is shown. If the file does not exist the
 * banner degrades gracefully and shows static text instead.
 *
 * This file is safe to include in the repository — it is inert unless
 * DEMO_MODE is explicitly enabled in config.local.php.
 */

define('DEMO_RESET_INTERVAL', 3600);
define('DEMO_TIMESTAMP_FILE', __DIR__ . '/../data/.last_reset');

function demo_get_seconds_until_reset(): ?int {
    if (!file_exists(DEMO_TIMESTAMP_FILE)) {
        return null;
    }
    $last = (int) trim(file_get_contents(DEMO_TIMESTAMP_FILE));
    $remaining = DEMO_RESET_INTERVAL - (time() - $last);
    return max(0, $remaining);
}

$seconds_remaining = demo_get_seconds_until_reset();
$show_countdown    = $seconds_remaining !== null;

if ($show_countdown) {
    $minutes = floor($seconds_remaining / 60);
    $secs    = $seconds_remaining % 60;
}
?>
<style>
.demo-banner {
    position: sticky;
    top: 0;
    z-index: 200;
    background: #1a0a00;
    border-bottom: 2px solid #f59e0b;
    padding: 0.6rem 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
    font-family: 'IBM Plex Sans', system-ui, sans-serif;
    font-size: 0.8125rem;
}
.demo-banner-left {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}
.demo-badge {
    background: #f59e0b;
    color: #000;
    font-weight: 700;
    font-size: 0.6875rem;
    letter-spacing: 0.08em;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    white-space: nowrap;
}
.demo-text {
    color: #fbbf24;
}
.demo-countdown {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.875rem;
    font-weight: 600;
    color: #f59e0b;
    white-space: nowrap;
    min-width: 5ch;
    text-align: right;
}
.demo-countdown.urgent {
    color: #ef4444;
    animation: demo-pulse 1s infinite;
}
@keyframes demo-pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.5; }
}
@media (max-width: 600px) {
    .demo-banner { flex-direction: column; align-items: flex-start; }
}
</style>

<div class="demo-banner">
    <div class="demo-banner-left">
        <span class="demo-badge">Live Demo</span>
        <span class="demo-text">
            Real traffic &middot; Real bot scoring
            <?php if ($show_countdown): ?>
                &middot; Resets every 60 minutes
            <?php else: ?>
                &middot; Sample data
            <?php endif; ?>
        </span>
    </div>
    <div style="display:flex;align-items:center;gap:1.25rem;">
        <a href="https://www.trysignaltrace.com/#what-to-try"
           target="_blank"
           rel="noopener"
           style="font-size:0.8125rem;color:#fbbf24;text-decoration:none;white-space:nowrap;font-family:'IBM Plex Sans',system-ui,sans-serif;">
            What to try? →
        </a>
        <?php if ($show_countdown): ?>
            <span class="demo-countdown <?= $seconds_remaining < 120 ? 'urgent' : '' ?>"
                  id="demo-countdown"
                  data-seconds="<?= $seconds_remaining ?>">
                <?= sprintf('%02d:%02d', $minutes, $secs) ?>
            </span>
        <?php endif; ?>
    </div>
</div>

<?php if ($show_countdown): ?>
<script>
(function () {
    const el = document.getElementById('demo-countdown');
    if (!el) return;
    let s = parseInt(el.dataset.seconds, 10);
    function fmt(n) {
        return String(Math.floor(n / 60)).padStart(2, '0') + ':' + String(n % 60).padStart(2, '0');
    }
    const timer = setInterval(function () {
        s--;
        if (s <= 0) {
            el.textContent = '00:00';
            clearInterval(timer);
            setTimeout(function () { location.reload(); }, 2000);
            return;
        }
        el.textContent = fmt(s);
        if (s < 120) el.classList.add('urgent');
    }, 1000);
})();
</script>
<?php endif; ?>
