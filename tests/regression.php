<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/classification.php';
require_once __DIR__ . '/integration_feed_overrides.php';
require_once __DIR__ . '/scheduler_regression.php';

function assertSameStrict(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            $message
            . PHP_EOL . 'Expected: ' . var_export($expected, true)
            . PHP_EOL . 'Actual:   ' . var_export($actual, true)
        );
    }
}

function runRegressionTests(): void
{
    // Threshold expansion tests (confidence labels at-or-above).
    assertSameStrict(
        ['bot'],
        confidenceLabelsAtOrAbove('bot'),
        'bot threshold should include only bot'
    );

    assertSameStrict(
        ['suspicious', 'bot'],
        confidenceLabelsAtOrAbove('suspicious'),
        'suspicious threshold should include suspicious+bot'
    );

    assertSameStrict(
        ['uncertain', 'likely-human', 'suspicious', 'bot'],
        confidenceLabelsAtOrAbove('uncertain'),
        'uncertain threshold should include uncertain and legacy likely-human'
    );

    assertSameStrict(
        ['uncertain', 'likely-human', 'suspicious', 'bot'],
        confidenceLabelsAtOrAbove('likely-human'),
        'legacy likely-human threshold should map to uncertain-tier behavior'
    );

    assertSameStrict(
        ['human', 'uncertain', 'likely-human', 'suspicious', 'bot'],
        confidenceLabelsAtOrAbove('human'),
        'human threshold should include all known labels'
    );

    // Token webhook eligibility tests.
    assertSameStrict(
        true,
        isTokenWebhookEnabledForLink(true, false, false),
        'per-token opt-in should always allow token webhook dispatch'
    );

    assertSameStrict(
        true,
        isTokenWebhookEnabledForLink(false, true, true),
        'campaign fallback should allow dispatch when campaign is enabled and active'
    );

    assertSameStrict(
        false,
        isTokenWebhookEnabledForLink(false, true, false),
        'disabled campaign should not allow fallback dispatch'
    );

    assertSameStrict(
        false,
        isTokenWebhookEnabledForLink(false, false, true),
        'inactive fallback setting should not allow dispatch'
    );
}

runRegressionTests();
runFeedOverrideIntegrationTests();
runSchedulerRegressionTests();
echo "Regression tests passed.\n";
