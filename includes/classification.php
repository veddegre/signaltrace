<?php

declare(strict_types=1);

/**
 * Returns confidence labels at or above the provided minimum threshold.
 * Keeps compatibility with legacy "likely-human" values in existing data.
 */
function confidenceLabelsAtOrAbove(string $minConfidence): array
{
    return match (strtolower($minConfidence)) {
        'bot'                       => ['bot'],
        'uncertain', 'likely-human' => ['uncertain', 'likely-human', 'suspicious', 'bot'],
        'human'                     => ['human', 'uncertain', 'likely-human', 'suspicious', 'bot'],
        default                     => ['suspicious', 'bot'],
    };
}

/**
 * Returns true when token webhook dispatch should be allowed for a known link.
 */
function isTokenWebhookEnabledForLink(
    bool $includeInTokenWebhook,
    bool $campaignWebhookEnabled,
    bool $campaignActive
): bool {
    return $includeInTokenWebhook || ($campaignWebhookEnabled && $campaignActive);
}
