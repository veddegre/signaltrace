<?php
declare(strict_types=1);

function requireAdminAuth(): void
{
    if (!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        sendAuthRequest();
    }

    $username = (string) $_SERVER['PHP_AUTH_USER'];
    $password = (string) $_SERVER['PHP_AUTH_PW'];

    if ($username !== ADMIN_USERNAME) {
        sendAuthRequest();
    }

    if (!password_verify($password, ADMIN_PASSWORD_HASH)) {
        sendAuthRequest();
    }
}

function sendAuthRequest(): void
{
    header('WWW-Authenticate: Basic realm="SignalTrace Admin"');
    header('HTTP/1.0 401 Unauthorized');
    exit('Unauthorized');
}
