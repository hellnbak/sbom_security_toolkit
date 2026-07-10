<?php
/**
 * Fuzz target: guzzlehttp/guzzle 7.9.2  (HTTP message parsing)
 * Guzzle parses raw HTTP responses and requests. Known CVEs (2026-48998, 49214,
 * 55766) in the psr7 parse layer; we fuzz both the Message::parseRequest and
 * response parsing paths. HTTP parsers are notorious for smuggling bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Exception\RequestException;

$config->setMaxLen(8192);
$config->setAllowedExceptions([
    RequestException::class,
    \InvalidArgumentException::class,
    \UnexpectedValueException::class,
]);

$config->setTarget(function (string $input) {
    try {
        Message::parseRequest($input);
    } catch (\Throwable $e) {
        // Also try as a response
        Message::parseResponse($input);
    }
});
