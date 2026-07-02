<?php
/**
 * Fuzz target: league/uri 7.5.1  (RFC 3986 URI parsing + round-trip)
 * A second, independent URI parser — differential bugs vs. PSR-7 are
 * interesting in their own right (one accepts what the other rejects).
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use League\Uri\Uri;
use League\Uri\Exceptions\SyntaxError;

$config->setMaxLen(1024);
$config->setAllowedExceptions([SyntaxError::class, \InvalidArgumentException::class]);

$config->setTarget(function (string $input) {
    $uri = Uri::new($input);
    $uri->getScheme();
    $uri->getHost();
    $uri->getPath();
    $uri->getQuery();
    $uri->toString();
});
