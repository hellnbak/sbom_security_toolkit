<?php
/**
 * Fuzz target: guzzlehttp/psr7 2.7.0  (URI parsing + round-trip)
 * URI parsing feeds routing, SSRF defenses, redirects — high-value to fuzz.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Psr7\Uri;

$config->setMaxLen(1024);
// Malformed URIs raise InvalidArgumentException (MalformedUriException extends it).
$config->setAllowedExceptions([\InvalidArgumentException::class]);

$config->setTarget(function (string $input) {
    $uri = new Uri($input);
    // Exercise the accessors and round-trip through __toString — a classic
    // source of parse/serialize asymmetry bugs.
    $uri->getScheme();
    $uri->getAuthority();
    $uri->getHost();
    $uri->getPath();
    $uri->getQuery();
    (string) $uri;
});
