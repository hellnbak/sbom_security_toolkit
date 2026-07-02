<?php
/**
 * Fuzz target: guzzlehttp/psr7 2.7.0 — raw HTTP message parse + re-serialize.
 *
 * Added after discovering (via Composer's security-advisory block, when
 * building this harness) that guzzlehttp/psr7 2.7.0 carries three active
 * CVEs, ALL of them in the raw-message parse/serialize surface:
 *   - CVE-2026-48998  Host Confusion via Authority Reinterpretation
 *   - CVE-2026-49214  CRLF Injection via URI Host Component
 *   - CVE-2026-55766  CRLF Injection in HTTP Start-Line Serialization
 * That is Message::parseRequest() / Message::toString() — a different API
 * surface than plain Uri parsing (see psr7_uri.php), which those CVEs do
 * NOT touch. This target exercises the surface that's actually implicated.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Psr7\Message;

$config->setMaxLen(2048);
$config->setAllowedExceptions([\InvalidArgumentException::class, \UnexpectedValueException::class]);

$config->setTarget(function (string $input) {
    // Parse fuzzer-controlled bytes as a raw HTTP request, then serialize it
    // straight back out — the exact parse-then-reserialize round trip the
    // three CVEs above are about (proxies, webhook relays, custom
    // transports that don't go through Guzzle's own client).
    $request = Message::parseRequest($input);
    Message::toString($request);
});
