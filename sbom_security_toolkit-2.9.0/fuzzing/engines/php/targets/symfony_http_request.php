<?php
/**
 * Fuzz target: symfony/http-foundation 7.2.0  (HTTP request parsing)
 * Parses raw HTTP request strings into Request objects. Header parsing,
 * cookie parsing, and content-type handling have historically been sources
 * of header injection, CRLF injection, and parser bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;

$config->setMaxLen(8192);

$config->setTarget(function (string $input) {
    // Parse input as raw HTTP headers + body
    $parts = explode("\r\n\r\n", $input, 2);
    $headers = $parts[0] ?? '';
    $body = $parts[1] ?? '';

    // Parse header lines
    $headerLines = explode("\r\n", $headers);
    $parsedHeaders = [];
    $method = 'GET';
    $uri = '/';

    foreach ($headerLines as $i => $line) {
        if ($i === 0 && preg_match('/^(\w+)\s+(\S+)/', $line, $m)) {
            $method = $m[1];
            $uri = $m[2];
        } elseif (strpos($line, ':') !== false) {
            [$key, $value] = explode(':', $line, 2);
            $parsedHeaders[trim($key)] = trim($value);
        }
    }

    Request::create($uri, $method, [], [], [], $parsedHeaders, $body);
});
