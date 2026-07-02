<?php
/**
 * Fuzz target: symfony/http-foundation 7.2.0  (HTTP request/response parsing)
 * Parses headers, cookies, query strings, and uploaded files. CRLF injection,
 * header parsing bugs, and cookie parsing edge cases are high-impact targets.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\HeaderBag;

$config->setMaxLen(2048);

$config->setTarget(function (string $input) {
    // Fuzz header parsing
    $headerBag = new HeaderBag();
    $lines = explode("\n", $input);
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) {
            [$key, $value] = explode(':', $line, 2);
            try {
                $headerBag->set(trim($key), trim($value));
            } catch (\InvalidArgumentException $e) {
                // Expected for invalid header names
            }
        }
    }

    // Fuzz query string parsing
    $request = Request::create('http://example.com/?' . $input);
    $request->query->all();

    // Fuzz cookie parsing
    $_COOKIE = [];
    parse_str($input, $_COOKIE);
    $request = new Request([], [], [], $_COOKIE);
    $request->cookies->all();
});
