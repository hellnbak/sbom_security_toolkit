<?php
/**
 * Fuzz target: guzzlehttp/guzzle 7.9.2  (HTTP client request construction)
 * Guzzle builds requests from arrays/strings with complex URI/header merging.
 * Known CVEs in guzzle/psr7 dependency for header parsing. High attacker reach.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

// Mock handler prevents actual network calls
$mock = new MockHandler([new Response(200)]);
$stack = HandlerStack::create($mock);
$client = new Client(['handler' => $stack]);

$config->setMaxLen(4096);
$config->setAllowedExceptions([
    GuzzleException::class,
    \InvalidArgumentException::class,
]);

$config->setTarget(function (string $input) use ($client) {
    // Parse input as JSON array of request options
    $opts = @json_decode($input, true);
    if (!is_array($opts)) {
        $opts = ['body' => $input]; // Fallback to body fuzzing
    }

    try {
        $client->request('POST', 'http://test.local/fuzz', $opts);
    } catch (\GuzzleHttp\Exception\ConnectException $e) {
        // Expected for invalid URIs
    }
});
