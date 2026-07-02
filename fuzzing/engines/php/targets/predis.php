<?php
/**
 * Fuzz target: predis/predis 2.3.0  (Redis protocol parser)
 * Predis parses RESP (REdis Serialization Protocol) messages from untrusted
 * Redis servers or Redis-compatible endpoints. Protocol desync, integer overflow,
 * and type confusion bugs are classic attack vectors in binary protocol parsers.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Predis\Connection\StreamConnection;
use Predis\Response\ResponseInterface;
use Predis\Protocol\Text\ProtocolProcessor;

$config->setMaxLen(8192);
$config->setAllowedExceptions([
    \Predis\Response\ServerException::class,
    \Predis\Protocol\ProtocolException::class,
    \InvalidArgumentException::class,
]);

$config->setTarget(function (string $input) {
    $processor = new ProtocolProcessor();

    // Create a mock stream with the fuzzed input
    $stream = fopen('php://memory', 'r+');
    fwrite($stream, $input);
    rewind($stream);

    try {
        // Parse RESP protocol
        $reader = new \Predis\Protocol\Text\ResponseReader();
        $connection = $reader->read($stream);
    } catch (\Predis\Response\ServerException $e) {
        // Expected for invalid protocol messages
    } finally {
        fclose($stream);
    }
});
