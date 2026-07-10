<?php
/**
 * Fuzz target: monolog/monolog 3.8.1  (Log message formatting/interpolation)
 * Logs often contain user-controlled input. Monolog's placeholder interpolation
 * and message formatting have had injection bugs in the past.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\NullHandler;

$logger = new Logger('fuzz');
$logger->pushHandler(new NullHandler());

$config->setMaxLen(2048);
$config->setAllowedExceptions([\InvalidArgumentException::class, \RuntimeException::class]);

$config->setTarget(function (string $input) use ($logger) {
    // Parse as JSON to get message + context
    $data = @json_decode($input, true);
    if (!is_array($data)) {
        $data = ['message' => $input, 'context' => []];
    }

    $message = $data['message'] ?? '';
    $context = is_array($data['context'] ?? null) ? $data['context'] : [];

    $logger->info($message, $context);
});
