<?php
/**
 * Fuzz target: mtdowling/jmespath.php 2.8.0  (JMESPath expression parser)
 * JMESPath is a query language for JSON, used by AWS SDK to filter/transform
 * API responses. Complex grammar, attacker-controlled expressions in filtering
 * APIs, and history of DoS via deep recursion or expensive operations.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use JmesPath\Env;

$config->setMaxLen(2048);
$config->setAllowedExceptions([\JmesPath\SyntaxErrorException::class, \RuntimeException::class]);

$config->setTarget(function (string $input) {
    // Parse the expression against a minimal data structure
    // to exercise the parser and evaluator
    $data = ['foo' => 'bar', 'items' => [1, 2, 3], 'nested' => ['key' => 'value']];
    Env::search($input, $data);
});
