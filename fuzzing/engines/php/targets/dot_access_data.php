<?php
/**
 * Fuzz target: dflydev/dot-access-data 3.0.3  (Nested array access parser)
 * Parses dot-notation paths like "foo.bar.baz" to access nested arrays.
 * If attacker-controlled keys reach get() (API parameters, config lookups),
 * bugs in path parsing can cause unexpected traversal or crashes.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Dflydev\DotAccessData\Data;

$testData = [
    'a' => [
        'b' => ['c' => 'value1', 'd' => 'value2'],
        'e' => 'value3',
    ],
    'f' => ['g' => ['h' => ['i' => 'deep']]],
    'x.y' => 'literal-dot-key',
];

$data = new Data($testData);

$config->setMaxLen(256);

$config->setTarget(function (string $input) use ($data) {
    // get() returns null for missing keys, doesn't throw
    $data->get($input);
});
