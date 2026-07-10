<?php
/**
 * Fuzz target: symfony/console 7.2.1  (CLI argument parsing)
 * Console input parsing handles user-provided arguments/options. Shell
 * injection and argument parsing bugs are common attack vectors.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Exception\RuntimeException as ConsoleRuntimeException;

$config->setMaxLen(1024);
$config->setAllowedExceptions([
    ConsoleRuntimeException::class,
    \InvalidArgumentException::class,
]);

$config->setTarget(function (string $input) {
    // Parse as command-line input
    new StringInput($input);
});
