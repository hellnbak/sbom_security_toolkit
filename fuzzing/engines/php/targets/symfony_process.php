<?php
/**
 * Fuzz target: symfony/process 7.2.0  (Command-line parsing + escaping)
 * Process handles shell command construction and argument escaping. Command
 * injection via quote/escape bypass is the primary concern. We fuzz both the
 * command string constructor and the argument array path.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\InvalidArgumentException;
use Symfony\Component\Process\Exception\LogicException;

$config->setMaxLen(2048);
$config->setAllowedExceptions([
    InvalidArgumentException::class,
    LogicException::class,
    \RuntimeException::class,
]);

$config->setTarget(function (string $input) {
    // Test command string parsing (DO NOT run - just parse)
    try {
        $process = Process::fromShellCommandline($input);
        $process->getCommandLine();
    } catch (InvalidArgumentException $e) {
        // Expected
    }

    // Test argument array handling with fuzzed parts
    $parts = explode("\0", $input);
    if (count($parts) >= 2) {
        try {
            $process = new Process($parts);
            $process->getCommandLine();
        } catch (InvalidArgumentException | LogicException $e) {
            // Expected
        }
    }
});
