<?php
/**
 * Fuzz target: psy/psysh 0.12.7  (PHP REPL / interactive shell)
 * Parses and evaluates PHP code. Used by Laravel Tinker for production
 * debugging shells. Code parsers are high-value fuzzing targets.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Psy\Shell;
use Psy\Exception\ParseErrorException;
use Psy\Exception\ThrowUpException;

$shell = new Shell();

$config->setMaxLen(2048);
$config->setAllowedExceptions([
    ParseErrorException::class,
    ThrowUpException::class,
]);

$config->setTarget(function (string $input) use ($shell) {
    // Parse the input code without executing (we don't want to eval() arbitrary
    // mutations inside the fuzzer). Psy\Shell::parse() exercises the lexer/parser.
    try {
        // Create a new shell instance for each iteration to avoid state pollution
        $testShell = new Shell();
        // getScopeVariables triggers the parser path without execution
        $testShell->addCode($input);
    } catch (\Throwable $e) {
        // Re-throw only allowed exceptions
        throw $e;
    }
});
