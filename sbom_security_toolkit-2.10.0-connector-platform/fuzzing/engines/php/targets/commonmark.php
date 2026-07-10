<?php
/**
 * Fuzz target: league/commonmark 2.6.0  (Markdown -> HTML)
 * Markdown parsers are the textbook fuzzing target: complex grammar, lots of
 * edge cases, attacker-controlled input in many apps (comments, profiles).
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use League\CommonMark\CommonMarkConverter;
use League\CommonMark\Exception\CommonMarkException;

$converter = new CommonMarkConverter([
    'html_input'        => 'allow',
    'allow_unsafe_links' => true,
    // Bound nesting so we surface real bugs instead of the expected
    // "max nesting exceeded" guard on pathological input.
    'max_nesting_level' => 50,
]);

$config->setMaxLen(2048);
// CommonMarkException is the library's declared failure type. Anything else
// (a raw TypeError, an unexpected exception, a hang) is treated as a crash.
$config->setAllowedExceptions([CommonMarkException::class]);

$config->setTarget(function (string $input) use ($converter) {
    $converter->convert($input);
});
