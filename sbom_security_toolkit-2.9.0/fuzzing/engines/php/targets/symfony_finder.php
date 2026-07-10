<?php
/**
 * Fuzz target: symfony/finder 7.2.0  (File path glob and pattern matching)
 * Finder parses glob patterns, regular expressions, and file path filters.
 * Path traversal, ReDoS in pattern matching, and symlink-following bugs are
 * the primary concerns. We fuzz pattern parsing without touching the filesystem.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\Glob;
use Symfony\Component\Finder\Exception\InvalidArgumentException;

$config->setMaxLen(1024);
$config->setAllowedExceptions([
    InvalidArgumentException::class,
    \InvalidArgumentException::class,
]);

$config->setTarget(function (string $input) {
    // Test glob-to-regex conversion (the core attack surface)
    try {
        $regex = Glob::toRegex($input);

        // Test the regex against a safe string to trigger any ReDoS
        @preg_match($regex, 'test/path/file.txt', $matches, 0);
    } catch (InvalidArgumentException $e) {
        // Expected
    }

    // Test pattern methods that parse without filesystem access
    try {
        $finder = new Finder();
        $finder->name($input);
        $finder->notName($input);
        $finder->path($input);
        $finder->notPath($input);
    } catch (InvalidArgumentException | \InvalidArgumentException $e) {
        // Expected
    }
});
