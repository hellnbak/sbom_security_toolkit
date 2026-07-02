<?php
/**
 * Fuzz target: league/flysystem 3.29.1  (Path parsing/normalization)
 * Flysystem normalizes file paths from user input. Path traversal bugs
 * and normalization bypasses are high-impact security issues.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use League\Flysystem\PathNormalizer;
use League\Flysystem\WhitespacePathNormalizer;
use League\Flysystem\InvalidPathException;

$normalizer = new WhitespacePathNormalizer();

$config->setMaxLen(512);
$config->setAllowedExceptions([
    InvalidPathException::class,
    \InvalidArgumentException::class,
]);

$config->setTarget(function (string $input) use ($normalizer) {
    $normalizer->normalizePath($input);
});
