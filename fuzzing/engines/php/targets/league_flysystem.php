<?php
/**
 * Fuzz target: league/flysystem 3.29.1  (path normalization / traversal defense)
 * Flysystem's PathNormalizer and PathTraversalDetector sit between untrusted
 * path input and filesystem/S3 operations. Path traversal bugs are critical;
 * the normalizer is a prime fuzzing target.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use League\Flysystem\PathNormalizer;
use League\Flysystem\WhitespacePathNormalizer;

$normalizer = new WhitespacePathNormalizer();

$config->setMaxLen(1024);

$config->setTarget(function (string $input) use ($normalizer) {
    $normalizer->normalizePath($input);
});
