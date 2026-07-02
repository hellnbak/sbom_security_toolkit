<?php
/**
 * Fuzz target: laravel/serializable-closure 2.0.0  (PHP closure serialization)
 * SerializableClosure converts closures to/from serialized form. Deserialization
 * of untrusted data is a critical attack surface: object injection, code execution,
 * and property-oriented programming exploits are all in scope.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Laravel\SerializableClosure\SerializableClosure;
use Laravel\SerializableClosure\Exceptions\InvalidSignatureException;
use Laravel\SerializableClosure\Exceptions\PhpVersionNotSupportedException;

$config->setMaxLen(16384);
$config->setAllowedExceptions([
    InvalidSignatureException::class,
    PhpVersionNotSupportedException::class,
    \ErrorException::class,
    \UnexpectedValueException::class,
]);

$config->setTarget(function (string $input) {
    // Attempt to unserialize fuzzed closure data
    try {
        $unserialized = unserialize($input);
        if ($unserialized instanceof SerializableClosure) {
            // Trigger the __invoke path without actually executing
            $unserialized->getClosure();
        }
    } catch (\Throwable $e) {
        // Catch broad exceptions during unserialize
        if (!in_array(get_class($e), [
            InvalidSignatureException::class,
            PhpVersionNotSupportedException::class,
            \ErrorException::class,
            \UnexpectedValueException::class,
        ])) {
            throw $e;
        }
    }
});
