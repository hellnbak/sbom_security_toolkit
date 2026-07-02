<?php
/**
 * Fuzz target: ramsey/uuid 4.7.6  (UUID parsing and validation)
 * UUID parsers are common in authentication tokens, session IDs, and API keys.
 * Multiple format variants (RFC 4122, v1-v8, DCE, GUID), hex validation, and
 * potential for type confusion or injection bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\Exception\InvalidUuidStringException;

$config->setMaxLen(256);
$config->setAllowedExceptions([InvalidUuidStringException::class, \InvalidArgumentException::class]);

$config->setTarget(function (string $input) {
    // Test both fromString (strict) and isValid (lenient)
    try {
        Uuid::fromString($input);
    } catch (InvalidUuidStringException $e) {
        // Expected for invalid input
    }
    Uuid::isValid($input);
});
