<?php
/**
 * Fuzz target: nesbot/carbon 3.8.2  (Date/time parsing)
 * Carbon parses free-form date strings. Date parsers have a history of
 * ReDoS, type confusion, and locale-handling bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Carbon\Carbon;
use Carbon\Exceptions\InvalidFormatException;

$config->setMaxLen(512);
$config->setAllowedExceptions([
    InvalidFormatException::class,
    \InvalidArgumentException::class,
    \Exception::class,
]);

$config->setTarget(function (string $input) {
    Carbon::parse($input);
    Carbon::createFromFormat('Y-m-d H:i:s', $input);
});
