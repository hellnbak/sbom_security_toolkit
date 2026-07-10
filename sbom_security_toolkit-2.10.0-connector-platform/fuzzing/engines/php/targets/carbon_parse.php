<?php
/**
 * Fuzz target: nesbot/carbon 3.8.2  (Date/time parsing)
 * Carbon parses natural-language date strings and is attacker-reachable in
 * many Laravel apps (profile fields, query params, form inputs). The parse()
 * method has a long tail of format handlers and timezone logic worth fuzzing.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Carbon\Carbon;
use Carbon\Exceptions\InvalidFormatException;

$config->setMaxLen(512);
$config->setAllowedExceptions([
    InvalidFormatException::class,
    \Exception::class,  // Carbon throws generic Exception for some parse failures
]);

$config->setTarget(function (string $input) {
    // parse() handles natural language dates, the high-value attack surface
    Carbon::parse($input);
});
