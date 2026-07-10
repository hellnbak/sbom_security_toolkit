<?php
/**
 * Fuzz target: dragonmantank/cron-expression 3.4.0  (Cron expression parsing)
 * Cron parsers handle complex field syntax (ranges, steps, lists, aliases).
 * Used in job schedulers where users supply cron strings. Risk of parser bugs,
 * ReDoS, or unexpected scheduling behavior.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Cron\CronExpression;

$config->setMaxLen(512);
$config->setAllowedExceptions([
    \InvalidArgumentException::class,
    \LogicException::class,
    \RuntimeException::class
]);

$config->setTarget(function (string $input) {
    try {
        $cron = new CronExpression($input);
        // Test isDue and getNextRunDate to exercise full parser
        $cron->isDue();
        $cron->getNextRunDate();
        $cron->getPreviousRunDate();
    } catch (\InvalidArgumentException | \LogicException | \RuntimeException $e) {
        // Expected for invalid cron syntax
    }
});
