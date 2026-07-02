<?php
/**
 * Fuzz target: dragonmantank/cron-expression 3.4.0  (Cron syntax parser)
 * Parses cron expressions (5-6 fields: minute/hour/day/month/weekday/year).
 * Used in schedulers like Laravel's task scheduling. History of DoS via
 * complex expressions with ranges, steps, and lists causing expensive iteration.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Cron\CronExpression;

$config->setMaxLen(512);
$config->setAllowedExceptions([\InvalidArgumentException::class, \RuntimeException::class]);

$config->setTarget(function (string $input) {
    // Parse and attempt to get next run date to exercise validation
    try {
        $cron = new CronExpression($input);
        $cron->getNextRunDate();
    } catch (\InvalidArgumentException $e) {
        // Expected for invalid cron syntax
    }
});
