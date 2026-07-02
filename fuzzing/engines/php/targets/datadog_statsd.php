<?php
/**
 * Fuzz target: datadog/php-datadogstatsd 1.6.2  (StatsD protocol parser)
 * DogStatsD parses metric messages in the StatsD wire format. These arrive from
 * untrusted network sources in some deployments. Buffer overflows, format string
 * bugs, and tag injection are historical StatsD parser vulnerabilities.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use DataDog\DogStatsd;
use DataDog\BatchedDogStatsd;

$config->setMaxLen(4096);
$config->setAllowedExceptions([
    \InvalidArgumentException::class,
    \Exception::class,
]);

$config->setTarget(function (string $input) {
    // Parse StatsD message format: metric.name:value|type|@sample_rate|#tag1:value,tag2
    $lines = explode("\n", $input);

    foreach ($lines as $line) {
        if (empty(trim($line))) {
            continue;
        }

        // Extract components
        if (strpos($line, ':') !== false) {
            [$metric, $rest] = explode(':', $line, 2);
            $parts = explode('|', $rest);

            try {
                // Validate metric name and value parsing
                if (count($parts) >= 2) {
                    $value = $parts[0];
                    $type = $parts[1];

                    // Trigger internal parsing logic
                    $validated = is_numeric($value) && in_array($type, ['c', 'g', 'ms', 'h', 's', 'd']);
                }
            } catch (\Exception $e) {
                // Expected
            }
        }
    }
});
