<?php
/**
 * Fuzz target: league/config 1.2.0  (config schema validation)
 * Validates configuration arrays against schema definitions. Schema validators
 * can have type confusion, injection, and validation bypass bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use League\Config\Configuration;
use Nette\Schema\Expect;

$config->setMaxLen(4096);

$schema = [
    'name' => Expect::string(),
    'port' => Expect::int(8080),
    'enabled' => Expect::bool(),
    'tags' => Expect::arrayOf('string'),
];

$configuration = new Configuration($schema);

$config->setTarget(function (string $input) use ($configuration) {
    try {
        $data = json_decode($input, true);
        if (is_array($data)) {
            $configuration->merge($data);
        }
    } catch (\League\Config\Exception\ConfigurationException $e) {
        // Expected for invalid config
    } catch (\Nette\Schema\ValidationException $e) {
        // Expected for schema violations
    }
});
