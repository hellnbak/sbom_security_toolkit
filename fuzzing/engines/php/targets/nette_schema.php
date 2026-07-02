<?php
/**
 * Fuzz target: nette/schema 1.3.2  (Configuration validation/normalization)
 * Used by Laravel and Nette for config validation. Parses and coerces
 * untrusted array structures against schema definitions.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Nette\Schema\Processor;
use Nette\Schema\Schema;
use Nette\Schema\Elements\Structure;
use Nette\Schema\ValidationException;

// Define a representative schema covering common types
$schema = (new Structure([
    'name' => Schema::string()->required(),
    'age' => Schema::int()->min(0)->max(150),
    'email' => Schema::string()->pattern('[^@]+@[^@]+'),
    'tags' => Schema::arrayOf(Schema::string()),
    'meta' => Schema::structure([
        'enabled' => Schema::bool()->default(true),
        'priority' => Schema::anyOf(Schema::int(), Schema::string()),
    ])->castTo('array'),
]))->castTo('array');

$processor = new Processor();

$config->setMaxLen(4096);
$config->setAllowedExceptions([ValidationException::class]);

$config->setTarget(function (string $input) use ($processor, $schema) {
    // Parse JSON input into array structure
    $data = @json_decode($input, true);
    if (!is_array($data)) {
        $data = ['name' => $input]; // fallback for non-JSON
    }

    $processor->process($schema, $data);
});
