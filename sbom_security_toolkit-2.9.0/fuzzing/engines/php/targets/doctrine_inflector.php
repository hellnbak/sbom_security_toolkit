<?php
/**
 * Fuzz target: doctrine/inflector 2.0.10  (string inflection / pluralization)
 * Handles untrusted strings for pluralize/singularize/tableize/classify/camelize.
 * Edge cases in UTF-8 handling, regex patterns, and word boundaries can surface bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Doctrine\Inflector\InflectorFactory;

$inflector = InflectorFactory::create()->build();

$config->setMaxLen(512);

$config->setTarget(function (string $input) use ($inflector) {
    $inflector->pluralize($input);
    $inflector->singularize($input);
    $inflector->tableize($input);
    $inflector->classify($input);
    $inflector->camelize($input);
});
