<?php
/**
 * Fuzz target: symfony/yaml 7.2.0  (YAML parsing)
 * YAML parsers have a long history of DoS (billion-laughs-style),
 * type-confusion, and parser bugs. Strong fuzzing candidate.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ExceptionInterface as YamlException;

$config->setMaxLen(32768);   // YAML DoS vectors (deep nesting, long directive
                             // headers) need real length/depth to matter —
                             // 2048 was too tight to let the mutator explore them.
$config->setAllowedExceptions([YamlException::class]);

$config->setTarget(function (string $input) {
    // PARSE_CUSTOM_TAGS exercises more of the grammar.
    // Deliberately NOT enabling PARSE_OBJECT / PARSE_OBJECT_FOR_MAP:
    // instantiating objects from untrusted YAML is a security risk we do not
    // want to invite even inside a sandbox.
    Yaml::parse($input, Yaml::PARSE_CUSTOM_TAGS);
});
