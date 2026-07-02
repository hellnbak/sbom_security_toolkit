<?php
/**
 * Fuzz target: symfony/var-dumper 7.2.0  (serialized data parsing)
 * Parses Data clones (serialized dump output). Deserialization of complex
 * object graphs has historically been a rich source of exploits.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\VarDumper\Cloner\Data;
use Symfony\Component\VarDumper\Exception\ThrowingCasterException;

$config->setMaxLen(16384);
$config->setAllowedExceptions([ThrowingCasterException::class]);

$config->setTarget(function (string $input) {
    try {
        $data = unserialize($input);
        if ($data instanceof Data) {
            $data->getValue();
            $data->getType();
        }
    } catch (\Throwable $e) {
        if (!$e instanceof ThrowingCasterException) {
            throw $e;
        }
    }
});
