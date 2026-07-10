<?php
/**
 * Fuzz target: nikic/php-parser 5.3.1  (PHP source -> AST)
 * This is the canonical php-fuzzer use case. The phar build of php-fuzzer is
 * required precisely so the fuzzer's own php-parser does not clash with this
 * target version.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\Error;

$parser = (new ParserFactory())->createForNewestSupportedVersion();

$config->setMaxLen(2048);
// PhpParser\Error is the expected outcome for malformed PHP source.
$config->setAllowedExceptions([Error::class]);

$config->setTarget(function (string $input) use ($parser) {
    // Prepend an open tag so inputs exercise the language grammar rather than
    // being treated as inline HTML/literal text.
    $parser->parse("<?php " . $input);
});
