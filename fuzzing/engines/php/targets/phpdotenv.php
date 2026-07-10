<?php
/**
 * Fuzz target: vlucas/phpdotenv 5.6.1  (.env file parsing)
 * Parses variable assignments with quoting, escaping, interpolation. Often
 * attacker-writable via config file upload or git repository injection.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;
use Dotenv\Exception\ExceptionInterface as DotenvException;

$config->setMaxLen(4096);
$config->setAllowedExceptions([DotenvException::class]);

$config->setTarget(function (string $input) {
    // Write to temp file since Dotenv reads from filesystem
    $tmpfile = tempnam(sys_get_temp_dir(), 'fuzz_env_');
    file_put_contents($tmpfile, $input);

    try {
        $dotenv = Dotenv::createImmutable(dirname($tmpfile), basename($tmpfile));
        $dotenv->safeLoad();
    } finally {
        @unlink($tmpfile);
    }
});
