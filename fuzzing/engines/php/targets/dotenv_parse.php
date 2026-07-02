<?php
/**
 * Fuzz target: vlucas/phpdotenv 5.6.1  (Environment file parsing)
 * Parses .env files. If user-controlled input reaches loadEnv() (config uploads,
 * dynamic env injection), bugs in quote handling, variable expansion, or comment
 * parsing can lead to injection attacks or unexpected behavior.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;

$config->setMaxLen(2048);
// No declared exceptions for parse success/fail; treat exceptions as crashes

$config->setTarget(function (string $input) {
    // Write input to a temp file, parse it, then delete
    $tmpDir = sys_get_temp_dir() . '/phpdotenv_fuzz_' . getmypid();
    @mkdir($tmpDir);
    $envFile = $tmpDir . '/.env';
    file_put_contents($envFile, $input);

    try {
        $dotenv = Dotenv::createImmutable($tmpDir);
        $dotenv->load();
    } finally {
        @unlink($envFile);
        @rmdir($tmpDir);
    }
});
