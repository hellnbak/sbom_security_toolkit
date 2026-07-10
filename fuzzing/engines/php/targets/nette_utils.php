<?php
/**
 * Fuzz target: nette/utils 4.0.5  (HTML/string utilities)
 * Html::el()->setText() and Strings::normalize() parse untrusted input.
 * HTML entity encoding bugs and Unicode normalization edge cases are targets.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Nette\Utils\Html;
use Nette\Utils\Strings;

$config->setMaxLen(1024);

$config->setTarget(function (string $input) {
    Html::el('div')->setText($input)->toHtml();
    Html::el('span')->setHtml($input)->toHtml();

    try {
        Strings::normalize($input);
    } catch (\Nette\Utils\RegexpException $e) {
        // Expected for invalid patterns
    }

    Strings::truncate($input, 100);
    Strings::trim($input);
});
