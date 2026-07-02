<?php
/**
 * Fuzz target: symfony/css-selector 7.2.0  (CSS selector -> XPath parser)
 * Converts CSS selectors to XPath expressions, used by web scrapers and test
 * frameworks. Complex grammar with combinators, pseudo-classes, and attribute
 * selectors. Potential for injection bugs if output is used unsafely.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\CssSelector\CssSelectorConverter;
use Symfony\Component\CssSelector\Exception\ExceptionInterface as CssSelectorException;

$converter = new CssSelectorConverter();

$config->setMaxLen(1024);
$config->setAllowedExceptions([CssSelectorException::class]);

$config->setTarget(function (string $input) use ($converter) {
    // toXPath exercises the full parser and converter
    $converter->toXPath($input);
});
