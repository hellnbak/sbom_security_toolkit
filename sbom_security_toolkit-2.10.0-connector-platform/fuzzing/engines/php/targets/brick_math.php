<?php
/**
 * Fuzz target: brick/math 0.12.1  (arbitrary-precision numeric-string parsing)
 * Numeric-string parsing + bignum arithmetic is a good source of edge cases
 * (locale, scientific notation, leading zeros, huge exponents).
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Brick\Math\BigDecimal;
use Brick\Math\Exception\MathException;

$config->setMaxLen(256);
// NumberFormatException / DivisionByZeroException / etc. all extend MathException.
$config->setAllowedExceptions([MathException::class]);

$config->setTarget(function (string $input) {
    $d = BigDecimal::of($input);     // parse an arbitrary numeric string
    $d->plus($d)->multipliedBy($d);  // exercise the arithmetic paths
});
