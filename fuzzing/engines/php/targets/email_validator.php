<?php
/**
 * Fuzz target: egulias/email-validator 4.0.2  (RFC email lexer/parser)
 * This is the validator behind Symfony Mailer / Laravel mail. Given the
 * CRLF-injection class of bugs around email handling, the lexer is worth
 * hammering. isValid() returns bool and swallows its own parse failures,
 * so the signals we care about are raw Errors, hangs, and memory blowups.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\RFCValidation;

$validator = new EmailValidator();
$rfc       = new RFCValidation();

$config->setMaxLen(512);

$config->setTarget(function (string $input) use ($validator, $rfc) {
    $validator->isValid($input, $rfc);
});
