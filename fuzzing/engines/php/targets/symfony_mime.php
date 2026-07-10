<?php
/**
 * Fuzz target: symfony/mime 7.2.1  (MIME message parsing)
 * Email/MIME parsers handle complex multipart boundaries, headers, encodings.
 * Direct path from external email to this parser in many applications.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Mime\Message;
use Symfony\Component\Mime\Exception\ExceptionInterface as MimeException;

$config->setMaxLen(8192);
$config->setAllowedExceptions([MimeException::class]);

$config->setTarget(function (string $input) {
    $message = Message::fromString($input);
    $message->getHeaders();
    $message->getBody();
});
