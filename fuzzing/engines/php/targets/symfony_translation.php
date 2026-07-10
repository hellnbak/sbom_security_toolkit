<?php
/**
 * Fuzz target: symfony/translation 7.2.0  (ICU MessageFormat parser)
 * Translation parsers handle ICU MessageFormat with placeholders, pluralization,
 * select rules, nested messages. Complex grammar, user input in translation keys
 * or dynamic messages. Not as obvious as YAML/Markdown, but format strings can hide bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Translation\Translator;
use Symfony\Component\Translation\Loader\ArrayLoader;
use Symfony\Component\Translation\Exception\ExceptionInterface as TranslationException;

$translator = new Translator('en');
$translator->addLoader('array', new ArrayLoader());

$config->setMaxLen(2048);
$config->setAllowedExceptions([TranslationException::class]);

$config->setTarget(function (string $input) use ($translator) {
    // Attempt to parse as ICU MessageFormat
    $translator->trans($input, ['placeholder' => $input]);
});
