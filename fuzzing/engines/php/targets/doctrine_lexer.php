<?php
/**
 * Fuzz target: doctrine/lexer 3.0.1  (Token lexer framework)
 * Lexers parse untrusted input into tokens; widely used by Doctrine ORM/DBAL
 * for DQL queries. Lexer bugs can lead to injection or parser confusion.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Doctrine\Common\Lexer\AbstractLexer;

// Minimal concrete lexer implementation to exercise the base framework
class TestLexer extends AbstractLexer
{
    const T_NONE = 1;
    const T_INTEGER = 2;
    const T_STRING = 3;
    const T_IDENTIFIER = 4;
    const T_WHITESPACE = 5;

    protected function getCatchablePatterns(): array
    {
        return [
            '[a-z_][a-z0-9_]*',
            '(?:[0-9]+(?:[\.][0-9]+)?)',
            '"(?:[^"]|"")*"',
        ];
    }

    protected function getNonCatchablePatterns(): array
    {
        return ['\s+'];
    }

    protected function getType(&$value): int
    {
        if (is_numeric($value)) {
            return self::T_INTEGER;
        }
        if ($value[0] === '"') {
            return self::T_STRING;
        }
        if (ctype_alpha($value[0])) {
            return self::T_IDENTIFIER;
        }
        return self::T_NONE;
    }
}

$lexer = new TestLexer();

$config->setMaxLen(2048);

$config->setTarget(function (string $input) use ($lexer) {
    $lexer->setInput($input);
    // Force full tokenization by walking the entire input
    while ($lexer->moveNext()) {
        $lexer->lookahead;
    }
});
