<?php
/**
 * Fuzz target: tijsverkoyen/css-to-inline-styles 2.2.7  (CSS parser + HTML DOM)
 * Parses CSS and inlines it into HTML style attributes for email clients.
 * Complex interaction between CSS parser and HTML DOM manipulation. Used by
 * Laravel Mailer. History of XSS bugs in similar CSS/HTML boundary tools.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use TijsVerkoyen\CssToInlineStyles\CssToInlineStyles;

$inliner = new CssToInlineStyles();

$config->setMaxLen(4096);
$config->setAllowedExceptions([\Exception::class]);

$config->setTarget(function (string $input) use ($inliner) {
    // Test with CSS input and minimal HTML
    $html = '<html><body><div class="test">Content</div></body></html>';
    $inliner->convert($html, $input);

    // Also test with input as HTML (exercises the HTML parser path)
    $css = '.test { color: red; }';
    $inliner->convert($input, $css);
});
