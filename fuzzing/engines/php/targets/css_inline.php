<?php
/**
 * Fuzz target: tijsverkoyen/css-to-inline-styles 2.2.7  (CSS parser + DOM)
 * Used by Symfony Mailer for email templates. Parses CSS and applies it inline.
 * Both the CSS parser and the HTML DOM manipulation are attack surfaces;
 * malformed CSS or HTML can trigger parser bugs or XSS if escaping breaks.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use TijsVerkoyen\CssToInlineStyles\CssToInlineStyles;

$inliner = new CssToInlineStyles();

$config->setMaxLen(4096);
// No declared exceptions; we expect clean success/fail, treat all exceptions as bugs

$config->setTarget(function (string $input) use ($inliner) {
    // Split input into HTML and CSS at first "\n---\n" boundary
    $parts = explode("\n---\n", $input, 2);
    $html = $parts[0];
    $css  = $parts[1] ?? '';

    $inliner->setHTML($html);
    $inliner->setCSS($css);
    $inliner->convert();
});
