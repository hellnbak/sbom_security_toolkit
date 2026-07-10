<?php
/**
 * Fuzz target: tijsverkoyen/css-to-inline-styles 2.2.7  (CSS inliner for HTML email)
 * Parses HTML + CSS and inlines styles. Email HTML is attacker-controlled in
 * many contexts (contact forms, CRM). CSS parsers have XSS/injection history.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use TijsVerkoyen\CssToInlineStyles\CssToInlineStyles;

$inliner = new CssToInlineStyles();

$config->setMaxLen(8192);

$config->setTarget(function (string $input) use ($inliner) {
    // Split input: first line as CSS, rest as HTML (or treat all as HTML)
    $parts = explode("\n", $input, 2);
    if (count($parts) === 2) {
        $css = $parts[0];
        $html = $parts[1];
    } else {
        $css = 'body { color: red; }';
        $html = $input;
    }

    $inliner->convert($html, $css);
});
