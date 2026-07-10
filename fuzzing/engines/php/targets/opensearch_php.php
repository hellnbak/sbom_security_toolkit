<?php
/**
 * Fuzz target: opensearch-project/opensearch-php 2.3.1  (JSON query DSL serialization)
 * The client serializes user input into JSON queries. Malformed structures, deeply nested
 * arrays, and edge cases in parameter encoding can expose bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use OpenSearch\ClientBuilder;

$config->setMaxLen(4096);

$config->setTarget(function (string $input) {
    // Parse as JSON if possible, otherwise treat as raw search term
    $decoded = @json_decode($input, true);

    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
        // Fuzz the query DSL serialization path
        $params = [
            'index' => 'test',
            'body' => $decoded
        ];

        // Serialize the body without actually sending
        json_encode($params);
    } else {
        // Fuzz simple search terms
        $params = [
            'index' => 'test',
            'body' => [
                'query' => [
                    'match' => ['field' => $input]
                ]
            ]
        ];
        json_encode($params);
    }
});
