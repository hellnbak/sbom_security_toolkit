<?php
/**
 * Fuzz target: opensearch-project/opensearch-php 2.3.1  (Query DSL parsing)
 * OpenSearch query DSL is JSON-based with complex nested structures, aggregations,
 * scripting. Risk of injection via untrusted query params or log search UIs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use OpenSearch\Common\Exceptions\OpenSearchException;
use OpenSearch\Serializers\ArrayToJSONSerializer;

$config->setMaxLen(4096);
$config->setAllowedExceptions([
    OpenSearchException::class,
    \JsonException::class,
    \InvalidArgumentException::class
]);

$config->setTarget(function (string $input) {
    // Test JSON serialization path (what OpenSearch client does with queries)
    $serializer = new ArrayToJSONSerializer();

    try {
        // Try parsing as JSON first
        $data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
        if ($data !== null) {
            // Serialize it back to test the serializer path
            $serializer->serialize($data);
        }
    } catch (\JsonException | OpenSearchException | \InvalidArgumentException $e) {
        // Expected for invalid JSON or query structure
    }
});
