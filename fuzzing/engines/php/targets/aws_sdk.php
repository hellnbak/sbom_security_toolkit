<?php
/**
 * Fuzz target: aws/aws-sdk-php 3.334.3  (XML response parsing)
 * AWS SDK parses XML responses from various services. XML parsers are
 * notorious for XXE, billion-laughs, and entity-expansion DoS.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Aws\Api\Parser\XmlParser;
use Aws\Api\StructureShape;
use Aws\Api\Service;
use Aws\Api\Shape;

$config->setMaxLen(32768);

// Create a minimal S3-like service shape for the parser
$serviceArray = [
    'metadata' => [
        'protocol' => 'rest-xml',
        'apiVersion' => '2006-03-01',
    ],
    'operations' => [
        'TestOp' => [
            'http' => ['method' => 'GET', 'requestUri' => '/'],
            'output' => ['shape' => 'TestOutput']
        ]
    ],
    'shapes' => [
        'TestOutput' => [
            'type' => 'structure',
            'members' => [
                'Key' => ['shape' => 'String'],
                'Value' => ['shape' => 'String'],
            ]
        ],
        'String' => ['type' => 'string']
    ]
];

$service = new Service($serviceArray, function() { return []; });
$parser = new XmlParser($service);
$shape = $service->getOperation('TestOp')->getOutput();

$config->setTarget(function (string $input) use ($parser, $shape) {
    try {
        $parser->parseMemberFromStream(
            new \GuzzleHttp\Psr7\Stream(fopen('data://text/plain,' . urlencode($input), 'r')),
            $shape,
            null
        );
    } catch (\Aws\Exception\AwsException $e) {
        // Expected for malformed input
    }
});
