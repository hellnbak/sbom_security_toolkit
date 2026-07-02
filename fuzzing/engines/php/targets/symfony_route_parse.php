<?php
/**
 * Fuzz target: symfony/routing 7.2.0  (Route pattern parsing and matching)
 * Route parsers handle patterns with placeholders, requirements (regex),
 * and UTF-8 paths. Risk of ReDoS in requirement regex or path traversal bugs.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;
use Symfony\Component\Routing\Exception\MethodNotAllowedException;

$config->setMaxLen(1024);
$config->setAllowedExceptions([
    \InvalidArgumentException::class,
    \LogicException::class,
    ResourceNotFoundException::class,
    MethodNotAllowedException::class
]);

$config->setTarget(function (string $input) {
    try {
        // Test route creation with fuzzed pattern
        $route = new Route($input);

        // Test matching against fuzzed path
        $collection = new RouteCollection();
        $collection->add('fuzz_route', new Route('/test/{param}'));
        $context = new RequestContext();
        $matcher = new UrlMatcher($collection, $context);

        try {
            $matcher->match($input);
        } catch (ResourceNotFoundException | MethodNotAllowedException $e) {
            // Expected for non-matching paths
        }
    } catch (\InvalidArgumentException | \LogicException $e) {
        // Expected for invalid route syntax
    }
});
