<?php
/**
 * Fuzz target: symfony/routing 7.2.0  (Route pattern matcher)
 * Parses route patterns with placeholders, requirements (regex), and matches
 * incoming paths. ReDoS and parser confusion bugs are common in route matchers.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;
use Symfony\Component\Routing\Exception\MethodNotAllowedException;

// Build a representative route collection with complex patterns
$routes = new RouteCollection();
$routes->add('user', new Route('/user/{id}', [], ['id' => '\d+']));
$routes->add('post', new Route('/post/{slug}', [], ['slug' => '[a-z0-9-]+']));
$routes->add('complex', new Route('/api/{version}/{resource}/{action}', [], [
    'version' => 'v\d+',
    'resource' => '\w+',
]));

$context = new RequestContext();
$matcher = new UrlMatcher($routes, $context);

$config->setMaxLen(1024);
$config->setAllowedExceptions([
    ResourceNotFoundException::class,
    MethodNotAllowedException::class,
]);

$config->setTarget(function (string $input) use ($matcher) {
    $matcher->match($input);
});
