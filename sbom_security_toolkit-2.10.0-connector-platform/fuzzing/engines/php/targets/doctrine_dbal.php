<?php
/**
 * Fuzz target: doctrine/dbal 4.2.1  (SQL query parsing/building)
 * DBAL's query builder and parameter parsing handle SQL fragments from
 * application code. SQL parsers are classic fuzzing targets.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception as DBALException;

$conn = DriverManager::getConnection(['url' => 'sqlite:///:memory:']);

$config->setMaxLen(1024);
$config->setAllowedExceptions([
    DBALException::class,
    \InvalidArgumentException::class,
]);

$config->setTarget(function (string $input) use ($conn) {
    // Fuzz the query builder's WHERE clause parsing
    $qb = $conn->createQueryBuilder();
    $qb->select('*')->from('users')->where($input);
    // Don't execute - just parse/build
    $qb->getSQL();
});
