<?php
/**
 * Fuzz target: ramsey/collection 2.0.0  (typed collection serialization)
 * Handles deserialization and type validation of collections. Serialization
 * boundaries are classic attack surfaces for type confusion and injection.
 *
 * @var PhpFuzzer\Config $config
 */
require __DIR__ . '/../vendor/autoload.php';

use Ramsey\Collection\Collection;

$config->setMaxLen(8192);

$config->setTarget(function (string $input) {
    try {
        $data = unserialize($input);
        if ($data instanceof Collection) {
            $data->count();
            $data->toArray();
            foreach ($data as $item) {
                $data->contains($item);
            }
        }
    } catch (\Ramsey\Collection\Exception\CollectionException $e) {
        // Expected for invalid collections
    } catch (\UnexpectedValueException $e) {
        // Expected for type mismatches
    } catch (\Error $e) {
        if (strpos($e->getMessage(), 'unserialize') === false) {
            throw $e;
        }
    }
});
