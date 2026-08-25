<?php

declare(strict_types=1);

namespace DomainFlow\Security\Internal;

use DomainFlow\Security\Exception\InvalidSecurityValue;

final class ImmutableData
{
    /**
     * @param array<array-key, mixed> $values
     */
    public static function assertMap(array $values, string $label): void
    {
        foreach ($values as $key => $value) {
            if (!is_string($key) || $key === '') {
                throw new InvalidSecurityValue($label . ' names must be non-empty strings.');
            }

            self::assertValue($value, $label);
        }
    }

    private static function assertValue(mixed $value, string $label): void
    {
        if (is_array($value)) {
            foreach ($value as $nestedValue) {
                self::assertValue($nestedValue, $label);
            }

            return;
        }

        if (is_object($value) || is_resource($value)) {
            throw new InvalidSecurityValue($label . ' values must not contain mutable objects or resources.');
        }
    }
}
