<?php

declare(strict_types=1);

namespace DomainFlow\Security\Internal;

use DomainFlow\Security\Exception\InvalidSecurityValue;

final class SecurityCode
{
    public static function assert(string $value, string $label): void
    {
        if (preg_match('/\A[a-z][a-z0-9_.:-]*\z/D', $value) !== 1) {
            throw new InvalidSecurityValue($label . ' must be a lowercase security code.');
        }
    }
}
