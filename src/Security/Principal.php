<?php

declare(strict_types=1);

namespace DomainFlow\Security;

use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\ImmutableData;

final readonly class Principal
{
    /**
     * @param array<array-key, mixed> $attributes
     */
    public function __construct(
        public string $identifier,
        private array $attributes = [],
    ) {
        if (trim($identifier) === '') {
            throw new InvalidSecurityValue('Principal identifier must not be empty.');
        }

        ImmutableData::assertMap($attributes, 'Principal attribute');
    }

    /**
     * @return array<array-key, mixed>
     */
    public function attributes(): array
    {
        return $this->attributes;
    }

    public function attribute(string $name): mixed
    {
        return $this->attributes[$name] ?? null;
    }

    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->attributes);
    }
}
