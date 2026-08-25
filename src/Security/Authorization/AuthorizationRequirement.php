<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authorization;

use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\ImmutableData;

final readonly class AuthorizationRequirement
{
    /**
     * @param array<array-key, mixed> $parameters
     */
    public function __construct(
        public string $name,
        private array $parameters = [],
    ) {
        if (trim($name) === '') {
            throw new InvalidSecurityValue('Authorization requirement name must not be empty.');
        }

        ImmutableData::assertMap($parameters, 'Authorization parameter');
    }

    /**
     * @return array<array-key, mixed>
     */
    public function parameters(): array
    {
        return $this->parameters;
    }

    public function parameter(string $name): mixed
    {
        return $this->parameters[$name] ?? null;
    }

    public function hasParameter(string $name): bool
    {
        return array_key_exists($name, $this->parameters);
    }
}
