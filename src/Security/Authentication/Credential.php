<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authentication;

use DomainFlow\Security\Exception\InvalidSecurityValue;

final readonly class Credential
{
    public string $scheme;

    public function __construct(
        string $scheme,
        private string $rawValue,
    ) {
        $scheme = strtolower(trim($scheme));

        if ($scheme === '') {
            throw new InvalidSecurityValue('Credential scheme must not be empty.');
        }

        if (trim($rawValue) === '') {
            throw new InvalidSecurityValue('Credential value must not be empty.');
        }

        $this->scheme = $scheme;
    }

    public function value(): string
    {
        return $this->rawValue;
    }
}
