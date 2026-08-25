<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authorization;

use DomainFlow\Security\Internal\SecurityCode;

final readonly class AuthorizationDecision
{
    private function __construct(
        private bool $granted,
        private ?string $reason,
    ) {
    }

    public static function allow(): self
    {
        return new self(true, null);
    }

    public static function deny(?string $reason = null): self
    {
        if ($reason !== null) {
            SecurityCode::assert($reason, 'Authorization decision reason');
        }

        return new self(false, $reason);
    }

    public function isGranted(): bool
    {
        return $this->granted;
    }

    public function reason(): ?string
    {
        return $this->reason;
    }
}
