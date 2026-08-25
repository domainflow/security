<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authentication;

use DomainFlow\Security\Principal;

final readonly class AuthenticationOutcome
{
    private function __construct(
        private ?Principal $principal,
        private ?AuthenticationFailure $failure,
    ) {
    }

    public static function authenticated(Principal $principal): self
    {
        return new self($principal, null);
    }

    public static function failed(AuthenticationFailure $failure): self
    {
        return new self(null, $failure);
    }

    public function isAuthenticated(): bool
    {
        return $this->principal !== null;
    }

    public function principal(): ?Principal
    {
        return $this->principal;
    }

    public function failure(): ?AuthenticationFailure
    {
        return $this->failure;
    }
}
