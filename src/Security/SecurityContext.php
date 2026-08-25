<?php

declare(strict_types=1);

namespace DomainFlow\Security;

use DomainFlow\Security\Authentication\AuthenticationOutcome;

final readonly class SecurityContext
{
    private function __construct(private AuthenticationOutcome $authentication)
    {
    }

    public static function fromAuthentication(AuthenticationOutcome $authentication): self
    {
        return new self($authentication);
    }

    public function authentication(): AuthenticationOutcome
    {
        return $this->authentication;
    }

    public function isAuthenticated(): bool
    {
        return $this->authentication->isAuthenticated();
    }

    public function principal(): ?Principal
    {
        return $this->authentication->principal();
    }
}
