<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authentication;

interface Authenticator
{
    public function authenticate(Credential $credential): AuthenticationOutcome;
}
