<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authorization;

use DomainFlow\Security\SecurityContext;

interface AuthorizationPolicy
{
    public function decide(
        SecurityContext $context,
        AuthorizationRequirement $requirement,
    ): AuthorizationDecision;
}
