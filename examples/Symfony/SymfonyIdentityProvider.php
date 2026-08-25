<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Symfony;

use DomainFlow\Security\Authentication\Credential;

/** Application-owned port around Symfony Security's token storage/firewall. */
interface SymfonyIdentityProvider
{
    /** @return array<string, mixed>|null */
    public function identityFor(Credential $credential): ?array;
}
