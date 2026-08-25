<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Keycloak;

/** Provider-specific seam implemented by an OIDC/JWT verification package. */
interface KeycloakClaimsVerifier
{
    /** @return array<string, mixed>|null */
    public function verify(string $token): ?array;
}
