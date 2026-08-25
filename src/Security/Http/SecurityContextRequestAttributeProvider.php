<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Http\Endpoint\EndpointContextProvider;
use DomainFlow\Security\SecurityContext;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Bridges the PSR-15 request attribute established by authentication
 * middleware to the generic DomainFlow HTTP endpoint-context seam.
 */
final class SecurityContextRequestAttributeProvider implements EndpointContextProvider
{
    public function context(ServerRequestInterface $request): ?object
    {
        $context = $request->getAttribute(SecurityContextAttribute::NAME);

        return $context instanceof SecurityContext ? $context : null;
    }
}
