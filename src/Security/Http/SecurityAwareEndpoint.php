<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Security\SecurityContext;

/**
 * Application endpoint seam for explicit security-context propagation.
 *
 * The regular HTTP entry point may keep its existing invokable method for
 * route discovery. An HTTP endpoint adapter calls this method when the
 * operation needs the authenticated principal or authentication outcome.
 */
interface SecurityAwareEndpoint
{
    public function invokeWithSecurityContext(
        ?object $request,
        SecurityContext $context,
    ): mixed;
}
