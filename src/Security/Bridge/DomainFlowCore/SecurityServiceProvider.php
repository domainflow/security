<?php

declare(strict_types=1);

namespace DomainFlow\Security\Bridge\DomainFlowCore;

use DomainFlow\Application;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authorization\AuthorizationPolicy;
use DomainFlow\Service\AbstractServiceProvider;

/**
 * Registers application-owned security services in a DomainFlow Core container.
 *
 * The security context is deliberately not registered here: it is immutable
 * request or operation state and must be passed explicitly at that boundary.
 * This bridge also does not register or adapt Core's callable middleware.
 */
final class SecurityServiceProvider extends AbstractServiceProvider
{
    public function __construct(
        private readonly ?Authenticator $authenticator = null,
        private readonly ?AuthorizationPolicy $authorizationPolicy = null,
    ) {
        $this->providedServices = array_values(array_filter([
            $authenticator === null ? null : Authenticator::class,
            $authorizationPolicy === null ? null : AuthorizationPolicy::class,
        ]));
    }

    public function register(Application $app): void
    {
        if ($this->authenticator !== null) {
            $app->instance(Authenticator::class, $this->authenticator);
        }

        if ($this->authorizationPolicy !== null) {
            $app->instance(AuthorizationPolicy::class, $this->authorizationPolicy);
        }
    }
}
