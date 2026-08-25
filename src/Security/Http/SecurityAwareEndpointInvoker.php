<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Http\Endpoint\ContextAwareEndpointInvoker;
use DomainFlow\Http\Endpoint\EndpointInvoker;
use DomainFlow\Security\Http\Exception\SecurityEndpointInvocationException;
use DomainFlow\Security\SecurityContext;

/**
 * Delegation adapter for the generic DomainFlow HTTP context seam.
 */
final readonly class SecurityAwareEndpointInvoker implements ContextAwareEndpointInvoker
{
    public function __construct(private EndpointInvoker $fallback)
    {
    }

    public function invoke(
        object $endpoint,
        ?object $request,
        ?string $requestClass,
    ): mixed {
        if ($endpoint instanceof SecurityAwareEndpoint) {
            throw SecurityEndpointInvocationException::missingContext($endpoint);
        }

        return $this->fallback->invoke($endpoint, $request, $requestClass);
    }

    public function invokeWithContext(
        object $endpoint,
        ?object $request,
        ?string $requestClass,
        object $context,
    ): mixed {
        if ($endpoint instanceof SecurityAwareEndpoint) {
            if (!$context instanceof SecurityContext) {
                throw SecurityEndpointInvocationException::forContext($context);
            }

            return $endpoint->invokeWithSecurityContext($request, $context);
        }

        return $this->fallback->invoke($endpoint, $request, $requestClass);
    }
}
