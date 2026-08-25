<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Security\Authorization\AuthorizationPolicy;
use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\SecurityContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthorizationPolicy $policy,
        private AuthorizationRequirement $requirement,
        private SecurityFailureResponseFactory $failureResponseFactory,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $context = $request->getAttribute(SecurityContextAttribute::NAME);

        if (!$context instanceof SecurityContext || !$context->isAuthenticated()) {
            return $this->failureResponseFactory->unauthorized();
        }

        $decision = $this->policy->decide($context, $this->requirement);

        if (!$decision->isGranted()) {
            return $this->failureResponseFactory->forbidden();
        }

        return $handler->handle($request);
    }
}
