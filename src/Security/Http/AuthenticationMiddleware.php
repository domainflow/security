<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\SecurityContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private CredentialExtractor $credentialExtractor,
        private Authenticator $authenticator,
        private SecurityFailureResponseFactory $failureResponseFactory,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $credential = $this->credentialExtractor->extract($request);

        if ($credential === null) {
            return $this->failureResponseFactory->unauthorized();
        }

        $authentication = $this->authenticator->authenticate($credential);

        if (!$authentication->isAuthenticated()) {
            return $this->failureResponseFactory->unauthorized();
        }

        $context = SecurityContext::fromAuthentication($authentication);

        return $handler->handle($request->withAttribute(SecurityContextAttribute::NAME, $context));
    }
}
