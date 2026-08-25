<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final readonly class PsrSecurityFailureResponseFactory implements SecurityFailureResponseFactory
{
    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private ?string $challenge = 'Bearer',
    ) {
    }

    public function unauthorized(): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(401);

        if ($this->challenge === null) {
            return $response;
        }

        return $response->withHeader('WWW-Authenticate', $this->challenge);
    }

    public function forbidden(): ResponseInterface
    {
        return $this->responseFactory->createResponse(403);
    }
}
