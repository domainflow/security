<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Security\Authentication\Credential;
use Psr\Http\Message\ServerRequestInterface;

interface CredentialExtractor
{
    public function extract(ServerRequestInterface $request): ?Credential;
}
