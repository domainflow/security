<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use DomainFlow\Security\Authentication\Credential;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationHeaderCredentialExtractor implements CredentialExtractor
{
    public function extract(ServerRequestInterface $request): ?Credential
    {
        $header = trim($request->getHeaderLine('Authorization'));

        if ($header === '') {
            return null;
        }

        if (preg_match('/\A(?<scheme>[^\s]+)\s+(?<value>.+)\z/D', $header, $matches) !== 1) {
            return null;
        }

        return new Credential($matches['scheme'], trim($matches['value']));
    }
}
