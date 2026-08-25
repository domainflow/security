<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Custom;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Principal;

/**
 * Small application-owned adapter for a custom token store.
 *
 * Replace the array lookup with the application's token verifier or port.
 */
final readonly class ArrayTokenAuthenticator implements Authenticator
{
    /**
     * @param array<string, array{identifier: string, attributes?: array<array-key, mixed>}> $tokens
     */
    public function __construct(private array $tokens)
    {
    }

    public function authenticate(Credential $credential): AuthenticationOutcome
    {
        if ($credential->scheme !== 'bearer') {
            return AuthenticationOutcome::failed(new AuthenticationFailure('unsupported_scheme'));
        }

        $record = $this->tokens[$credential->value()] ?? null;
        if (!is_array($record) || !isset($record['identifier']) || !is_string($record['identifier'])) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('invalid_credentials'));
        }

        return AuthenticationOutcome::authenticated(new Principal(
            $record['identifier'],
            $record['attributes'] ?? [],
        ));
    }
}
