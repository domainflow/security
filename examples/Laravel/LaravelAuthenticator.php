<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Laravel;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Principal;
use Throwable;

final readonly class LaravelAuthenticator implements Authenticator
{
    public function __construct(private LaravelGuard $guard)
    {
    }

    public function authenticate(Credential $credential): AuthenticationOutcome
    {
        try {
            $identity = $this->guard->identityFor($credential);
        } catch (Throwable) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('provider_error'));
        }

        $identifier = $identity['identifier'] ?? null;
        $attributes = $identity['attributes'] ?? [];
        if (
            $identity === null
            || !is_string($identifier)
            || trim($identifier) === ''
            || !is_array($attributes)
        ) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('invalid_credentials'));
        }

        return AuthenticationOutcome::authenticated(new Principal($identifier, $attributes));
    }
}
