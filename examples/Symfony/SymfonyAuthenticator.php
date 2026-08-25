<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Symfony;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Principal;
use Throwable;

final readonly class SymfonyAuthenticator implements Authenticator
{
    public function __construct(private SymfonyIdentityProvider $provider)
    {
    }

    public function authenticate(Credential $credential): AuthenticationOutcome
    {
        try {
            $identity = $this->provider->identityFor($credential);
        } catch (Throwable) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('provider_error'));
        }

        $identifier = $identity['identifier'] ?? null;
        $roles = $this->roles($identity['roles'] ?? []);
        if (
            $identity === null
            || !is_string($identifier)
            || trim($identifier) === ''
            || $roles === null
        ) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('invalid_credentials'));
        }

        return AuthenticationOutcome::authenticated(new Principal($identifier, [
            'roles' => $roles,
        ]));
    }

    /** @return list<string>|null */
    private function roles(mixed $roles): ?array
    {
        if (!is_array($roles) || !array_is_list($roles)) {
            return null;
        }

        $normalized = [];
        foreach ($roles as $role) {
            if (!is_string($role) || trim($role) === '') {
                return null;
            }

            $normalized[] = $role;
        }

        return $normalized;
    }
}
