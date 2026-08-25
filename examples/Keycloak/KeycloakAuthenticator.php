<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Keycloak;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Principal;
use Throwable;

/**
 * Keycloak/OIDC adapter. Token signature, issuer, audience, and expiry checks
 * belong to the injected verifier, not to this contract package.
 */
final readonly class KeycloakAuthenticator implements Authenticator
{
    public function __construct(private KeycloakClaimsVerifier $verifier)
    {
    }

    public function authenticate(Credential $credential): AuthenticationOutcome
    {
        if ($credential->scheme !== 'bearer') {
            return AuthenticationOutcome::failed(new AuthenticationFailure('unsupported_scheme'));
        }

        try {
            $claims = $this->verifier->verify($credential->value());
        } catch (Throwable) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('provider_error'));
        }

        $subject = $claims['sub'] ?? null;
        $roles = $claims === null ? null : $this->roles($claims);
        $scopes = $claims === null ? null : $this->scopes($claims);
        if (
            $claims === null
            || !is_string($subject)
            || trim($subject) === ''
            || $roles === null
            || $scopes === null
        ) {
            return AuthenticationOutcome::failed(new AuthenticationFailure('invalid_credentials'));
        }

        return AuthenticationOutcome::authenticated(new Principal($subject, [
            'issuer' => is_string($claims['iss'] ?? null) ? $claims['iss'] : null,
            'roles' => $roles,
            'scopes' => $scopes,
        ]));
    }

    /**
     * @param array<string, mixed> $claims
     * @return list<string>|null
     */
    private function roles(array $claims): ?array
    {
        $realmAccess = $claims['realm_access'] ?? null;
        if ($realmAccess === null) {
            return [];
        }

        if (!is_array($realmAccess) || !array_key_exists('roles', $realmAccess)) {
            return null;
        }

        return $this->strings($realmAccess['roles']);
    }

    /**
     * @param array<string, mixed> $claims
     * @return list<string>|null
     */
    private function scopes(array $claims): ?array
    {
        $scope = $claims['scope'] ?? '';

        return is_string($scope) ? array_values(array_filter(explode(' ', trim($scope)))) : null;
    }

    /** @return list<string>|null */
    private function strings(mixed $value): ?array
    {
        if (!is_array($value) || !array_is_list($value)) {
            return null;
        }

        $strings = [];
        foreach ($value as $item) {
            if (!is_string($item) || trim($item) === '') {
                return null;
            }

            $strings[] = $item;
        }

        return $strings;
    }
}
