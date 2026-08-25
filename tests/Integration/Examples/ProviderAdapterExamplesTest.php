<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Integration\Examples;

use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Examples\Custom\ArrayTokenAuthenticator;
use DomainFlow\Security\Examples\Keycloak\KeycloakAuthenticator;
use DomainFlow\Security\Examples\Keycloak\KeycloakClaimsVerifier;
use DomainFlow\Security\Examples\Laravel\LaravelAuthenticator;
use DomainFlow\Security\Examples\Laravel\LaravelGuard;
use DomainFlow\Security\Examples\Symfony\SymfonyAuthenticator;
use DomainFlow\Security\Examples\Symfony\SymfonyIdentityProvider;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversNothing]
final class ProviderAdapterExamplesTest extends TestCase
{
    public function testCustomAdapterMapsOnlyValidatedApplicationValues(): void
    {
        $authenticator = new ArrayTokenAuthenticator([
            'custom-token' => ['identifier' => 'service-1', 'attributes' => ['tenant' => 'acme']],
        ]);

        $outcome = $authenticator->authenticate(new Credential('Bearer', 'custom-token'));
        $principal = $outcome->principal();

        $this->assertTrue($outcome->isAuthenticated());
        $this->assertNotNull($principal);
        $this->assertSame('service-1', $principal->identifier);
        $this->assertSame('acme', $principal->attribute('tenant'));
        $this->assertNotSame('custom-token', $principal->attribute('token'));
    }

    public function testKeycloakAdapterDelegatesVerificationAndMapsClaims(): void
    {
        $authenticator = new KeycloakAuthenticator(new StubKeycloakVerifier([
            'sub' => 'user-1',
            'iss' => 'https://id.example.test/realms/acme',
            'scope' => 'orders:read profile',
            'realm_access' => ['roles' => ['operator']],
        ]));

        $outcome = $authenticator->authenticate(new Credential('bearer', 'jwt-token'));
        $principal = $outcome->principal();

        $this->assertTrue($outcome->isAuthenticated());
        $this->assertNotNull($principal);
        $this->assertSame('user-1', $principal->identifier);
        $this->assertSame(['operator'], $principal->attribute('roles'));
        $this->assertSame(['orders:read', 'profile'], $principal->attribute('scopes'));
        $this->assertFalse($principal->hasAttribute('token'));
    }

    public function testSymfonyAndLaravelExamplesMapProviderIdentities(): void
    {
        $credential = new Credential('bearer', 'token');
        $symfony = new SymfonyAuthenticator(new StubSymfonyProvider());
        $laravel = new LaravelAuthenticator(new StubLaravelGuard());

        $this->assertSame('symfony-user', $symfony->authenticate($credential)->principal()?->identifier);
        $this->assertSame('laravel-user', $laravel->authenticate($credential)->principal()?->identifier);
    }

    public function testAdaptersReturnFailureWithoutLeakingProviderErrorsOrTokens(): void
    {
        $keycloak = new KeycloakAuthenticator(new StubKeycloakVerifier(null));
        $outcome = $keycloak->authenticate(new Credential('bearer', 'expired-token'));

        $this->assertFalse($outcome->isAuthenticated());
        $this->assertSame('invalid_credentials', $outcome->failure()?->code);
    }

    public function testProviderExceptionsAreTranslatedAtTheKeycloakBoundary(): void
    {
        $outcome = (new KeycloakAuthenticator(new ThrowingKeycloakVerifier()))
            ->authenticate(new Credential('bearer', 'token'));

        $this->assertFalse($outcome->isAuthenticated());
        $this->assertSame('provider_error', $outcome->failure()?->code);
    }

    public function testFrameworkAdaptersRejectMalformedIdentityData(): void
    {
        $credential = new Credential('bearer', 'token');

        $this->assertFalse(
            (new SymfonyAuthenticator(new InvalidSymfonyProvider()))
                ->authenticate($credential)
                ->isAuthenticated(),
        );
        $this->assertFalse(
            (new LaravelAuthenticator(new InvalidLaravelGuard()))
                ->authenticate($credential)
                ->isAuthenticated(),
        );
    }

    public function testKeycloakRejectsMalformedClaimLists(): void
    {
        $outcome = (new KeycloakAuthenticator(new StubKeycloakVerifier([
            'sub' => 'user-1',
            'realm_access' => ['roles' => ['role' => 'operator']],
        ])))->authenticate(new Credential('bearer', 'token'));

        $this->assertFalse($outcome->isAuthenticated());
        $this->assertSame('invalid_credentials', $outcome->failure()?->code);
    }

    public function testFrameworkProviderExceptionsAreTranslated(): void
    {
        $credential = new Credential('bearer', 'token');

        $this->assertSame(
            'provider_error',
            (new SymfonyAuthenticator(new ThrowingSymfonyProvider()))
                ->authenticate($credential)
                ->failure()?->code,
        );
        $this->assertSame(
            'provider_error',
            (new LaravelAuthenticator(new ThrowingLaravelGuard()))
                ->authenticate($credential)
                ->failure()?->code,
        );
    }
}

final class StubKeycloakVerifier implements KeycloakClaimsVerifier
{
    /** @param array<string, mixed>|null $claims */
    public function __construct(private readonly ?array $claims)
    {
    }

    public function verify(string $token): ?array
    {
        return $this->claims;
    }
}

final class StubSymfonyProvider implements SymfonyIdentityProvider
{
    public function identityFor(Credential $credential): ?array
    {
        return $credential->value() === 'missing'
            ? null
            : ['identifier' => 'symfony-user', 'roles' => ['ROLE_USER']];
    }
}

final class InvalidSymfonyProvider implements SymfonyIdentityProvider
{
    public function identityFor(Credential $credential): ?array
    {
        return $credential->value() === 'missing'
            ? null
            : ['identifier' => 42, 'roles' => []];
    }
}

final class ThrowingSymfonyProvider implements SymfonyIdentityProvider
{
    public function identityFor(Credential $credential): ?array
    {
        throw new RuntimeException('Symfony details must not escape');
    }
}

final class StubLaravelGuard implements LaravelGuard
{
    public function identityFor(Credential $credential): ?array
    {
        return $credential->value() === 'missing'
            ? null
            : ['identifier' => 'laravel-user', 'attributes' => ['team' => 'platform']];
    }
}

final class InvalidLaravelGuard implements LaravelGuard
{
    public function identityFor(Credential $credential): ?array
    {
        return $credential->value() === 'missing'
            ? null
            : ['identifier' => 'laravel-user', 'attributes' => 'invalid'];
    }
}

final class ThrowingLaravelGuard implements LaravelGuard
{
    public function identityFor(Credential $credential): ?array
    {
        throw new RuntimeException('Laravel details must not escape');
    }
}

final class ThrowingKeycloakVerifier implements KeycloakClaimsVerifier
{
    public function verify(string $token): ?array
    {
        throw new RuntimeException('provider details must not escape');
    }
}
