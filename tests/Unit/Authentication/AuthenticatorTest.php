<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authentication;

use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Principal;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class AuthenticatorTest extends TestCase
{
    public function testAProviderAdapterCanImplementTheAuthenticatorPort(): void
    {
        $authenticator = new class() implements Authenticator {
            public function authenticate(Credential $credential): AuthenticationOutcome
            {
                return AuthenticationOutcome::authenticated(new Principal($credential->value()));
            }
        };

        $outcome = $authenticator->authenticate(new Credential('bearer', 'user-42'));

        $this->assertTrue($outcome->isAuthenticated());
        $this->assertSame('user-42', $outcome->principal()?->identifier);
    }
}
