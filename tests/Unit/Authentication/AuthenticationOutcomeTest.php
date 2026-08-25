<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authentication;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\Internal\SecurityCode;
use DomainFlow\Security\Principal;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthenticationOutcome::class)]
#[UsesClass(AuthenticationFailure::class)]
#[UsesClass(ImmutableData::class)]
#[UsesClass(Principal::class)]
#[UsesClass(SecurityCode::class)]
final class AuthenticationOutcomeTest extends TestCase
{
    public function testRepresentsSuccessfulAuthenticationWithoutAFailure(): void
    {
        $principal = new Principal('user-42');
        $outcome = AuthenticationOutcome::authenticated($principal);

        $this->assertTrue($outcome->isAuthenticated());
        $this->assertSame($principal, $outcome->principal());
        $this->assertNull($outcome->failure());
    }

    public function testRepresentsFailedAuthenticationWithoutAPrincipal(): void
    {
        $failure = new AuthenticationFailure('expired_credential');
        $outcome = AuthenticationOutcome::failed($failure);

        $this->assertFalse($outcome->isAuthenticated());
        $this->assertNull($outcome->principal());
        $this->assertSame($failure, $outcome->failure());
    }
}
