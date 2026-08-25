<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\Internal\SecurityCode;
use DomainFlow\Security\Principal;
use DomainFlow\Security\SecurityContext;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SecurityContext::class)]
#[UsesClass(AuthenticationFailure::class)]
#[UsesClass(AuthenticationOutcome::class)]
#[UsesClass(ImmutableData::class)]
#[UsesClass(Principal::class)]
#[UsesClass(SecurityCode::class)]
final class SecurityContextTest extends TestCase
{
    public function testExposesTheAuthenticatedPrincipalFromItsAuthenticationOutcome(): void
    {
        $principal = new Principal('user-42');
        $authentication = AuthenticationOutcome::authenticated($principal);
        $context = SecurityContext::fromAuthentication($authentication);

        $this->assertSame($authentication, $context->authentication());
        $this->assertTrue($context->isAuthenticated());
        $this->assertSame($principal, $context->principal());
    }

    public function testKeepsAnAuthenticationFailureWithoutInventingAPrincipal(): void
    {
        $authentication = AuthenticationOutcome::failed(new AuthenticationFailure('missing_credential'));
        $context = SecurityContext::fromAuthentication($authentication);

        $this->assertFalse($context->isAuthenticated());
        $this->assertNull($context->principal());
        $this->assertSame('missing_credential', $context->authentication()->failure()?->code);
    }
}
