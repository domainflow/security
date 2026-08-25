<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authorization;

use DomainFlow\Security\Authorization\AuthorizationDecision;
use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\SecurityCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthorizationDecision::class)]
#[CoversClass(InvalidSecurityValue::class)]
#[CoversClass(SecurityCode::class)]
final class AuthorizationDecisionTest extends TestCase
{
    public function testCreatesAnAllowDecisionWithoutAReason(): void
    {
        $decision = AuthorizationDecision::allow();

        $this->assertTrue($decision->isGranted());
        $this->assertNull($decision->reason());
    }

    public function testCreatesADenyDecisionWithASafeReasonCode(): void
    {
        $decision = AuthorizationDecision::deny('insufficient_scope');

        $this->assertFalse($decision->isGranted());
        $this->assertSame('insufficient_scope', $decision->reason());
    }

    public function testAReasonIsOptionalForADenyDecision(): void
    {
        $this->assertNull(AuthorizationDecision::deny()->reason());
    }

    public function testRejectsAnUnsafeDenyReason(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Authorization decision reason must be a lowercase security code.'));

        AuthorizationDecision::deny(' ');
    }
}
