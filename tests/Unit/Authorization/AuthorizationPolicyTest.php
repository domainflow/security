<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authorization;

use DomainFlow\Security\Authorization\AuthorizationDecision;
use DomainFlow\Security\Authorization\AuthorizationPolicy;
use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\SecurityContext;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class AuthorizationPolicyTest extends TestCase
{
    public function testAnApplicationPolicyCanImplementTheFrameworkNeutralPolicyPort(): void
    {
        $policy = new class() implements AuthorizationPolicy {
            public function decide(
                SecurityContext $context,
                AuthorizationRequirement $requirement,
            ): AuthorizationDecision {
                return AuthorizationDecision::allow();
            }
        };

        $decision = $policy->decide(
            SecurityContext::fromAuthentication(
                \DomainFlow\Security\Authentication\AuthenticationOutcome::authenticated(
                    new \DomainFlow\Security\Principal('user-42'),
                ),
            ),
            new AuthorizationRequirement('orders.read'),
        );

        $this->assertTrue($decision->isGranted());
    }
}
