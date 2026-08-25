<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\OpenApi;

use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\OpenApi\OpenApiSecurityRequirement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OpenApiSecurityRequirement::class)]
#[UsesClass(AuthorizationRequirement::class)]
#[UsesClass(ImmutableData::class)]
final class OpenApiSecurityRequirementTest extends TestCase
{
    public function testMapsAnAuthorizationRequirementToAnOpenApiObject(): void
    {
        $requirement = new AuthorizationRequirement('orders.read', [
            'scheme' => 'oauth2',
            'scopes' => ['orders:read'],
        ]);

        $security = OpenApiSecurityRequirement::fromAuthorizationRequirement($requirement);

        $this->assertSame('oauth2', $security->scheme);
        $this->assertSame(['orders:read'], $security->scopes);
        $this->assertSame(['oauth2' => ['orders:read']], $security->toOpenApi());
    }

    public function testUsesTheRequirementNameAsSchemeAndAllowsNoScopes(): void
    {
        $security = OpenApiSecurityRequirement::fromAuthorizationRequirement(
            new AuthorizationRequirement('bearer'),
        );

        $this->assertSame(['bearer' => []], $security->toOpenApi());
    }

    public function testRejectsInvalidSecurityParameters(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        OpenApiSecurityRequirement::fromAuthorizationRequirement(
            new AuthorizationRequirement('orders.read', ['scopes' => ['orders:read', 42]]),
        );
    }

    public function testRejectsAnEmptyScheme(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        new OpenApiSecurityRequirement('   ');
    }

    public function testRejectsAnEmptyScope(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        new OpenApiSecurityRequirement('oauth2', ['']);
    }

    public function testRejectsNonStringScopesAtThePublicConstructor(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        /** @var array<int, mixed> $scopes */
        $scopes = [42];
        new OpenApiSecurityRequirement('oauth2', $scopes);
    }

    public function testRejectsAssociativeScopesAtThePublicConstructor(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        /** @var array<int|string, string> $scopes */
        $scopes = ['read' => 'orders:read'];
        new OpenApiSecurityRequirement('oauth2', $scopes);
    }

    public function testRejectsANonStringSchemeParameter(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        OpenApiSecurityRequirement::fromAuthorizationRequirement(
            new AuthorizationRequirement('orders.read', ['scheme' => 42]),
        );
    }

    public function testRejectsNonListScopes(): void
    {
        $this->expectException(InvalidSecurityValue::class);

        OpenApiSecurityRequirement::fromAuthorizationRequirement(
            new AuthorizationRequirement('orders.read', ['scopes' => ['read' => 'orders:read']]),
        );
    }
}
