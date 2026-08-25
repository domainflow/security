<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authorization;

use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\ImmutableData;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthorizationRequirement::class)]
#[CoversClass(InvalidSecurityValue::class)]
#[UsesClass(ImmutableData::class)]
final class AuthorizationRequirementTest extends TestCase
{
    public function testStoresARequirementNameAndItsProviderNeutralParameters(): void
    {
        $requirement = new AuthorizationRequirement('orders.read', ['scope' => 'orders:read']);

        $this->assertSame('orders.read', $requirement->name);
        $this->assertSame(['scope' => 'orders:read'], $requirement->parameters());
        $this->assertSame('orders:read', $requirement->parameter('scope'));
        $this->assertTrue($requirement->hasParameter('scope'));
        $this->assertFalse($requirement->hasParameter('permission'));
        $this->assertNull($requirement->parameter('permission'));
    }

    public function testRejectsAnEmptyRequirementName(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Authorization requirement name must not be empty.'));

        new AuthorizationRequirement(' ', []);
    }

    public function testRejectsNonStringParameterNames(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Authorization parameter names must be non-empty strings.'));

        new AuthorizationRequirement('orders.read', $this->invalidParameters());
    }

    /**
     * @return array<array-key, mixed>
     */
    private function invalidParameters(): array
    {
        return [42 => 'invalid'];
    }
}
