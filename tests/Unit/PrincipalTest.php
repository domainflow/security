<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit;

use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\Principal;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use stdClass;

#[CoversClass(Principal::class)]
#[CoversClass(InvalidSecurityValue::class)]
#[CoversClass(ImmutableData::class)]
final class PrincipalTest extends TestCase
{
    public function testStoresAnApplicationIdentityAndNormalizedAttributes(): void
    {
        $principal = new Principal('user-42', [
            'tenant' => 'acme',
            'active' => true,
            'roles' => ['reader'],
        ]);

        $this->assertSame('user-42', $principal->identifier);
        $this->assertSame(['tenant' => 'acme', 'active' => true, 'roles' => ['reader']], $principal->attributes());
        $this->assertSame('acme', $principal->attribute('tenant'));
        $this->assertTrue($principal->hasAttribute('active'));
        $this->assertFalse($principal->hasAttribute('missing'));
        $this->assertNull($principal->attribute('missing'));
    }

    public function testRejectsAnEmptyIdentifier(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Principal identifier must not be empty.'));

        new Principal(' ');
    }

    public function testRejectsNonStringAttributeNames(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Principal attribute names must be non-empty strings.'));

        new Principal('user-42', $this->invalidAttributes());
    }

    public function testRejectsEmptyAttributeNames(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Principal attribute names must be non-empty strings.'));

        new Principal('user-42', ['' => 'invalid']);
    }

    public function testRejectsMutableObjectsInAttributes(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Principal attribute values must not contain mutable objects or resources.'));

        new Principal('user-42', ['provider_claim' => new stdClass()]);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function invalidAttributes(): array
    {
        return [42 => 'invalid'];
    }
}
