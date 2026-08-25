<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authentication;

use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Exception\InvalidSecurityValue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Credential::class)]
#[CoversClass(InvalidSecurityValue::class)]
final class CredentialTest extends TestCase
{
    public function testNormalizesTheCaseInsensitiveSchemeAndPreservesTheCredentialValue(): void
    {
        $credential = new Credential(' Bearer ', 'token-value');

        $this->assertSame('bearer', $credential->scheme);
        $this->assertSame('token-value', $credential->value());
    }

    public function testRejectsAnEmptyScheme(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Credential scheme must not be empty.'));

        new Credential('  ', 'token-value');
    }

    public function testRejectsAnEmptyValue(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Credential value must not be empty.'));

        new Credential('bearer', " \n");
    }
}
