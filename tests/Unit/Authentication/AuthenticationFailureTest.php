<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Authentication;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Exception\InvalidSecurityValue;
use DomainFlow\Security\Internal\SecurityCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthenticationFailure::class)]
#[CoversClass(InvalidSecurityValue::class)]
#[CoversClass(SecurityCode::class)]
final class AuthenticationFailureTest extends TestCase
{
    public function testStoresAStableNonSensitiveFailureCode(): void
    {
        $failure = new AuthenticationFailure('invalid_credential');

        $this->assertSame('invalid_credential', $failure->code);
    }

    public function testRejectsAnUnsafeFailureCode(): void
    {
        $this->expectExceptionObject(new InvalidSecurityValue('Authentication failure code must be a lowercase security code.'));

        new AuthenticationFailure(' ');
    }
}
