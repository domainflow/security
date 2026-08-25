<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Http;

use DomainFlow\Security\Http\PsrSecurityFailureResponseFactory;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PsrSecurityFailureResponseFactory::class)]
final class PsrSecurityFailureResponseFactoryTest extends TestCase
{
    public function testCreatesAnUnauthorizedResponseWithTheConfiguredChallenge(): void
    {
        $response = (new PsrSecurityFailureResponseFactory(new Psr17Factory(), 'Bearer'))->unauthorized();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(['Bearer'], $response->getHeader('WWW-Authenticate'));
        $this->assertSame('', (string) $response->getBody());
    }

    public function testCanCreateAnUnauthorizedResponseWithoutAChallenge(): void
    {
        $response = (new PsrSecurityFailureResponseFactory(new Psr17Factory(), null))->unauthorized();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($response->hasHeader('WWW-Authenticate'));
    }

    public function testCreatesAnEmptyForbiddenResponse(): void
    {
        $response = (new PsrSecurityFailureResponseFactory(new Psr17Factory()))->forbidden();

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('', (string) $response->getBody());
    }
}
