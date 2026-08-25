<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Http;

use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Http\SecurityContextAttribute;
use DomainFlow\Security\Http\SecurityContextRequestAttributeProvider;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\Principal;
use DomainFlow\Security\SecurityContext;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SecurityContextRequestAttributeProvider::class)]
#[UsesClass(AuthenticationOutcome::class)]
#[UsesClass(ImmutableData::class)]
#[UsesClass(Principal::class)]
#[UsesClass(SecurityContext::class)]
final class SecurityContextRequestAttributeProviderTest extends TestCase
{
    public function testReturnsTheSecurityContextRequestAttribute(): void
    {
        $context = SecurityContext::fromAuthentication(
            AuthenticationOutcome::authenticated(new Principal('user-1')),
        );
        $request = (new ServerRequest('GET', '/'))
            ->withAttribute(SecurityContextAttribute::NAME, $context);

        $this->assertSame($context, (new SecurityContextRequestAttributeProvider())->context($request));
    }

    public function testReturnsNullWhenTheAttributeIsMissingOrInvalid(): void
    {
        $provider = new SecurityContextRequestAttributeProvider();

        $this->assertNull($provider->context(new ServerRequest('GET', '/')));
        $this->assertNull(
            $provider->context(
                (new ServerRequest('GET', '/'))->withAttribute(SecurityContextAttribute::NAME, 'invalid'),
            ),
        );
    }
}
