<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Http;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authorization\AuthorizationDecision;
use DomainFlow\Security\Authorization\AuthorizationPolicy;
use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\Http\AuthorizationMiddleware;
use DomainFlow\Security\Http\PsrSecurityFailureResponseFactory;
use DomainFlow\Security\Http\SecurityContextAttribute;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\Internal\SecurityCode;
use DomainFlow\Security\Principal;
use DomainFlow\Security\SecurityContext;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

#[CoversClass(AuthorizationMiddleware::class)]
#[UsesClass(AuthenticationFailure::class)]
#[UsesClass(AuthenticationOutcome::class)]
#[UsesClass(AuthorizationDecision::class)]
#[UsesClass(AuthorizationRequirement::class)]
#[UsesClass(ImmutableData::class)]
#[UsesClass(SecurityCode::class)]
#[UsesClass(SecurityContext::class)]
#[UsesClass(SecurityContextAttribute::class)]
#[UsesClass(Principal::class)]
#[UsesClass(PsrSecurityFailureResponseFactory::class)]
final class AuthorizationMiddlewareTest extends TestCase
{
    public function testPassesAnAuthenticatedRequestWhenThePolicyAllowsIt(): void
    {
        $context = $this->authenticatedContext();
        $requirement = new AuthorizationRequirement('orders.read');
        $request = (new ServerRequest('GET', '/orders'))
            ->withAttribute(SecurityContextAttribute::NAME, $context);
        $response = (new Psr17Factory())->createResponse(204);
        $policy = $this->createMock(AuthorizationPolicy::class);
        $policy->expects($this->once())
            ->method('decide')
            ->with($context, $requirement)
            ->willReturn(AuthorizationDecision::allow());
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($request)->willReturn($response);

        $result = (new AuthorizationMiddleware(
            $policy,
            $requirement,
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            $request,
            $handler,
        );

        $this->assertSame($response, $result);
    }

    public function testReturnsForbiddenWhenAnAuthenticatedRequestIsDenied(): void
    {
        $context = $this->authenticatedContext();
        $requirement = new AuthorizationRequirement('orders.write');
        $request = (new ServerRequest('POST', '/orders'))
            ->withAttribute(SecurityContextAttribute::NAME, $context);
        $policy = $this->createStub(AuthorizationPolicy::class);
        $policy->method('decide')->willReturn(AuthorizationDecision::deny('insufficient_scope'));
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $response = (new AuthorizationMiddleware(
            $policy,
            $requirement,
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            $request,
            $handler,
        );

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('', (string) $response->getBody());
    }

    public function testReturnsUnauthorizedWhenNoSecurityContextWasEstablished(): void
    {
        $policy = $this->createMock(AuthorizationPolicy::class);
        $policy->expects($this->never())->method('decide');
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $response = (new AuthorizationMiddleware(
            $policy,
            new AuthorizationRequirement('orders.read'),
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            new ServerRequest('GET', '/orders'),
            $handler,
        );

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testReturnsUnauthorizedWhenTheSecurityContextIsAnonymous(): void
    {
        $request = (new ServerRequest('GET', '/orders'))->withAttribute(
            SecurityContextAttribute::NAME,
            SecurityContext::fromAuthentication(
                AuthenticationOutcome::failed(new AuthenticationFailure('missing_credential')),
            ),
        );
        $policy = $this->createMock(AuthorizationPolicy::class);
        $policy->expects($this->never())->method('decide');
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $response = (new AuthorizationMiddleware(
            $policy,
            new AuthorizationRequirement('orders.read'),
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            $request,
            $handler,
        );

        $this->assertSame(401, $response->getStatusCode());
    }

    private function authenticatedContext(): SecurityContext
    {
        return SecurityContext::fromAuthentication(
            AuthenticationOutcome::authenticated(new Principal('user-42')),
        );
    }
}
