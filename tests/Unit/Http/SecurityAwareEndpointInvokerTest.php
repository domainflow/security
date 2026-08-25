<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Http;

use DomainFlow\Http\Endpoint\EndpointInvoker;
use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Http\Exception\SecurityEndpointInvocationException;
use DomainFlow\Security\Http\SecurityAwareEndpoint;
use DomainFlow\Security\Http\SecurityAwareEndpointInvoker;
use DomainFlow\Security\Internal\ImmutableData;
use DomainFlow\Security\Internal\SecurityCode;
use DomainFlow\Security\Principal;
use DomainFlow\Security\SecurityContext;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use stdClass;

#[CoversClass(SecurityAwareEndpointInvoker::class)]
#[CoversClass(SecurityEndpointInvocationException::class)]
#[UsesClass(AuthenticationFailure::class)]
#[UsesClass(AuthenticationOutcome::class)]
#[UsesClass(ImmutableData::class)]
#[UsesClass(Principal::class)]
#[UsesClass(SecurityCode::class)]
#[UsesClass(SecurityContext::class)]
final class SecurityAwareEndpointInvokerTest extends TestCase
{
    public function testPassesTheDtoAndContextToTheSecurityAwareEndpoint(): void
    {
        $request = new RequestDto('order-1');
        $context = SecurityContext::fromAuthentication(
            AuthenticationOutcome::authenticated(new Principal('user-1')),
        );
        $endpoint = new StubSecurityAwareEndpoint();

        $result = (new SecurityAwareEndpointInvoker(new StubFallbackInvoker()))->invokeWithContext(
            $endpoint,
            $request,
            RequestDto::class,
            $context,
        );

        $this->assertSame('order-1:user-1', $result);
        $this->assertSame($request, $endpoint->request);
        $this->assertSame($context, $endpoint->context);
    }

    public function testPassesNullForAnOperationWithoutARequestDto(): void
    {
        $context = SecurityContext::fromAuthentication(
            AuthenticationOutcome::failed(new AuthenticationFailure('missing')),
        );
        $endpoint = new StubSecurityAwareEndpoint();

        $this->assertSame(
            null,
            (new SecurityAwareEndpointInvoker(new StubFallbackInvoker()))->invokeWithContext(
                $endpoint,
                null,
                null,
                $context,
            ),
        );
        $this->assertNull($endpoint->request);
        $this->assertSame($context, $endpoint->context);
    }

    public function testDelegatesNonSecurityEndpointsToTheRegularInvoker(): void
    {
        $invoker = new SecurityAwareEndpointInvoker(new StubFallbackInvoker());

        $this->assertSame(
            'fallback',
            $invoker->invokeWithContext(
                new stdClass(),
                null,
                null,
                new stdClass(),
            ),
        );
    }

    public function testKeepsTheRegularEndpointInvokerContract(): void
    {
        $invoker = new SecurityAwareEndpointInvoker(new StubFallbackInvoker());

        $this->assertSame('fallback', $invoker->invoke(new stdClass(), null, null));
    }

    public function testRejectsASecurityAwareEndpointWithoutAContext(): void
    {
        $this->expectException(SecurityEndpointInvocationException::class);

        (new SecurityAwareEndpointInvoker(new StubFallbackInvoker()))->invoke(
            new StubSecurityAwareEndpoint(),
            null,
            null,
        );
    }

    public function testRejectsAnUnexpectedContextForASecurityAwareEndpoint(): void
    {
        $this->expectException(SecurityEndpointInvocationException::class);

        (new SecurityAwareEndpointInvoker(new StubFallbackInvoker()))->invokeWithContext(
            new StubSecurityAwareEndpoint(),
            null,
            null,
            new stdClass(),
        );
    }
}

final class RequestDto
{
    public function __construct(public readonly string $id)
    {
    }
}

final class StubFallbackInvoker implements EndpointInvoker
{
    public function invoke(object $endpoint, ?object $request, ?string $requestClass): mixed
    {
        return 'fallback';
    }
}

final class StubSecurityAwareEndpoint implements SecurityAwareEndpoint
{
    public ?object $request = null;
    public ?SecurityContext $context = null;

    public function invokeWithSecurityContext(?object $request, SecurityContext $context): mixed
    {
        $this->request = $request;
        $this->context = $context;

        return $request instanceof RequestDto && $context->principal() !== null
            ? $request->id . ':' . $context->principal()->identifier
            : null;
    }
}
