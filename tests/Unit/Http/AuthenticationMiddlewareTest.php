<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Http;

use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Http\AuthenticationMiddleware;
use DomainFlow\Security\Http\CredentialExtractor;
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
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[CoversClass(AuthenticationMiddleware::class)]
#[UsesClass(AuthenticationFailure::class)]
#[UsesClass(AuthenticationOutcome::class)]
#[UsesClass(Credential::class)]
#[UsesClass(ImmutableData::class)]
#[UsesClass(SecurityCode::class)]
#[UsesClass(SecurityContext::class)]
#[UsesClass(SecurityContextAttribute::class)]
#[UsesClass(Principal::class)]
#[UsesClass(PsrSecurityFailureResponseFactory::class)]
final class AuthenticationMiddlewareTest extends TestCase
{
    public function testPassesAnAuthenticatedSecurityContextToTheDownstreamHandler(): void
    {
        $credential = new Credential('bearer', 'token-value');
        $principal = new Principal('user-42');
        $response = (new Psr17Factory())->createResponse(204);

        $extractor = $this->createStub(CredentialExtractor::class);
        $extractor->method('extract')->willReturn($credential);
        $authenticator = $this->createStub(Authenticator::class);
        $authenticator->method('authenticate')->willReturn(AuthenticationOutcome::authenticated($principal));
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->with($this->callback(function (ServerRequestInterface $request) use ($principal): bool {
                $context = $request->getAttribute(SecurityContextAttribute::NAME);

                return $context instanceof SecurityContext
                    && $context->isAuthenticated()
                    && $context->principal() === $principal;
            }))
            ->willReturn($response);

        $result = (new AuthenticationMiddleware(
            $extractor,
            $authenticator,
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            new ServerRequest('GET', '/orders'),
            $handler,
        );

        $this->assertSame($response, $result);
    }

    public function testReturnsUnauthorizedWhenAuthenticationFailsWithoutLeakingTheFailureCode(): void
    {
        $extractor = $this->createStub(CredentialExtractor::class);
        $extractor->method('extract')->willReturn(new Credential('bearer', 'bad-token'));
        $authenticator = $this->createStub(Authenticator::class);
        $authenticator->method('authenticate')->willReturn(
            AuthenticationOutcome::failed(new AuthenticationFailure('invalid_credential')),
        );
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $response = (new AuthenticationMiddleware(
            $extractor,
            $authenticator,
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            new ServerRequest('GET', '/orders'),
            $handler,
        );

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(['Bearer'], $response->getHeader('WWW-Authenticate'));
        $this->assertSame('', (string) $response->getBody());
    }

    public function testReturnsUnauthorizedWhenNoCredentialWasExtracted(): void
    {
        $extractor = $this->createStub(CredentialExtractor::class);
        $extractor->method('extract')->willReturn(null);
        $authenticator = $this->createMock(Authenticator::class);
        $authenticator->expects($this->never())->method('authenticate');
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $response = (new AuthenticationMiddleware(
            $extractor,
            $authenticator,
            new PsrSecurityFailureResponseFactory(new Psr17Factory()),
        ))->process(
            new ServerRequest('GET', '/orders'),
            $handler,
        );

        $this->assertSame(401, $response->getStatusCode());
    }
}
