<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Bridge\DomainFlowCore;

use DomainFlow\Application;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Authorization\AuthorizationDecision;
use DomainFlow\Security\Authorization\AuthorizationPolicy;
use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\Bridge\DomainFlowCore\SecurityServiceProvider;
use DomainFlow\Security\SecurityContext;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SecurityServiceProvider::class)]
final class SecurityServiceProviderTest extends TestCase
{
    public function test_registersConfiguredSecurityServicesAsInstances(): void
    {
        $authenticator = new StubAuthenticator();
        $policy = new StubAuthorizationPolicy();
        $app = new Application(sys_get_temp_dir());

        $provider = new SecurityServiceProvider($authenticator, $policy);
        $provider->register($app);

        $this->assertSame($authenticator, $app->get(Authenticator::class));
        $this->assertSame($policy, $app->get(AuthorizationPolicy::class));
    }

    public function test_registersOnlyTheConfiguredService(): void
    {
        $authenticator = new StubAuthenticator();
        $app = new Application(sys_get_temp_dir());
        $provider = new SecurityServiceProvider($authenticator);

        $provider->register($app);

        $this->assertSame([Authenticator::class], $provider->provides());
        $this->assertSame($authenticator, $app->get(Authenticator::class));
        $this->assertFalse($app->has(AuthorizationPolicy::class));
    }

    public function test_exposesConfiguredServiceKeysAndIsNotDeferred(): void
    {
        $provider = new SecurityServiceProvider(
            new StubAuthenticator(),
            new StubAuthorizationPolicy(),
        );

        $this->assertSame(
            [Authenticator::class, AuthorizationPolicy::class],
            $provider->provides(),
        );
        $this->assertFalse($provider->isDeferred());
    }

    public function test_bootDoesNotRegisterMiddlewareOrMutateTheCorePipeline(): void
    {
        $app = new Application(sys_get_temp_dir());
        $provider = new SecurityServiceProvider(new StubAuthenticator());
        $middleware = static fn (mixed $payload, callable $next): mixed => $next($payload);
        $app->useMiddleware($middleware);

        $provider->boot($app);

        $this->assertSame([$middleware], $app->getRegisteredMiddleware());
    }
}

final class StubAuthenticator implements Authenticator
{
    public function authenticate(Credential $credential): AuthenticationOutcome
    {
        throw new LogicException('Not used by the bridge test.');
    }
}

final class StubAuthorizationPolicy implements AuthorizationPolicy
{
    public function decide(
        SecurityContext $context,
        AuthorizationRequirement $requirement,
    ): AuthorizationDecision {
        throw new LogicException('Not used by the bridge test.');
    }
}
