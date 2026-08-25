# DomainFlow Security

[![Tests](https://github.com/domainflow/security/actions/workflows/tests.yml/badge.svg)](https://github.com/domainflow/security/actions/workflows/tests.yml)
![Packagist Version](https://img.shields.io/packagist/v/domainflow/security)
![PHP Version](https://img.shields.io/packagist/php-v/domainflow/security)
![License](https://img.shields.io/github/license/domainflow/security)
![PHPStan](https://img.shields.io/badge/PHPStan-Level%210-brightgreen.svg)


Framework-neutral authentication and authorization contracts for DomainFlow
applications, with PSR-compatible HTTP adapters.

`domainflow/security` answers two questions without choosing a framework or
identity provider:

- Who is calling? An `Authenticator` turns a credential into an immutable
  `AuthenticationOutcome` and `Principal`.
- May that caller perform an operation? An `AuthorizationPolicy` evaluates a
  `SecurityContext` and an `AuthorizationRequirement`.

The package supports application-owned adapters for API keys, OAuth/OIDC,
JWT, Keycloak, Symfony Security, Laravel guards, sessions, mTLS, or custom
providers. Provider libraries and provider objects stay outside the base
package.

## Install

```sh
composer require domainflow/security
```

PHP 8.4+ and the PSR HTTP message/server/factory contracts are required. A
concrete PSR-7 implementation, such as Nyholm PSR-7, belongs to the
application.

Optional integrations:

- `domainflow/core` registers configured security services during bootstrap.
- `domainflow/http` provides the generic endpoint-context seam and HTTP kernel.
- `domainflow/openapi` can describe operation security requirements.

## Authentication and authorization

Implement the stable ports in the application or an adapter package:

```php
use DomainFlow\Security\Authentication\AuthenticationFailure;
use DomainFlow\Security\Authentication\AuthenticationOutcome;
use DomainFlow\Security\Authentication\Authenticator;
use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Principal;

final readonly class ApiTokenAuthenticator implements Authenticator
{
    public function authenticate(Credential $credential): AuthenticationOutcome
    {
        $identifier = $this->lookup($credential->value());

        return $identifier === null
            ? AuthenticationOutcome::failed(new AuthenticationFailure('invalid_credentials'))
            : AuthenticationOutcome::authenticated(new Principal($identifier));
    }

    private function lookup(string $token): ?string
    {
        // Delegate token verification to the application/provider adapter.
        return $token === 'example-token' ? 'service-1' : null;
    }
}
```

The raw credential is never placed in the `Principal`. Authorization remains
an explicit application policy:

```php
use DomainFlow\Security\Authorization\AuthorizationRequirement;

$requirement = new AuthorizationRequirement(
    'orders.read',
    ['scheme' => 'oauth2', 'scopes' => ['orders:read']],
);
$decision = $policy->decide($context, $requirement);
```


## Provider examples

The `examples/` directory contains dependency-free seams for custom token
stores, Keycloak/OIDC claim verification, Symfony Security identity mapping,
and Laravel guard identity mapping. Replace the example verifier/guard ports
with the concrete provider package in your application. The base package does
not install those providers.

## Development

```sh
composer test-all
composer phpstan
composer lint
composer quality
```

The package targets PHP 8.4 and 8.5, PHPStan level 10, strict formatting,
dependency auditing, and full reachable-source line coverage.

## License

MIT license.
