<?php

declare(strict_types=1);

namespace DomainFlow\Security\OpenApi;

use DomainFlow\Security\Authorization\AuthorizationRequirement;
use DomainFlow\Security\Exception\InvalidSecurityValue;

/**
 * Framework-neutral representation of one OpenAPI Security Requirement
 * Object. The OpenAPI package can consume toOpenApi() without runtime auth.
 */
final readonly class OpenApiSecurityRequirement
{
    /**
     * @var list<string>
     */
    public readonly array $scopes;

    /**
     * @param array<array-key, mixed> $scopes
     */
    public function __construct(
        public string $scheme,
        array $scopes = [],
    ) {
        if (trim($scheme) === '') {
            throw new InvalidSecurityValue('OpenAPI security scheme must not be empty.');
        }

        $this->scopes = self::validatedScopes($scopes);
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @return list<string>
     */
    private static function validatedScopes(array $scopes): array
    {
        if (!array_is_list($scopes)) {
            throw new InvalidSecurityValue('OpenAPI security scopes must be a list.');
        }

        $validated = [];
        foreach ($scopes as $scope) {
            if (!is_string($scope)) {
                throw new InvalidSecurityValue('OpenAPI security scopes must contain strings.');
            }

            if (trim($scope) === '') {
                throw new InvalidSecurityValue('OpenAPI security scope must not be empty.');
            }

            $validated[] = $scope;
        }

        return $validated;
    }

    public static function fromAuthorizationRequirement(AuthorizationRequirement $requirement): self
    {
        $scheme = $requirement->parameter('scheme') ?? $requirement->name;
        if (!is_string($scheme)) {
            throw new InvalidSecurityValue('Authorization security scheme must be a string.');
        }

        $scopes = $requirement->parameter('scopes') ?? [];
        if (!is_array($scopes) || !array_is_list($scopes)) {
            throw new InvalidSecurityValue('Authorization security scopes must be a list.');
        }

        foreach ($scopes as $scope) {
            if (!is_string($scope)) {
                throw new InvalidSecurityValue('Authorization security scopes must contain strings.');
            }
        }

        return new self($scheme, $scopes);
    }

    /** @return array<string, list<string>> */
    public function toOpenApi(): array
    {
        return [$this->scheme => $this->scopes];
    }
}
