<?php

declare(strict_types=1);

namespace DomainFlow\Security\Examples\Laravel;

use DomainFlow\Security\Authentication\Credential;

/** Application-owned port around a Laravel guard or Sanctum/Passport adapter. */
interface LaravelGuard
{
    /** @return array<string, mixed>|null */
    public function identityFor(Credential $credential): ?array;
}
