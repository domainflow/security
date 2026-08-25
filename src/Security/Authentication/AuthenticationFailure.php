<?php

declare(strict_types=1);

namespace DomainFlow\Security\Authentication;

use DomainFlow\Security\Internal\SecurityCode;

final readonly class AuthenticationFailure
{
    public function __construct(public string $code)
    {
        SecurityCode::assert($code, 'Authentication failure code');
    }
}
