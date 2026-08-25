<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http\Exception;

use DomainFlow\Security\SecurityContext;
use RuntimeException;

final class SecurityEndpointInvocationException extends RuntimeException
{
    public static function missingContext(object $endpoint): self
    {
        return new self(sprintf(
            'Security-aware endpoint %s requires a SecurityContext.',
            $endpoint::class,
        ));
    }

    public static function forContext(object $context): self
    {
        return new self(sprintf(
            'Security-aware endpoints require %s, %s given.',
            SecurityContext::class,
            $context::class,
        ));
    }
}
