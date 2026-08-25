<?php

declare(strict_types=1);

namespace DomainFlow\Security\Http;

use Psr\Http\Message\ResponseInterface;

interface SecurityFailureResponseFactory
{
    public function unauthorized(): ResponseInterface;

    public function forbidden(): ResponseInterface;
}
