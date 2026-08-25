<?php

declare(strict_types=1);

namespace DomainFlow\Security\Tests\Unit\Http;

use DomainFlow\Security\Authentication\Credential;
use DomainFlow\Security\Http\AuthorizationHeaderCredentialExtractor;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthorizationHeaderCredentialExtractor::class)]
#[UsesClass(Credential::class)]
final class AuthorizationHeaderCredentialExtractorTest extends TestCase
{
    public function testExtractsTheSchemeAndValueFromAnAuthorizationHeader(): void
    {
        $credential = (new AuthorizationHeaderCredentialExtractor())->extract(
            new ServerRequest('GET', '/', ['Authorization' => 'Bearer token-value']),
        );

        $this->assertInstanceOf(Credential::class, $credential);
        $this->assertSame('bearer', $credential->scheme);
        $this->assertSame('token-value', $credential->value());
    }

    public function testReturnsNullWhenTheAuthorizationHeaderIsMissing(): void
    {
        $this->assertNull(
            (new AuthorizationHeaderCredentialExtractor())->extract(new ServerRequest('GET', '/')),
        );
    }

    public function testReturnsNullForAHeaderWithoutAValue(): void
    {
        $this->assertNull(
            (new AuthorizationHeaderCredentialExtractor())->extract(
                new ServerRequest('GET', '/', ['Authorization' => 'Bearer']),
            ),
        );
    }
}
