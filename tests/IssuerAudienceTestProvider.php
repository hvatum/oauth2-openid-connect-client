<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

/**
 * Test double that overrides client assertion audience to use the issuer URL.
 * Used to verify that subclasses can customize the audience via getClientAssertionAudience().
 */
final class IssuerAudienceTestProvider extends TestProvider
{
    protected function getClientAssertionAudience(): string
    {
        return $this->issuerUrl;
    }
}
