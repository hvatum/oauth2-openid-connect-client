<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

/**
 * Test double that overrides the client assertion audience to the token
 * endpoint URL — the legacy RFC 7523 §3 / OIDC Core §9 value, kept as an
 * escape hatch for servers that have not moved to rfc7523bis. Used to verify
 * that subclasses can still customize the audience via
 * getClientAssertionAudience().
 */
final class TokenEndpointAudienceTestProvider extends TestProvider
{
    protected function getClientAssertionAudience(): string
    {
        return $this->tokenUrl;
    }
}
