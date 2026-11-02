<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Test double whose token implements the interface without extending
 * League's AccessToken, which getAccessToken() must reject.
 */
final class InterfaceOnlyTokenTestProvider extends TestProvider
{
    protected function createAccessToken(array $response, AbstractGrant $grant): AccessTokenInterface
    {
        return \Mockery::mock(AccessTokenInterface::class);
    }
}
