<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Token\AccessToken;
use Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider;

/**
 * Test double to bypass strict token construction while still exercising request logic.
 */
class TestProvider extends OpenIDConnectProvider
{
    public function debugAccessTokenRequest(array $params)
    {
        return $this->getAccessTokenRequest($params);
    }

    public function debugAccessTokenRequestFromGrant($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);

        if (isset($options['scope']) && is_array($options['scope'])) {
            $options['scope'] = implode($this->getScopeSeparator(), $options['scope']);
        }

        $params = [
            'client_id' => 'client-123',
            'redirect_uri' => 'https://app.example/callback',
        ];

        if (!empty($this->pkceCode)) {
            $params['code_verifier'] = $this->pkceCode;
        }

        $params = $grant->prepareRequestParameters($params, $options);

        return $this->debugAccessTokenRequest($params);
    }

    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        $response['access_token'] = $response['access_token'] ?? 'test-token';
        return new AccessToken($response);
    }
}
