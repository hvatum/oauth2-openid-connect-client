<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

use League\OAuth2\Client\Tool\RequestFactory;

/**
 * Test helper that creates IssuerAudienceTestProvider instances
 * for testing the getClientAssertionAudience() override.
 */
final class IssuerAudienceTestHelper
{
    public static function fullProvider(array $responses, array &$history, array $options = []): IssuerAudienceTestProvider
    {
        // Auto-generate client assertion key if not provided
        if (!isset($options['privateKeyPath'])) {
            [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();
            $resource = openssl_pkey_get_private($privateKey);
            $details = openssl_pkey_get_details($resource);
            $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
            $jwk['kid'] = 'test-client-key';
            $options['privateKeyPath'] = TestHelper::createTempKeyFile(json_encode($jwk));
        }

        // Auto-generate DPoP keys if not provided
        if (!isset($options['dpopPrivateKeyPath']) || !isset($options['dpopPublicKeyPath'])) {
            [$dpopPriv, $dpopPub, ] = TestHelper::generateEcKeyPair();
            $options['dpopPrivateKeyPath'] = TestHelper::createTempKeyFile($dpopPriv);
            $options['dpopPublicKeyPath'] = TestHelper::createTempKeyFile($dpopPub);
        }

        unset($options['clientSecret']);

        $httpClient = TestHelper::httpClient($responses, $history);
        $requestFactory = new RequestFactory();

        return new IssuerAudienceTestProvider(array_merge([
            'clientId' => 'client-123',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'cacheDir' => sys_get_temp_dir() . '/oauth2-oidc-tests-' . uniqid(),
        ], $options), [
            'httpClient' => $httpClient,
            'requestFactory' => $requestFactory,
        ]);
    }
}
