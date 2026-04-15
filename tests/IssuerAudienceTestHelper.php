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
        // Auto-generate client assertion key if neither option is provided
        if (!isset($options['privateKeyPath']) && !isset($options['privateKey'])) {
            [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();
            $resource = openssl_pkey_get_private($privateKey);
            $details = openssl_pkey_get_details($resource);
            $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
            $jwk['kid'] = 'test-client-key';
            $options['privateKeyPath'] = TestHelper::createTempKeyFile(json_encode($jwk));
        }

        // Auto-generate DPoP keys ONLY when nothing is configured. See the
        // matching note in TestHelper::fullProvider — partial injection would
        // mask the derive-from-private path and create mismatched key pairs.
        $dpopPrivateConfigured = isset($options['dpopPrivateKeyPath']) || isset($options['dpopPrivateKey']);
        $dpopPublicConfigured = isset($options['dpopPublicKeyPath']) || isset($options['dpopPublicKey']);
        if (!$dpopPrivateConfigured && !$dpopPublicConfigured) {
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
