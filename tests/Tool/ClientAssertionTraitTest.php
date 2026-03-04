<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Tool;

use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;

final class ClientAssertionTraitTest extends TestCase
{
    public function testClientAssertionAudienceUsesTokenEndpointUrl(): void
    {
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();

        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwk['kid'] = 'kid-1';

        $privPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'privateKeyPath' => $privPath,
            'keyId' => 'kid-1',
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string)$request->getBody();
        parse_str($body, $params);

        self::assertArrayNotHasKey('client_secret', $params);

        $assertion = $params['client_assertion'] ?? '';
        $payloadB64 = explode('.', $assertion)[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);

        // Audience should be the token endpoint URL (RFC 7523 Section 3)
        self::assertSame('https://idp.test/oauth2/token', $payload['aud']);
        self::assertSame('client-123', $payload['iss']);
        self::assertSame('client-123', $payload['sub']);
    }

    public function testRsaKeyDefaultsToRs256(): void
    {
        [, $jwk] = $this->generateRsaPrivateJwk('rsa-test');
        $jwkPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $jwkPath,
            'keyId' => $jwk['kid'],
        ]);

        $request = $provider->debugAccessTokenRequestFromGrant('client_credentials');
        parse_str((string)$request->getBody(), $params);

        $assertion = $params['client_assertion'] ?? '';
        $headerB64 = explode('.', $assertion)[0];
        $header = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);

        // Generic package: RSA without explicit alg defaults to RS256
        self::assertSame('RS256', $header['alg']);
    }

    public function testMissingKeyTypeGivesHelpfulError(): void
    {
        $jwkPath = TestHelper::createTempKeyFile(json_encode(['kid' => 'no-kty']));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $jwkPath,
            'keyId' => 'no-kty',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported or missing key type (kty) in JWK');

        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    public function testExplicitRs384AlgorithmIsUsed(): void
    {
        [, $jwk] = $this->generateRsaPrivateJwk('rs384-test');
        $jwk['alg'] = 'RS384';
        $jwkPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $jwkPath,
            'keyId' => $jwk['kid'],
        ]);

        $request = $provider->debugAccessTokenRequestFromGrant('client_credentials');
        parse_str((string)$request->getBody(), $params);

        $assertion = $params['client_assertion'] ?? '';
        $headerB64 = explode('.', $assertion)[0];
        $header = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);

        self::assertSame('RS384', $header['alg']);
    }

    public function testForbiddenAlgorithmThrowsError(): void
    {
        [, $jwk] = $this->generateRsaPrivateJwk('forbidden-alg-test');
        $jwk['alg'] = 'HS256';
        $jwkPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $jwkPath,
            'keyId' => $jwk['kid'],
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not allowed');

        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    public function testExplicitPs256AlgorithmIsUsed(): void
    {
        // Real test JWK with explicit PS256 algorithm
        [, $jwk] = $this->generateRsaPrivateJwk('ps256-test');
        $jwk['alg'] = 'PS256';
        $jwkPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $jwkPath,
            'keyId' => $jwk['kid'],
        ]);

        $request = $provider->debugAccessTokenRequestFromGrant('client_credentials');
        parse_str((string)$request->getBody(), $params);

        $assertion = $params['client_assertion'] ?? '';
        $headerB64 = explode('.', $assertion)[0];
        $header = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);

        self::assertSame('PS256', $header['alg']);
    }

    public function testEcPkcs8PemKeyDetectedAsEs256(): void
    {
        // Generate EC key — openssl_pkey_export produces PKCS#8 format
        // ("-----BEGIN PRIVATE KEY-----") by default for EC keys
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        openssl_pkey_export($resource, $privateKeyPem);

        // Verify this is indeed a PKCS#8 PEM (generic header, not "EC PRIVATE KEY")
        self::assertStringContainsString('-----BEGIN PRIVATE KEY-----', $privateKeyPem);
        self::assertStringNotContainsString('EC PRIVATE KEY', $privateKeyPem);

        $pemPath = TestHelper::createTempKeyFile($privateKeyPem);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $pemPath,
            'keyId' => 'ec-pkcs8-test',
        ]);

        $request = $provider->debugAccessTokenRequestFromGrant('client_credentials');
        parse_str((string)$request->getBody(), $params);

        $assertion = $params['client_assertion'] ?? '';
        $headerB64 = explode('.', $assertion)[0];
        $header = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);

        // Must use ES256, not RS256 — this was the bug
        self::assertSame('ES256', $header['alg']);
    }

    public function testMissingPrivateKeyFileThrowsError(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => '/tmp/does-not-exist-' . bin2hex(random_bytes(8)),
            'keyId' => 'missing-file',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Private key file not found');
        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    public function testJwkSetJsonThrowsError(): void
    {
        $jwkSetPath = TestHelper::createTempKeyFile(json_encode([
            'keys' => [],
        ]));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $jwkSetPath,
            'keyId' => 'set-key',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported or missing key type');
        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    public function testUnsupportedJwkKeyTypeThrowsError(): void
    {
        $octPath = TestHelper::createTempKeyFile(json_encode([
            'kty' => 'oct',
            'k' => 'AQAB',
            'kid' => 'oct-key',
        ]));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $octPath,
            'keyId' => 'oct-key',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported or missing key type');
        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    // ── token_endpoint_auth_signing_alg_values_supported tests ──

    public function testAssertionAlgAcceptedWhenInServerList(): void
    {
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();

        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwk['kid'] = 'kid-1';

        $privPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_signing_alg_values_supported' => ['ES256', 'RS256'],
            ]),
            TestHelper::tokenResponse(),
        ], $history, [
            'privateKeyPath' => $privPath,
            'keyId' => 'kid-1',
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string) $request->getBody();
        parse_str($body, $params);
        self::assertArrayHasKey('client_assertion', $params);
    }

    public function testAssertionAlgAcceptedWhenServerListsAll9(): void
    {
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();

        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwk['kid'] = 'kid-1';

        $privPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_signing_alg_values_supported' => [
                    'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                ],
            ]),
            TestHelper::tokenResponse(),
        ], $history, [
            'privateKeyPath' => $privPath,
            'keyId' => 'kid-1',
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string) $request->getBody();
        parse_str($body, $params);
        self::assertArrayHasKey('client_assertion', $params);
    }

    public function testAssertionAlgRejectedWhenNotInServerList(): void
    {
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();

        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwk['kid'] = 'kid-1';

        $privPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            ]),
        ], $history, [
            'privateKeyPath' => $privPath,
            'keyId' => 'kid-1',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Client assertion algorithm "ES256" is not supported by the authorization server');
        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    public function testAssertionAlgSkipsValidationWhenNotAdvertised(): void
    {
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();

        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwk['kid'] = 'kid-1';

        $privPath = TestHelper::createTempKeyFile(json_encode($jwk));

        $history = [];
        // Default wellKnownResponse has no token_endpoint_auth_signing_alg_values_supported
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'privateKeyPath' => $privPath,
            'keyId' => 'kid-1',
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string) $request->getBody();
        parse_str($body, $params);
        self::assertArrayHasKey('client_assertion', $params);
    }

    private function generateRsaPrivateJwk(string $kid): array
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($resource === false) {
            self::fail('Failed to generate RSA key pair for test');
        }

        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);

        $rsa = $details['rsa'];

        $jwk = [
            'kty' => 'rsa', // intentionally lowercase to verify normalization
            'kid' => $kid,
            'n' => $this->base64UrlEncode($rsa['n']),
            'e' => $this->base64UrlEncode($rsa['e']),
            'd' => $this->base64UrlEncode($rsa['d']),
            'p' => $this->base64UrlEncode($rsa['p']),
            'q' => $this->base64UrlEncode($rsa['q']),
            'dp' => $this->base64UrlEncode($rsa['dmp1']),
            'dq' => $this->base64UrlEncode($rsa['dmq1']),
            'qi' => $this->base64UrlEncode($rsa['iqmp']),
        ];

        return [$privateKey, $jwk];
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
