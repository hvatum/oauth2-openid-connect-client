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
