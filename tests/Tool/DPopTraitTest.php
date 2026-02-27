<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Tool;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;

final class DPopTraitTest extends TestCase
{
    public function testTokenRequestIncludesDpopProofAndThumbprint(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('test-verifier');
        $tokenRequest = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string)$tokenRequest->getBody();
        parse_str($body, $params);
        self::assertSame($provider->getDPopJwkThumbprint(), $params['dpop_jkt']);

        $dpopHeader = $tokenRequest->getHeaderLine('DPoP');
        self::assertNotEmpty($dpopHeader);

        $payloadB64 = explode('.', $dpopHeader)[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertSame('POST', $payload['htm']);
        self::assertSame('https://idp.test/oauth2/token', $payload['htu']);
    }

    public function testDpopNonceIsPersistedFromApiResponse(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(200, ['DPoP-Nonce' => 'server-nonce'], '{}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $response = $provider->makeDPopRequest('GET', 'https://api.example.com', 'token-123');
        self::assertSame('server-nonce', $provider->getDPopNonce());
        self::assertSame('server-nonce', $response->getHeaderLine('DPoP-Nonce'));
    }
}
