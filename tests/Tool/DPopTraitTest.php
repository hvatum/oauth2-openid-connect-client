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

    public function testDpopHtuStripsQueryAndFragment(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(200, [], '{"data":"ok"}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->makeDPopRequest('GET', 'https://api.example.com/resource?page=1&limit=10#section', 'token-123');

        // Extract DPoP proof from the request
        $apiRequest = $history[1]['request'];
        $dpopHeader = $apiRequest->getHeaderLine('DPoP');
        $payloadB64 = explode('.', $dpopHeader)[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);

        // htu must not contain query or fragment per RFC 9449 Section 4.2
        self::assertSame('https://api.example.com/resource', $payload['htu']);
    }

    public function testDpopHtuPreservesIpv6Brackets(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(200, [], '{"data":"ok"}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->makeDPopRequest('GET', 'https://[2001:db8::1]/resource?q=1', 'token-123');

        $apiRequest = $history[1]['request'];
        $dpopHeader = $apiRequest->getHeaderLine('DPoP');
        $payloadB64 = explode('.', $dpopHeader)[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);

        // IPv6 brackets must be preserved in htu
        self::assertSame('https://[2001:db8::1]/resource', $payload['htu']);
    }

    public function testDpopNonceRetryOn400(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            // First request: 400 with DPoP-Nonce header (nonce required)
            new Response(400, ['DPoP-Nonce' => 'required-nonce'], json_encode([
                'error' => 'use_dpop_nonce',
                'error_description' => 'DPoP nonce required',
            ])),
            // Retry: 200 OK
            new Response(200, ['DPoP-Nonce' => 'required-nonce'], '{"data":"ok"}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $response = $provider->makeDPopRequest('GET', 'https://api.example.com/resource', 'token-123');

        // Should have retried and succeeded
        self::assertSame(200, $response->getStatusCode());
        // history[0] = well-known, history[1] = first DPoP request, history[2] = retry
        self::assertCount(3, $history);
        self::assertSame('required-nonce', $provider->getDPopNonce());
    }

    public function testDpopDoesNotRetryOn400WithoutUseDpopNonceError(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            // 400 includes DPoP-Nonce but does not signal use_dpop_nonce
            new Response(400, ['DPoP-Nonce' => 'new-nonce'], json_encode([
                'error' => 'invalid_request',
                'error_description' => 'Something else failed',
            ])),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $response = $provider->makeDPopRequest('POST', 'https://api.example.com/resource', 'token-123');

        self::assertSame(400, $response->getStatusCode());
        // history[0] = well-known, history[1] = first DPoP request (no retry)
        self::assertCount(2, $history);
        self::assertSame('new-nonce', $provider->getDPopNonce());
    }

    public function testDpopNonceRetryOn401UseDpopNonceAuthenticateHeader(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(
                401,
                [
                    'DPoP-Nonce' => 'required-nonce',
                    'WWW-Authenticate' => 'DPoP error="use_dpop_nonce"',
                ],
                ''
            ),
            new Response(200, ['DPoP-Nonce' => 'required-nonce'], '{"data":"ok"}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $response = $provider->makeDPopRequest('GET', 'https://api.example.com/resource', 'token-123');

        self::assertSame(200, $response->getStatusCode());
        // history[0] = well-known, history[1] = first DPoP request, history[2] = retry
        self::assertCount(3, $history);
        self::assertSame('required-nonce', $provider->getDPopNonce());
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
