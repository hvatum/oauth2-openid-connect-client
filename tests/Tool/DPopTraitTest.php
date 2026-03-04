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

    public function testDpopNonceIsIncludedInRetryProof(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(400, ['DPoP-Nonce' => 'server-nonce'], json_encode([
                'error' => 'use_dpop_nonce',
            ])),
            new Response(200, ['DPoP-Nonce' => 'server-nonce'], '{"data":"ok"}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->makeDPopRequest('GET', 'https://api.example.com/resource', 'token-123');

        // Verify the retry request (history[2]) includes the nonce in the DPoP proof
        self::assertCount(3, $history);
        $retryDpop = $history[2]['request']->getHeaderLine('DPoP');
        $retryPayload = json_decode(base64_decode(strtr(explode('.', $retryDpop)[1], '-_', '+/')), true);
        self::assertSame('server-nonce', $retryPayload['nonce']);
    }

    public function testDpopAthClaimIsCorrect(): void
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

        $accessToken = 'my-access-token-value';
        $provider->makeDPopRequest('GET', 'https://api.example.com/resource', $accessToken);

        $dpopHeader = $history[1]['request']->getHeaderLine('DPoP');
        $payload = json_decode(base64_decode(strtr(explode('.', $dpopHeader)[1], '-_', '+/')), true);

        // ath = base64url(sha256(access_token))
        $expectedAth = rtrim(strtr(base64_encode(hash('sha256', $accessToken, true)), '+/', '-_'), '=');
        self::assertSame($expectedAth, $payload['ath']);
    }

    public function testDpopJtiIsUnique(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(200, [], '{}'),
            new Response(200, [], '{}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->makeDPopRequest('GET', 'https://api.example.com/a', 'token-1');
        $provider->makeDPopRequest('GET', 'https://api.example.com/b', 'token-2');

        $extractJti = function (int $index) use ($history): string {
            $dpop = $history[$index]['request']->getHeaderLine('DPoP');
            return json_decode(base64_decode(strtr(explode('.', $dpop)[1], '-_', '+/')), true)['jti'];
        };

        self::assertNotSame($extractJti(1), $extractJti(2));
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

    public function testDpopDoesNotRetryOnNon400Or401Status(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(403, ['DPoP-Nonce' => 'nonce-1'], json_encode([
                'error' => 'use_dpop_nonce',
            ])),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $response = $provider->makeDPopRequest('GET', 'https://api.example.com/resource', 'token-123');

        // Should not retry — 403 is not retryable
        self::assertSame(403, $response->getStatusCode());
        self::assertCount(2, $history);
    }

    public function testDpopDoesNotRetryWhenNonceUnchanged(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(400, ['DPoP-Nonce' => 'same-nonce'], json_encode([
                'error' => 'use_dpop_nonce',
            ])),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        // Pre-set the nonce to the same value the server returns
        $provider->setDPopNonce('same-nonce');

        $response = $provider->makeDPopRequest('GET', 'https://api.example.com/resource', 'token-123');

        // Should not retry — nonce hasn't changed
        self::assertSame(400, $response->getStatusCode());
        self::assertCount(2, $history);
    }

    public function testDpopRequestIncludesBodyAndHeaders(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            new Response(200, [], '{"ok":true}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->makeDPopRequest('POST', 'https://api.example.com/resource', 'token-123', [
            'body' => '{"key":"value"}',
            'headers' => ['Content-Type' => 'application/json'],
        ]);

        $apiRequest = $history[1]['request'];
        self::assertSame('POST', $apiRequest->getMethod());
        self::assertSame('application/json', $apiRequest->getHeaderLine('Content-Type'));
        self::assertSame('{"key":"value"}', (string) $apiRequest->getBody());
        self::assertStringStartsWith('DPoP ', $apiRequest->getHeaderLine('Authorization'));
    }

    public function testIsUseDpopNonceErrorDetectsWwwAuthenticateVariants(): void
    {
        [$privateKey, $publicKey, $jwk] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            // Quoted error value with realm in WWW-Authenticate
            new Response(401, [
                'DPoP-Nonce' => 'nonce-a',
                'WWW-Authenticate' => 'DPoP realm="test", error="use_dpop_nonce"',
            ], '{}'),
            new Response(200, ['DPoP-Nonce' => 'nonce-a'], '{"ok":true}'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $response = $provider->makeDPopRequest('GET', 'https://api.example.com/resource', 'token-123');

        // Should have retried (WWW-Authenticate with quoted error value detected)
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(3, $history);
    }

    // ── dpop_signing_alg_values_supported tests ──

    public function testDPopAcceptedWhenES256InServerList(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'dpop_signing_alg_values_supported' => ['ES256', 'PS256'],
            ]),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('test-verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $dpopHeader = $request->getHeaderLine('DPoP');
        self::assertNotEmpty($dpopHeader);
    }

    public function testDPopAcceptedWhenServerListsAll9(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'dpop_signing_alg_values_supported' => [
                    'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                ],
            ]),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('test-verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $dpopHeader = $request->getHeaderLine('DPoP');
        self::assertNotEmpty($dpopHeader);
    }

    public function testDPopRejectedWhenES256NotInServerList(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'dpop_signing_alg_values_supported' => ['PS256', 'RS256'],
            ]),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('test-verifier');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('DPoP algorithm ES256 is not supported by the authorization server');
        $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);
    }

    public function testDPopSkipsValidationWhenNotAdvertised(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        // Default wellKnownResponse has no dpop_signing_alg_values_supported
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('test-verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $dpopHeader = $request->getHeaderLine('DPoP');
        self::assertNotEmpty($dpopHeader);
    }
}
