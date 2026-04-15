<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Tool;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;

final class DPopTraitTest extends TestCase
{
    public function testTokenRequestIncludesDpopProof(): void
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

        // dpop_jkt must NOT be in the token request body (RFC 9449 — it belongs in the
        // authorization request only; token endpoint binding is done via the DPoP header)
        $body = (string)$tokenRequest->getBody();
        parse_str($body, $params);
        self::assertArrayNotHasKey('dpop_jkt', $params, 'dpop_jkt must not be sent to the token endpoint');

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

    public function testRawPemViaDpopPrivateKeyOption(): void
    {
        [$privateKeyPem, $publicKeyPem] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKey' => $privateKeyPem,
            'dpopPublicKey' => $publicKeyPem,
        ]);

        $provider->setPkceCode('test-verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $dpopHeader = $request->getHeaderLine('DPoP');
        self::assertNotEmpty($dpopHeader, 'DPoP proof should be emitted when key loaded from raw PEM');
    }

    public function testDpopPrivateKeyAndPathAreMutuallyExclusive(): void
    {
        [$privateKeyPem] = TestHelper::generateEcKeyPair();
        $path = TestHelper::createTempKeyFile($privateKeyPem);

        $history = [];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Provide either `dpopPrivateKey` (raw PEM/JWK content) or `dpopPrivateKeyPath` (filesystem path), not both');

        TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'dpopPrivateKey' => $privateKeyPem,
            'dpopPrivateKeyPath' => $path,
        ]);
    }

    public function testDpopPublicKeyAndPathAreMutuallyExclusive(): void
    {
        [$privateKeyPem, $publicKeyPem] = TestHelper::generateEcKeyPair();
        $publicPath = TestHelper::createTempKeyFile($publicKeyPem);

        $history = [];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Provide either `dpopPublicKey` (raw PEM/JWK content) or `dpopPublicKeyPath` (filesystem path), not both');

        TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'dpopPrivateKey' => $privateKeyPem,
            'dpopPublicKey' => $publicKeyPem,
            'dpopPublicKeyPath' => $publicPath,
        ]);
    }

    public function testMissingDpopPrivateKeyFileThrowsAtConstruction(): void
    {
        $history = [];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`dpopPrivateKeyPath` must be a readable file');

        TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'dpopPrivateKeyPath' => '/tmp/does-not-exist-' . bin2hex(random_bytes(8)),
        ]);
    }

    public function testEmptyDpopPrivateKeyAliasFallsBackToPath(): void
    {
        // Empty alias must NOT silently disable DPoP when a valid *Path is set.
        [$privateKeyPem] = TestHelper::generateEcKeyPair();
        $path = TestHelper::createTempKeyFile($privateKeyPem);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKey' => '',
            'dpopPrivateKeyPath' => $path,
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        self::assertNotEmpty(
            $request->getHeaderLine('DPoP'),
            'Empty alias must not silently disable DPoP when path fallback is configured'
        );
    }

    public function testJwkSetRejectedAsDpopPrivateKey(): void
    {
        // {"keys":[...]} parses to JWKSet — must surface a useful error rather
        // than crash on the JWK return type.
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();
        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwks = json_encode(['keys' => [$jwk]]);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKey' => $jwks,
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('DPoP private key: must be a single JWK, not a JWK set');

        $provider->setPkceCode('verifier');
        $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);
    }

    public function testDpopPublicKeyDerivedFromPrivateWhenOmitted(): void
    {
        // RFC 9449 §4.2: when the public key is omitted, the library must
        // derive it from the private key's curve points and embed THAT in the
        // proof's `jwk` header. Verify the embedded x/y match the private
        // key's public coordinates — a regression here would mean either the
        // derivation is wrong or the test scaffold is silently injecting an
        // unrelated public key.
        [$privateKeyPem] = TestHelper::generateEcKeyPair();
        $privateResource = openssl_pkey_get_private($privateKeyPem);
        $details = openssl_pkey_get_details($privateResource);
        $expectedX = rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '=');
        $expectedY = rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '=');

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKey' => $privateKeyPem,
            // dpopPublicKey deliberately omitted
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $dpopHeader = $request->getHeaderLine('DPoP');
        self::assertNotEmpty($dpopHeader);

        // Decode the JWT header (first segment of compact serialization)
        $headerB64 = explode('.', $dpopHeader)[0];
        $decoded = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);

        self::assertIsArray($decoded['jwk'] ?? null, 'DPoP proof must embed jwk in header');
        self::assertSame('EC', $decoded['jwk']['kty']);
        self::assertSame($expectedX, $decoded['jwk']['x'], 'Derived public key x must match private key');
        self::assertSame($expectedY, $decoded['jwk']['y'], 'Derived public key y must match private key');
    }

    public function testJwkSetRejectedAsDpopPublicKey(): void
    {
        // The public-key code path uses the same JWK builder as the private one;
        // the error message must point at `DPoP public key`, not the private one.
        [$privateKeyPem, , $jwk] = TestHelper::generateEcKeyPair();
        $jwks = json_encode(['keys' => [$jwk]]);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKey' => $privateKeyPem,
            'dpopPublicKey' => $jwks,
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('DPoP public key: must be a single JWK, not a JWK set');

        $provider->setPkceCode('verifier');
        $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);
    }

    public function testBomPrefixedRawDpopPemAccepted(): void
    {
        [$privateKeyPem] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history, [
            'dpopPrivateKey' => "\xEF\xBB\xBF" . $privateKeyPem,
        ]);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        self::assertNotEmpty($request->getHeaderLine('DPoP'));
    }

    /**
     * @return array<string, array{mixed, string}>
     */
    public static function wrongTypedDpopOptionProvider(): array
    {
        return [
            'array dpopPrivateKey' => [['bad'], 'dpopPrivateKey'],
            'int dpopPrivateKeyPath' => [42, 'dpopPrivateKeyPath'],
            'array dpopPublicKey' => [['bad'], 'dpopPublicKey'],
            'bool dpopPublicKeyPath' => [true, 'dpopPublicKeyPath'],
        ];
    }

    /**
     * @dataProvider wrongTypedDpopOptionProvider
     */
    public function testWrongTypedDpopOptionThrowsAtConstruction(mixed $value, string $optionName): void
    {
        // The constructor now validates the public DPoP options upfront (no
        // longer gated on a configured private key), so all four options
        // fail-fast on wrong types regardless of what the others contain.
        $history = [];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("`{$optionName}` must be a string");

        TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [$optionName => $value]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function orphanPublicKeyOptionProvider(): array
    {
        return [
            'dpopPublicKey raw content alone' => ['dpopPublicKey'],
            'dpopPublicKeyPath alone' => ['dpopPublicKeyPath'],
        ];
    }

    /**
     * @dataProvider orphanPublicKeyOptionProvider
     */
    public function testOrphanedDpopPublicKeyThrowsAtConstruction(string $optionName): void
    {
        // Configuring a public DPoP key without a corresponding private key is
        // a misconfiguration: the public key alone cannot sign proofs. The old
        // constructor silently dropped these on the floor.
        [$privateKeyPem, $publicKeyPem] = TestHelper::generateEcKeyPair();
        $value = $optionName === 'dpopPublicKeyPath'
            ? TestHelper::createTempKeyFile($publicKeyPem)
            : $publicKeyPem;

        $history = [];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            '`dpopPublicKey` / `dpopPublicKeyPath` requires a corresponding '
            . '`dpopPrivateKey` / `dpopPrivateKeyPath`'
        );

        TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [$optionName => $value]);
    }
}
