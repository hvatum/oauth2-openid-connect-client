<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Provider;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;

final class OpenIDConnectProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();
        \Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider::clearWellKnownCache();
    }

    public function testConstructorRequiresIssuer(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('issuer is required');

        $history = [];
        $httpClient = TestHelper::httpClient([], $history);

        new \Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider([
            'clientId' => 'test',
        ], [
            'httpClient' => $httpClient,
        ]);
    }

    public function testBasicProviderWithIssuer(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        self::assertSame('https://idp.test/oauth2/authorize', $provider->getBaseAuthorizationUrl());
        self::assertSame('https://idp.test/oauth2/token', $provider->getBaseAccessTokenUrl([]));
        self::assertSame('https://idp.test', $provider->getIssuerUrl());
    }

    public function testEndSessionEndpointIsNullWhenNotInDiscovery(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        self::assertNull($provider->getEndSessionEndpoint());
    }

    public function testEndSessionEndpointFromDiscovery(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'end_session_endpoint' => 'https://idp.test/oauth2/logout',
            ]),
        ], $history);

        self::assertSame('https://idp.test/oauth2/logout', $provider->getEndSessionEndpoint());
    }

    public function testClientAssertionIsOptional(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        // Should not throw — client assertion is optional
        $url = $provider->getAuthorizationUrl();
        self::assertNotEmpty($url);
    }

    public function testDpopIsOptional(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        // Token request should work without DPoP
        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string)$request->getBody();
        parse_str($body, $params);

        self::assertArrayNotHasKey('dpop_jkt', $params);
        self::assertEmpty($request->getHeaderLine('DPoP'));
    }

    public function testDefaultScopesAreMinimal(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $url = $provider->getAuthorizationUrl();

        // Check the PAR request for scopes
        $parRequest = $history[1]['request'];
        $parBody = (string)$parRequest->getBody();
        parse_str($parBody, $parParams);

        self::assertSame('openid', $parParams['scope']);
    }

    public function testNonceIsGeneratedForAuthorization(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();
        self::assertNotNull($provider->getNonce());
        self::assertSame(64, strlen($provider->getNonce())); // 32 bytes = 64 hex chars
    }

    public function testPkceIsEnforcedWithS256(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();
        self::assertNotEmpty($provider->getPkceCode());

        // Verify PKCE was included in the PAR request
        $parRequest = $history[1]['request'];
        $parBody = (string)$parRequest->getBody();
        parse_str($parBody, $parParams);
        self::assertArrayHasKey('code_challenge', $parParams);
        self::assertSame('S256', $parParams['code_challenge_method']);
    }

    public function testParRequestIncludesClientSecretForSecretClients(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();

        // history[0] = well-known, history[1] = PAR
        self::assertCount(2, $history);
        $parRequest = $history[1]['request'];
        $parBody = (string)$parRequest->getBody();
        parse_str($parBody, $parParams);

        self::assertSame('client-123', $parParams['client_id']);
        self::assertSame('secret-456', $parParams['client_secret']);
    }

    public function testParRequestOmitsClientSecretWhenSecretIsEmpty(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history, [
            'clientSecret' => '',
        ]);

        $provider->getAuthorizationUrl();

        self::assertCount(2, $history);
        $parRequest = $history[1]['request'];
        parse_str((string) $parRequest->getBody(), $parParams);

        self::assertArrayNotHasKey('client_secret', $parParams);
        self::assertArrayNotHasKey('client_assertion', $parParams);
    }

    public function testParRequestUsesClientAssertionWhenConfigured(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();

        // history[0] = well-known, history[1] = PAR
        self::assertCount(2, $history);
        $parRequest = $history[1]['request'];
        $parBody = (string)$parRequest->getBody();
        parse_str($parBody, $parParams);

        self::assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $parParams['client_assertion_type']);
        self::assertNotEmpty($parParams['client_assertion']);
        self::assertArrayNotHasKey('client_secret', $parParams);

        // Audience should be the token endpoint URL per RFC 7523 §3
        // (RFC 9126 §2: PAR uses same client auth as token endpoint)
        $assertion = $parParams['client_assertion'];
        $payloadB64 = explode('.', $assertion)[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertSame('https://idp.test/oauth2/token', $payload['aud']);
    }

    public function testDiscoveryAcceptsProviderWithoutUserinfoEndpoint(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'userinfo_endpoint' => null,
            ]),
        ], $history);

        // Provider should initialize without error
        self::assertSame('https://idp.test/oauth2/authorize', $provider->getBaseAuthorizationUrl());
    }

    public function testGetResourceOwnerDetailsUrlThrowsWhenUserinfoMissing(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'userinfo_endpoint' => null,
            ]),
        ], $history);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('UserInfo endpoint not available');

        $token = new \League\OAuth2\Client\Token\AccessToken(['access_token' => 'test']);
        $provider->getResourceOwnerDetailsUrl($token);
    }

    public function testRejectsUserInfoSubMismatchWithIdToken(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            new Response(200, ['Content-Type' => 'application/json'], '{"sub":"other-user","name":"Alice"}'),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('UserInfo sub claim does not match ID token sub claim');

        $provider->getResourceOwner($token);
    }

    public function testGetIdTokenValidatesBeforeReturning(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://evil.example.com',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->getAccessToken('client_credentials');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('iss');
        $provider->getIdToken();
    }

    public function testGetIdTokenReturnsValidatedToken(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->getAccessToken('client_credentials');
        self::assertSame($idToken, $provider->getIdToken());
    }

    public function testGetIdTokenRevalidatesAfterCallbackIssuerChange(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->getAccessToken('client_credentials');
        self::assertSame($idToken, $provider->getIdToken());

        $provider->setCallbackIssuer('https://evil.example.com');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Issuer mismatch');
        $provider->getIdToken();
    }

    public function testGetIdTokenRevalidatesAfterNonceChange(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');
        $provider->getAccessToken('client_credentials');
        self::assertSame($idToken, $provider->getIdToken());

        $provider->setNonce('n-2');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('nonce');
        $provider->getIdToken();
    }

    public function testCachesPerIssuer(): void
    {
        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $history2 = [];
        $provider2 = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'issuer' => 'https://second.test',
                'authorization_endpoint' => 'https://second.test/auth',
            ]),
        ], $history2, [
            'issuer' => 'https://second.test',
        ]);

        self::assertSame('https://second.test/auth', $provider2->getBaseAuthorizationUrl());
    }

    public function testIssuerMismatchInDiscoveryThrows(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Issuer mismatch in discovery document');

        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse(['issuer' => 'https://evil.example.com']),
        ], $history);
    }

    public function testDiscoveryRejectsNonHttpsTokenEndpoint(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('token_endpoint must use https URL');

        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint' => 'http://idp.test/oauth2/token',
            ]),
        ], $history);
    }

    public function testDiscoveryRejectsNonHttpsJwksUri(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('jwks_uri must use https URL');

        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'jwks_uri' => 'http://idp.test/oauth2/jwks',
            ]),
        ], $history);
    }

    public function testDiscoveryRejectsNonHttpsIssuerMetadata(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('issuer must use https URL');

        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'issuer' => 'http://idp.test',
            ]),
        ], $history, [
            // Keep discovery fetch itself on HTTPS; only metadata issuer is HTTP.
            'issuer' => 'http://idp.test',
            'wellKnownUrl' => 'https://idp.test/.well-known/openid-configuration',
        ]);
    }

    public function testTokenEndpointErrorThrowsException(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenErrorResponse(400, 'invalid_grant', 'Authorization code expired'),
        ], $history);

        $provider->setPkceCode('verifier');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Authorization code expired');

        $provider->getAccessToken('authorization_code', ['code' => 'expired-code']);
    }

    public function testParErrorThrowsException(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            new Response(400, ['Content-Type' => 'application/json'], json_encode([
                'error' => 'invalid_request',
                'error_description' => 'Missing required parameter',
            ])),
        ], $history);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('invalid_request');

        $provider->getAuthorizationUrl();
    }

    public function testParUnexpectedExceptionIsWrapped(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            new \RuntimeException('network down'),
        ], $history);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('PAR request failed');

        $provider->getAuthorizationUrl();
    }

    public function testParMissingRequestUriThrowsException(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            new Response(201, ['Content-Type' => 'application/json'], json_encode([
                'expires_in' => 60,
            ])),
        ], $history);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('request_uri');

        $provider->getAuthorizationUrl();
    }

    public function testDiscoveryRejectsNonHttpsWellKnownUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('HTTPS');

        $history = [];
        $httpClient = TestHelper::httpClient([], $history);

        new \Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider([
            'clientId' => 'test',
            'issuer' => 'http://insecure.example.com',
        ], [
            'httpClient' => $httpClient,
        ]);
    }

    public function testWellKnownUrlOverride(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(['issuer' => 'https://idp.test']),
        ], $history, [
            'issuer' => 'https://idp.test',
            'wellKnownUrl' => 'https://idp.test/custom/.well-known/openid-configuration',
        ]);

        self::assertSame('https://idp.test', $provider->getIssuerUrl());
        self::assertSame(
            'https://idp.test/custom/.well-known/openid-configuration',
            (string) $history[0]['request']->getUri()
        );
    }

    public function testWellKnownCacheEntryValidationHelper(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $isFresh = \Closure::bind(
            fn($entry) => $this->isFreshInMemoryWellKnownCacheEntry($entry),
            $provider,
            $provider
        );

        self::assertTrue($isFresh([
            'config' => ['issuer' => 'https://idp.test'],
            'loaded_at' => time(),
        ]));
        self::assertFalse($isFresh('invalid'));
        self::assertFalse($isFresh(['config' => ['issuer' => 'x']]));
        self::assertFalse($isFresh([
            'config' => ['issuer' => 'https://idp.test'],
            'loaded_at' => time() - 90000,
        ]));
    }

    public function testLoadWellKnownFromCacheRejectsInvalidJsonAndDeletesFile(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $cacheFile = tempnam(sys_get_temp_dir(), 'wk_invalid_');
        file_put_contents($cacheFile, '{not-json');

        $loadFromCache = \Closure::bind(
            fn(string $file) => $this->loadWellKnownFromCache($file),
            $provider,
            $provider
        );

        self::assertNull($loadFromCache($cacheFile));
        self::assertFileDoesNotExist($cacheFile);
    }

    public function testLoadWellKnownFromCacheRejectsExpiredFileAndDeletesFile(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $cacheFile = tempnam(sys_get_temp_dir(), 'wk_expired_');
        file_put_contents($cacheFile, json_encode(['issuer' => 'https://idp.test']));
        touch($cacheFile, time() - 90000);

        $loadFromCache = \Closure::bind(
            fn(string $file) => $this->loadWellKnownFromCache($file),
            $provider,
            $provider
        );

        self::assertNull($loadFromCache($cacheFile));
        self::assertFileDoesNotExist($cacheFile);
    }

    public function testSaveWellKnownToCacheWritesFileWithCorrectPermissions(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $cacheDir = sys_get_temp_dir() . '/oauth2-oidc-test-save-' . uniqid();
        $cacheFile = $cacheDir . '/wellknown_test.json';

        $saveToCache = \Closure::bind(
            fn(string $file, array $config) => $this->saveWellKnownToCache($file, $config),
            $provider,
            $provider
        );

        $config = ['issuer' => 'https://idp.test', 'token_endpoint' => 'https://idp.test/token'];
        $saveToCache($cacheFile, $config);

        self::assertFileExists($cacheFile);
        self::assertSame($config, json_decode(file_get_contents($cacheFile), true));
        self::assertSame(0600, fileperms($cacheFile) & 0777);

        // Cleanup
        @unlink($cacheFile);
        @rmdir($cacheDir);
    }

    public function testSetCacheDirIsUsedForCachePath(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $customDir = '/tmp/custom-cache-dir-' . uniqid();
        $provider->setCacheDir($customDir);

        $getCacheFile = \Closure::bind(
            fn(string $url) => $this->getWellKnownCacheFile($url),
            $provider,
            $provider
        );

        $file = $getCacheFile('https://idp.test/.well-known/openid-configuration');
        self::assertStringStartsWith($customDir . '/', $file);
        self::assertStringContainsString('wellknown_', $file);
    }

    public function testGetCacheNamespaceReturnsHashedIdentifier(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $getNamespace = \Closure::bind(
            fn() => $this->getCacheNamespace(),
            $provider,
            $provider
        );

        $namespace = $getNamespace();
        // Should be either a sha256 hash or 'default'
        self::assertMatchesRegularExpression('/^([a-f0-9]{64}|default)$/', $namespace);
    }

    public function testLoadWellKnownFromCacheReturnsNullForMissingFile(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $loadFromCache = \Closure::bind(
            fn(string $file) => $this->loadWellKnownFromCache($file),
            $provider,
            $provider
        );

        self::assertNull($loadFromCache('/tmp/nonexistent-' . uniqid() . '.json'));
    }

    public function testLoadWellKnownFromCacheReturnsValidConfig(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $config = ['issuer' => 'https://idp.test', 'authorization_endpoint' => 'https://idp.test/auth'];
        $cacheFile = tempnam(sys_get_temp_dir(), 'wk_valid_');
        file_put_contents($cacheFile, json_encode($config));

        $loadFromCache = \Closure::bind(
            fn(string $file) => $this->loadWellKnownFromCache($file),
            $provider,
            $provider
        );

        self::assertSame($config, $loadFromCache($cacheFile));
        @unlink($cacheFile);
    }

    public function testGetJwksThrowsOnHttpError(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            new Response(500, [], 'Internal Server Error'),
        ], $history);

        $provider->getAccessToken('client_credentials');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Failed to fetch JWKS');

        $provider->getIdToken();
    }

    public function testGetJwksThrowsOnInvalidJsonResponse(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            new Response(200, ['Content-Type' => 'application/json'], '{not-json'),
        ], $history);

        $provider->getAccessToken('client_credentials');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid JWKS response format');

        $provider->getIdToken();
    }

    public function testGetJwksThrowsOnMissingKeysArray(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            new Response(200, ['Content-Type' => 'application/json'], '{"foo":"bar"}'),
        ], $history);

        $provider->getAccessToken('client_credentials');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid JWKS response format');

        $provider->getIdToken();
    }

    public function testGenerateNonceIsUniqueAcrossCalls(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
            TestHelper::parResponse(),
        ], $history);

        // Each getAuthorizationUrl() generates a fresh nonce
        $provider->getAuthorizationUrl();
        $nonce1 = $provider->getNonce();

        $provider->getAuthorizationUrl();
        $nonce2 = $provider->getNonce();

        self::assertSame(64, strlen($nonce1));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $nonce1);
        self::assertNotSame($nonce1, $nonce2);
    }

    public function testAuthorizationWithoutPARReturnsFullParams(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'pushed_authorization_request_endpoint' => null,
            ]),
        ], $history);

        $url = $provider->getAuthorizationUrl(['scope' => ['openid', 'profile']]);

        // Without PAR, all params should be in the URL directly
        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);

        self::assertSame('client-123', $params['client_id']);
        self::assertArrayHasKey('nonce', $params);
        self::assertArrayHasKey('code_challenge', $params);
        self::assertArrayNotHasKey('request_uri', $params);
    }

    public function testAuthorizationWithPAROnlyContainsClientIdAndRequestUri(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse('urn:ietf:params:oauth:request_uri:abc-123'),
        ], $history);

        $url = $provider->getAuthorizationUrl(['scope' => ['openid', 'profile']]);

        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);

        // With PAR, only client_id and request_uri should be in the URL
        self::assertSame('client-123', $params['client_id']);
        self::assertSame('urn:ietf:params:oauth:request_uri:abc-123', $params['request_uri']);

        // Sensitive params must NOT leak into the URL — they were sent via PAR
        self::assertArrayNotHasKey('scope', $params);
        self::assertArrayNotHasKey('nonce', $params);
        self::assertArrayNotHasKey('code_challenge', $params);
        self::assertArrayNotHasKey('redirect_uri', $params);
        self::assertArrayNotHasKey('client_secret', $params);
    }

    public function testCheckResponseThrowsOnErrorInSuccessStatusBody(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            // 200 response but with error field in body
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'error' => 'server_error',
                'error_description' => 'Unexpected internal failure',
            ])),
        ], $history);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Unexpected internal failure');

        $provider->getAccessToken('client_credentials');
    }

    public function testIsDPopNonceErrorDetectsErrorInMessage(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $isDPopNonceError = \Closure::bind(
            fn(\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) =>
                $this->isDPopNonceError($e),
            $provider,
            $provider
        );

        // Direct message match
        $e1 = new \League\OAuth2\Client\Provider\Exception\IdentityProviderException(
            'use_dpop_nonce', 400, null
        );
        self::assertTrue($isDPopNonceError($e1));

        // Non-matching message, no response body
        $e2 = new \League\OAuth2\Client\Provider\Exception\IdentityProviderException(
            'invalid_grant', 400, null
        );
        self::assertFalse($isDPopNonceError($e2));

        // Non-matching message, but response body contains use_dpop_nonce
        $response = new Response(400, [], json_encode(['error' => 'use_dpop_nonce']));
        $e3 = new \League\OAuth2\Client\Provider\Exception\IdentityProviderException(
            'DPoP nonce required', 400, $response
        );
        self::assertTrue($isDPopNonceError($e3));

        // Non-matching message, response body has different error
        $response2 = new Response(400, [], json_encode(['error' => 'invalid_request']));
        $e4 = new \League\OAuth2\Client\Provider\Exception\IdentityProviderException(
            'Something else', 400, $response2
        );
        self::assertFalse($isDPopNonceError($e4));
    }

    public function testExtractDPopNonceFromTokenResponse(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            // Token response with DPoP-Nonce header
            new Response(200, [
                'Content-Type' => 'application/json',
                'DPoP-Nonce' => 'server-token-nonce',
            ], json_encode([
                'access_token' => 'token123',
                'token_type' => 'DPoP',
                'expires_in' => 3600,
            ])),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('verifier');
        $provider->getAccessToken('authorization_code', ['code' => 'abc']);

        // The DPoP nonce should have been extracted from the token response
        self::assertSame('server-token-nonce', $provider->getDPopNonce());
    }

    public function testDPopNonceRetryOnTokenEndpoint(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            // First token request: 400 with use_dpop_nonce
            new Response(400, [
                'Content-Type' => 'application/json',
                'DPoP-Nonce' => 'required-nonce',
            ], json_encode([
                'error' => 'use_dpop_nonce',
                'error_description' => 'DPoP nonce required',
            ])),
            // Retry: success
            new Response(200, [
                'Content-Type' => 'application/json',
                'DPoP-Nonce' => 'required-nonce',
            ], json_encode([
                'access_token' => 'token-after-retry',
                'token_type' => 'DPoP',
                'expires_in' => 3600,
            ])),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $provider->setPkceCode('verifier');
        $token = $provider->getAccessToken('authorization_code', ['code' => 'abc']);

        // Should have retried: well-known + first token request + retry
        self::assertCount(3, $history);
        self::assertSame('token-after-retry', $token->getToken());
    }


    public function testWellKnownInMemoryCacheIsUsedOnSecondConstruction(): void
    {
        // First provider loads from network (basicProvider clears cache first)
        $history1 = [];
        $provider1 = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history1);
        self::assertCount(1, $history1); // one HTTP call for well-known

        // Second provider with same issuer — do NOT use basicProvider (it clears cache)
        $history2 = [];
        $httpClient2 = TestHelper::httpClient([], $history2);
        $provider2 = new \Hvatum\OpenIDConnect\Client\Test\TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'cacheDir' => sys_get_temp_dir() . '/oauth2-oidc-tests-' . uniqid(),
        ], [
            'httpClient' => $httpClient2,
        ]);

        // No HTTP calls — served from in-memory cache
        self::assertCount(0, $history2);
        self::assertSame('https://idp.test', $provider2->getIssuerUrl());
    }

    public function testWellKnownFileCacheIsUsedWhenInMemoryCacheCleared(): void
    {
        $cacheDir = sys_get_temp_dir() . '/oauth2-oidc-filecache-' . uniqid();

        // First provider loads from network and writes file cache
        $history1 = [];
        $provider1 = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'issuer' => 'https://filecache.test',
                'authorization_endpoint' => 'https://filecache.test/auth',
                'token_endpoint' => 'https://filecache.test/token',
            ]),
        ], $history1, [
            'issuer' => 'https://filecache.test',
            'wellKnownUrl' => 'https://filecache.test/.well-known/openid-configuration',
            'cacheDir' => $cacheDir,
        ]);
        self::assertCount(1, $history1);

        // Clear in-memory cache
        \Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider::clearWellKnownCache();

        // Second provider should use file cache
        $history2 = [];
        $httpClient2 = TestHelper::httpClient([], $history2);
        $provider2 = new \Hvatum\OpenIDConnect\Client\Test\TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://filecache.test',
            'wellKnownUrl' => 'https://filecache.test/.well-known/openid-configuration',
            'cacheDir' => $cacheDir,
        ], [
            'httpClient' => $httpClient2,
        ]);

        // No HTTP calls — served from file cache
        self::assertCount(0, $history2);
        self::assertSame('https://filecache.test', $provider2->getIssuerUrl());

        // Cleanup
        array_map('unlink', glob($cacheDir . '/*'));
        @rmdir($cacheDir);
    }


    public function testDiscoveryRejectsNonStringEndpointValue(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('must be a string URL');

        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint' => 12345,
            ]),
        ], $history);
    }

    public function testDiscoveryRejectsMissingRequiredField(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('missing authorization_endpoint');

        $history = [];
        $httpClient = TestHelper::httpClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'issuer' => 'https://idp.test',
                'token_endpoint' => 'https://idp.test/oauth2/token',
                // authorization_endpoint missing
            ])),
        ], $history);

        new \Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider([
            'clientId' => 'test',
            'issuer' => 'https://idp.test',
            'cacheDir' => sys_get_temp_dir() . '/oauth2-oidc-tests-' . uniqid(),
        ], [
            'httpClient' => $httpClient,
        ]);
    }
}
