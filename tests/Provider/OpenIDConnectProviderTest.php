<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Provider;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Test\IssuerAudienceTestHelper;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;
use Hvatum\OpenIDConnect\Client\Test\TestProvider;

final class OpenIDConnectProviderTest extends TestCase
{
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

    public function testGetAccessTokenExtractsIssFromOptions(): void
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
            TestHelper::wellKnownResponse([
                'authorization_response_iss_parameter_supported' => true,
            ]),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        // Pass iss alongside code — should automatically set callbackIssuer
        $provider->getAccessToken('authorization_code', [
            'code' => 'auth-code-123',
            'iss' => 'https://idp.test',
        ]);

        self::assertSame('https://idp.test', $provider->getCallbackIssuer());
        self::assertSame($idToken, $provider->getIdToken());
    }

    public function testGetAccessTokenRejectsIssOptionMismatch(): void
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
            TestHelper::wellKnownResponse([
                'authorization_response_iss_parameter_supported' => true,
            ]),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        // Pass mismatched iss
        $provider->getAccessToken('authorization_code', [
            'code' => 'auth-code-123',
            'iss' => 'https://evil.example.com',
        ]);

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

    public function testWellKnownConfigIsCachedViaPsr16(): void
    {
        $cacheDir = sys_get_temp_dir() . '/oauth2-oidc-psr16-test-' . uniqid();
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history, ['cacheDir' => $cacheDir]);

        // Well-known should have been cached
        $cacheFiles = glob($cacheDir . '/wellknown_*.cache');
        self::assertNotEmpty($cacheFiles, 'Well-known config should be cached to file');

        // Read cache file and verify content
        $content = file_get_contents($cacheFiles[0]);
        $entry = json_decode($content, true);
        self::assertArrayHasKey('data', $entry);
        self::assertSame('https://idp.test', $entry['data']['issuer']);

        // Cleanup
        array_map('unlink', glob($cacheDir . '/*'));
        @rmdir($cacheDir);
    }

    public function testCustomPsr16CacheIsUsed(): void
    {
        $cacheDir = sys_get_temp_dir() . '/oauth2-oidc-mock-cache-' . uniqid();
        $mockCache = new \Hvatum\OpenIDConnect\Client\Cache\FilesystemCache($cacheDir);

        $history = [];
        $httpClient = TestHelper::httpClient([TestHelper::wellKnownResponse()], $history);
        $requestFactory = new \League\OAuth2\Client\Tool\RequestFactory();

        $provider = new \Hvatum\OpenIDConnect\Client\Test\TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => $requestFactory,
            'cache' => $mockCache,
        ]);

        // Cache should have the well-known entry
        $cacheKey = 'wellknown_' . md5('https://idp.test/.well-known/openid-configuration');
        self::assertNotNull($mockCache->get($cacheKey));

        // Cleanup
        array_map('unlink', glob($cacheDir . '/*'));
        @rmdir($cacheDir);
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

    public function testJwksIsCachedViaPsr16AfterFetch(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $mockCache = \Mockery::mock(\Psr\SimpleCache\CacheInterface::class);
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^wellknown_/'))->andReturn(null)->once();
        $mockCache->shouldReceive('set')->with(
            \Mockery::pattern('/^wellknown_/'),
            \Mockery::on(fn($v) => is_array($v) && isset($v['issuer'])),
            \Mockery::any()
        )->once();
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^jwks_/'))->andReturn(null)->once();
        $mockCache->shouldReceive('set')->with(
            \Mockery::pattern('/^jwks_/'),
            \Mockery::on(fn($v) => is_array($v) && isset($v['keys'])),
            \Mockery::any()
        )->once();

        $history = [];
        $httpClient = TestHelper::httpClient([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider = new TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => new \League\OAuth2\Client\Tool\RequestFactory(),
            'cache' => $mockCache,
        ]);

        $provider->getAccessToken('client_credentials');
        $token = $provider->getIdToken();
        self::assertNotNull($token);
        \Mockery::close();
    }

    public function testCustomCacheTtlsAreUsedForWellKnownAndJwks(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $mockCache = \Mockery::mock(\Psr\SimpleCache\CacheInterface::class);
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^wellknown_/'))->andReturn(null)->once();
        $mockCache->shouldReceive('set')->with(
            \Mockery::pattern('/^wellknown_/'),
            \Mockery::on(fn($v) => is_array($v) && isset($v['issuer'])),
            42
        )->once();
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^jwks_/'))->andReturn(null)->once();
        $mockCache->shouldReceive('set')->with(
            \Mockery::pattern('/^jwks_/'),
            \Mockery::on(fn($v) => is_array($v) && isset($v['keys'])),
            17
        )->once();

        $history = [];
        $httpClient = TestHelper::httpClient([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider = new TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'wellKnownCacheTtl' => 42,
            'jwksCacheTtl' => 17,
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => new \League\OAuth2\Client\Tool\RequestFactory(),
            'cache' => $mockCache,
        ]);

        $provider->getAccessToken('client_credentials');
        $token = $provider->getIdToken();
        self::assertNotNull($token);
        \Mockery::close();
    }

    public function testRejectsNegativeWellKnownCacheTtlOption(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('wellKnownCacheTtl must be a non-negative integer');

        $history = [];
        $httpClient = TestHelper::httpClient([], $history);
        new TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'wellKnownCacheTtl' => -1,
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => new \League\OAuth2\Client\Tool\RequestFactory(),
        ]);
    }

    public function testRejectsNonIntegerJwksCacheTtlOption(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('jwksCacheTtl must be a non-negative integer');

        $history = [];
        $httpClient = TestHelper::httpClient([], $history);
        new TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'jwksCacheTtl' => '3600',
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => new \League\OAuth2\Client\Tool\RequestFactory(),
        ]);
    }

    public function testJwksIsLoadedFromPsr16CacheOnSecondInstance(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $jwksData = ['keys' => [$jwk]];

        $mockCache = \Mockery::mock(\Psr\SimpleCache\CacheInterface::class);
        // well-known config from cache
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^wellknown_/'))->andReturn([
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/oauth2/authorize',
            'token_endpoint' => 'https://idp.test/oauth2/token',
            'jwks_uri' => 'https://idp.test/oauth2/jwks',
            'id_token_signing_alg_values_supported' => ['ES256', 'RS256'],
        ]);
        // JWKS from cache — no HTTP fetch needed
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^jwks_/'))->andReturn($jwksData)->once();
        $mockCache->shouldNotReceive('set');

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $httpClient = TestHelper::httpClient([
            // Only token response needed — no well-known or JWKS fetch
            TestHelper::tokenResponse(['id_token' => $idToken]),
        ], $history);

        $provider = new TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => new \League\OAuth2\Client\Tool\RequestFactory(),
            'cache' => $mockCache,
        ]);

        $provider->getAccessToken('client_credentials');
        $token = $provider->getIdToken();
        self::assertNotNull($token);
        // Verify only 1 HTTP request was made (token), no JWKS/well-known fetches
        self::assertCount(1, $history);
        \Mockery::close();
    }

    public function testJwksForceRefreshBypassesPsr16Cache(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $jwksData = ['keys' => [$jwk]];

        $mockCache = \Mockery::mock(\Psr\SimpleCache\CacheInterface::class);
        $mockCache->shouldReceive('get')->with(\Mockery::pattern('/^wellknown_/'))->andReturn([
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/oauth2/authorize',
            'token_endpoint' => 'https://idp.test/oauth2/token',
            'jwks_uri' => 'https://idp.test/oauth2/jwks',
            'id_token_signing_alg_values_supported' => ['ES256', 'RS256'],
        ]);
        // JWKS cache should not be read (force refresh), but should be written after fetch
        $mockCache->shouldNotReceive('get')->with(\Mockery::pattern('/^jwks_/'));
        $mockCache->shouldReceive('set')->with(
            \Mockery::pattern('/^jwks_/'),
            \Mockery::on(fn($v) => is_array($v) && isset($v['keys'])),
            \Mockery::any()
        )->once();

        $history = [];
        $httpClient = TestHelper::httpClient([
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider = new TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => new \League\OAuth2\Client\Tool\RequestFactory(),
            'cache' => $mockCache,
        ]);

        // Call getJwks directly with forceRefresh=true
        $getJwks = \Closure::bind(
            fn() => $this->getJwks(true),
            $provider,
            $provider
        );

        // Need to set jwksUrl since well-known was loaded from cache
        $result = $getJwks();
        self::assertSame($jwksData, $result);
        // HTTP request was made despite cache
        self::assertCount(1, $history);
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

    public function testAuthorizationWithoutPARIncludesDpopThumbprintWhenConfigured(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'pushed_authorization_request_endpoint' => null,
            ]),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $url = $provider->getAuthorizationUrl();

        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);

        self::assertSame($provider->getDPopJwkThumbprint(), $params['dpop_jkt']);
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

    public function testAuthorizationWithPARPushesDpopThumbprintWhenConfigured(): void
    {
        [$privateKey, $publicKey] = TestHelper::generateEcKeyPair();
        $privPath = TestHelper::createTempKeyFile($privateKey);
        $pubPath = TestHelper::createTempKeyFile($publicKey);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse('urn:ietf:params:oauth:request_uri:dpop-123'),
        ], $history, [
            'dpopPrivateKeyPath' => $privPath,
            'dpopPublicKeyPath' => $pubPath,
        ]);

        $url = $provider->getAuthorizationUrl();

        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);
        self::assertSame('urn:ietf:params:oauth:request_uri:dpop-123', $params['request_uri']);
        self::assertArrayNotHasKey('dpop_jkt', $params);

        $parBody = (string)$history[1]['request']->getBody();
        parse_str($parBody, $parParams);
        self::assertSame($provider->getDPopJwkThumbprint(), $parParams['dpop_jkt']);
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

    public function testResourceOwnerMergesIdTokenClaimsWithUserinfo(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'email' => 'from-idtoken@example.com',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            // UserInfo response with matching sub
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'sub' => 'user-123',
                'name' => 'Alice',
            ])),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        // UserInfo fields take precedence, ID token identity claims are merged
        self::assertSame('user-123', $owner->getId());
        self::assertSame('Alice', $owner->toArray()['name']);
        // ID token claims like email should be merged in
        self::assertSame('from-idtoken@example.com', $owner->toArray()['email']);
        // Transport claims (nonce, at_hash, etc.) should NOT be present
        self::assertArrayNotHasKey('nonce', $owner->toArray());
    }

    public function testResourceOwnerUserinfoOverridesIdTokenClaims(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'email' => 'old@example.com',
            'name' => 'ID Token Name',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'sub' => 'user-123',
                'email' => 'updated@example.com',
                'name' => 'UserInfo Name',
            ])),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        // UserInfo values must take precedence over ID token values
        self::assertSame('updated@example.com', $owner->toArray()['email']);
        self::assertSame('UserInfo Name', $owner->toArray()['name']);
    }

    public function testWellKnownFileCacheIsReusedAcrossProviderInstances(): void
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

        // Second provider with same cacheDir should use file cache
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

    public function testWellKnownPsr16CacheExpiresAfterTtl(): void
    {
        $cacheDir = sys_get_temp_dir() . '/oauth2-oidc-wellknown-age-' . uniqid();
        @mkdir($cacheDir, 0700, true);
        $cache = new \Hvatum\OpenIDConnect\Client\Cache\FilesystemCache($cacheDir);

        $issuer = 'https://age-preservation.test';
        $wellKnownUrl = $issuer . '/.well-known/openid-configuration';
        $cacheKey = 'wellknown_' . md5($wellKnownUrl);
        $cache->set($cacheKey, [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer . '/oauth2/authorize',
            'token_endpoint' => $issuer . '/oauth2/token',
            'jwks_uri' => $issuer . '/oauth2/jwks',
        ], 1);

        $history1 = [];
        new \Hvatum\OpenIDConnect\Client\Test\TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => $issuer,
            'wellKnownUrl' => $wellKnownUrl,
            'cacheDir' => $cacheDir,
        ], [
            'httpClient' => TestHelper::httpClient([], $history1),
            'cache' => $cache,
        ]);

        self::assertCount(0, $history1, 'first provider should load discovery from PSR-16 cache');

        sleep(2);

        $history2 = [];
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Failed to fetch well-known configuration');
        new \Hvatum\OpenIDConnect\Client\Test\TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => $issuer,
            'wellKnownUrl' => $wellKnownUrl,
            'cacheDir' => $cacheDir,
        ], [
            'httpClient' => TestHelper::httpClient([], $history2),
            'cache' => $cache,
        ]);
    }

    public function testDefaultCacheDirIncludesUserNamespace(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        $getCacheDir = \Closure::bind(
            fn() => $this->getDefaultCacheDir(),
            $provider,
            $provider
        );

        $dir = $getCacheDir();

        // Should be under sys_get_temp_dir()/oauth2-oidc/ with a namespace segment
        self::assertStringStartsWith(sys_get_temp_dir() . '/oauth2-oidc/', $dir);
        // The namespace segment should be a sha256 hash or 'default'
        $namespace = basename($dir);
        self::assertMatchesRegularExpression('/^([a-f0-9]{64}|default)$/', $namespace);
    }

    public function testJwksPsr16CacheExpiresAfterTtl(): void
    {
        [, , $jwk] = TestHelper::generateEcKeyPair();

        $cacheDir = sys_get_temp_dir() . '/oauth2-oidc-jwks-age-' . uniqid();
        @mkdir($cacheDir, 0700, true);
        $cache = new \Hvatum\OpenIDConnect\Client\Cache\FilesystemCache($cacheDir);

        $issuer = 'https://idp.test';
        $wellKnownUrl = $issuer . '/.well-known/openid-configuration';
        $jwksUrl = $issuer . '/oauth2/jwks';

        $cache->set('wellknown_' . md5($wellKnownUrl), [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer . '/oauth2/authorize',
            'token_endpoint' => $issuer . '/oauth2/token',
            'jwks_uri' => $jwksUrl,
            'id_token_signing_alg_values_supported' => ['ES256', 'RS256'],
        ], 3600);
        $cache->set('jwks_' . md5($jwksUrl), ['keys' => [$jwk]], 1);

        $history = [];
        $provider = new \Hvatum\OpenIDConnect\Client\Test\TestProvider([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => $issuer,
            'wellKnownUrl' => $wellKnownUrl,
            'cacheDir' => $cacheDir,
        ], [
            'httpClient' => TestHelper::httpClient([], $history),
            'cache' => $cache,
        ]);

        $getJwks = \Closure::bind(
            fn() => $this->getJwks(false),
            $provider,
            $provider
        );

        self::assertSame(['keys' => [$jwk]], $getJwks(), 'first JWKS read should come from PSR-16 cache');

        sleep(2);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Failed to fetch JWKS');
        $getJwks();
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

    public function testDiscoveryRejectsMalformedIdTokenAlgMetadata(): void
    {
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('id_token_signing_alg_values_supported must be an array of strings');

        $history = [];
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                // Should be array<string>, but malformed OP responses can return a string.
                'id_token_signing_alg_values_supported' => 'RS256',
            ]),
        ], $history);
    }

    public function testFetchResourceOwnerDetailsThrowsOnNonJsonResponse(): void
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
            // UserInfo endpoint returns non-JSON
            new Response(200, ['Content-Type' => 'text/html'], '<html>Not JSON</html>'),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Expected JSON');

        $provider->getResourceOwner($token);
    }

    public function testGetIdTokenReturnsNullWhenNoTokenReceived(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            // Token response without id_token
            TestHelper::tokenResponse(),
        ], $history);

        $provider->getAccessToken('client_credentials');

        self::assertNull($provider->getIdToken());
    }

    public function testProviderCreatesDefaultCacheWhenNoneProvided(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
        ], $history);

        // The provider should have a cache instance even without explicit configuration
        $getCache = \Closure::bind(
            fn() => $this->cache,
            $provider,
            $provider
        );

        $cache = $getCache();
        self::assertInstanceOf(\Psr\SimpleCache\CacheInterface::class, $cache);
    }

    public function testUnsupportedPemKeyTypeThrowsError(): void
    {
        // Generate a DSA-like key that will have an unsupported kty — use an OKP (Ed25519)
        // Instead, we can test with a symmetric key PEM which isn't EC or RSA
        // The simplest approach: provide a valid EC PEM but mock the kty check
        // Actually, loadJwkFromPem only rejects non-EC/non-RSA kty values.
        // OKP keys from JWKFactory would produce kty=OKP which is unsupported.
        // Let's use sodium to generate an Ed25519 key if available, otherwise skip.
        if (!function_exists('sodium_crypto_sign_keypair')) {
            self::markTestSkipped('sodium extension required');
        }

        $keypair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($keypair);

        // Ed25519 private key in PKCS#8 PEM format
        // The DER encoding for Ed25519 private key wraps the 32-byte seed
        $seed = substr($secret, 0, 32);
        $der = hex2bin('302e020100300506032b6570042204') . bin2hex($seed);
        // Actually, let's build proper PKCS#8 DER
        $derBytes = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20" . $seed;
        $pem = "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($derBytes), 64, "\n") . "-----END PRIVATE KEY-----\n";

        $pemPath = TestHelper::createTempKeyFile($pem);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
        ], $history, [
            'privateKeyPath' => $pemPath,
            'keyId' => 'ed25519-test',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported key type in PEM');

        $provider->debugAccessTokenRequestFromGrant('client_credentials');
    }

    // ── token_endpoint_auth_methods_supported tests ──

    public function testAuthMethodAcceptsPrivateKeyJwt(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            ]),
            TestHelper::tokenResponse(),
        ], $history);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string) $request->getBody();
        parse_str($body, $params);
        self::assertArrayHasKey('client_assertion', $params);
    }

    public function testAuthMethodAcceptsClientSecretPost(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
            ]),
            TestHelper::tokenResponse(),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        self::assertNotNull($token);
    }

    public function testAuthMethodRejectsUnsupportedPrivateKeyJwt(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            ]),
        ], $history);

        $provider->setPkceCode('verifier');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Client uses private_key_jwt authentication but the authorization server does not support it');
        $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);
    }

    public function testAuthMethodRejectsUnsupportedClientSecretPost(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            ]),
        ], $history);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Client uses client_secret_post authentication but the authorization server does not support it');
        $provider->getAccessToken('client_credentials');
    }

    public function testAuthMethodSkipsValidationWhenNotAdvertised(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        self::assertNotNull($token);
    }

    // ── code_challenge_methods_supported tests ──

    public function testPkceAcceptsS256InServerList(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'code_challenge_methods_supported' => ['S256'],
            ]),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();
        // No exception = pass
        self::assertCount(2, $history); // well-known + PAR
    }

    public function testPkceAcceptsS256WithMultipleMethods(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'code_challenge_methods_supported' => ['plain', 'S256'],
            ]),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();
        self::assertCount(2, $history);
    }

    public function testPkceRejectsWhenS256NotInServerList(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'code_challenge_methods_supported' => ['plain'],
            ]),
        ], $history);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('PKCE method S256 is not supported by the authorization server');
        $provider->getAuthorizationUrl();
    }

    public function testPkceSkipsValidationWhenNotAdvertised(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();
        self::assertCount(2, $history);
    }

    // ── require_pushed_authorization_requests tests ──

    public function testRequirePARUsesParWhenEndpointAvailable(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'require_pushed_authorization_requests' => true,
            ]),
            TestHelper::parResponse(),
        ], $history);

        $url = $provider->getAuthorizationUrl();

        // PAR request was sent (well-known + PAR = 2 requests)
        self::assertCount(2, $history);

        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);
        self::assertArrayHasKey('request_uri', $params);
    }

    public function testRequirePARThrowsWhenNoEndpoint(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'require_pushed_authorization_requests' => true,
                'pushed_authorization_request_endpoint' => null,
            ]),
        ], $history);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('requires Pushed Authorization Requests');
        $provider->getAuthorizationUrl();
    }

    public function testPARUsedNormallyWhenNotRequired(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'require_pushed_authorization_requests' => false,
            ]),
            TestHelper::parResponse(),
        ], $history);

        $url = $provider->getAuthorizationUrl();

        // PAR is used because endpoint is available (even though not required)
        self::assertCount(2, $history);
        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);
        self::assertArrayHasKey('request_uri', $params);
    }

    public function testPARNotUsedWhenNotRequiredAndNoEndpoint(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'require_pushed_authorization_requests' => false,
                'pushed_authorization_request_endpoint' => null,
            ]),
        ], $history);

        $url = $provider->getAuthorizationUrl();

        // Only well-known fetch, no PAR
        self::assertCount(1, $history);
        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);
        self::assertArrayNotHasKey('request_uri', $params);
    }

    // -------------------------------------------------------------------------
    // Client assertion audience hook
    // -------------------------------------------------------------------------

    public function testClientAssertionAudienceDefaultsToTokenEndpoint(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string) $request->getBody();
        parse_str($body, $params);
        self::assertNotEmpty($params['client_assertion']);

        $payloadB64 = explode('.', $params['client_assertion'])[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertSame('https://idp.test/oauth2/token', $payload['aud']);
    }

    public function testSubclassCanOverrideClientAssertionAudience(): void
    {
        $history = [];
        $provider = IssuerAudienceTestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', ['code' => 'abc']);

        $body = (string) $request->getBody();
        parse_str($body, $params);

        $payloadB64 = explode('.', $params['client_assertion'])[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertSame('https://idp.test', $payload['aud']);
    }

    public function testParRequestUsesOverriddenClientAssertionAudience(): void
    {
        $history = [];
        $provider = IssuerAudienceTestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $provider->getAuthorizationUrl();

        // history[0] = well-known, history[1] = PAR
        $parBody = (string) $history[1]['request']->getBody();
        parse_str($parBody, $parParams);

        $payloadB64 = explode('.', $parParams['client_assertion'])[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertSame('https://idp.test', $payload['aud']);
    }

    // -------------------------------------------------------------------------
    // authorization_details (RFC 9396 - Rich Authorization Requests)
    // -------------------------------------------------------------------------

    public function testAuthorizationDetailsJsonEncodedForAuthCodeGrant(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $details = [['type' => 'payment_initiation', 'instructedAmount' => ['amount' => 100, 'currency' => 'EUR']]];

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', [
            'code' => 'abc',
            'authorization_details' => $details,
        ]);

        $body = (string) $request->getBody();
        parse_str($body, $params);

        self::assertArrayHasKey('authorization_details', $params);
        $decoded = json_decode($params['authorization_details'], true);
        self::assertSame('payment_initiation', $decoded[0]['type']);
    }

    public function testAuthorizationDetailsJsonEncodedForClientCredentials(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $details = [['type' => 'payment_initiation', 'instructedAmount' => ['amount' => 100, 'currency' => 'EUR']]];

        $request = $provider->debugAccessTokenRequestFromGrant('client_credentials', [
            'authorization_details' => $details,
        ]);

        $body = (string) $request->getBody();
        parse_str($body, $params);

        // RFC 9396: authorization_details must be present in the token request body.
        self::assertArrayHasKey('authorization_details', $params);
        $decoded = json_decode($params['authorization_details'], true);
        self::assertSame('payment_initiation', $decoded[0]['type']);

        // Default behavior does not copy authorization_details into client assertion claims.
        $payloadB64 = explode('.', $params['client_assertion'])[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertArrayNotHasKey('authorization_details', $payload);
    }

    public function testAuthorizationDetailsPassedAsStringIsPreserved(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $jsonStr = '[{"type":"payment_initiation"}]';

        $provider->setPkceCode('verifier');
        $request = $provider->debugAccessTokenRequestFromGrant('authorization_code', [
            'code' => 'abc',
            'authorization_details' => $jsonStr,
        ]);

        $body = (string) $request->getBody();
        parse_str($body, $params);

        // Pre-encoded string should be passed through as-is
        self::assertSame($jsonStr, $params['authorization_details']);
    }

    public function testAuthorizationDetailsJsonEncodedForAuthorizationRequestWithoutPAR(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse([
                'pushed_authorization_request_endpoint' => null,
            ]),
        ], $history);

        $details = [['type' => 'payment_initiation']];
        $url = $provider->getAuthorizationUrl([
            'authorization_details' => $details,
        ]);

        $parsed = parse_url($url);
        parse_str($parsed['query'], $params);
        self::assertArrayHasKey('authorization_details', $params);
        self::assertIsString($params['authorization_details']);
        self::assertSame('payment_initiation', json_decode($params['authorization_details'], true)[0]['type']);
    }

    public function testAuthorizationDetailsJsonEncodedForPARRequest(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        $details = [['type' => 'payment_initiation']];
        $provider->getAuthorizationUrl([
            'authorization_details' => $details,
        ]);

        $parBody = (string) $history[1]['request']->getBody();
        parse_str($parBody, $parParams);
        self::assertArrayHasKey('authorization_details', $parParams);
        self::assertIsString($parParams['authorization_details']);
        self::assertSame('payment_initiation', json_decode($parParams['authorization_details'], true)[0]['type']);
    }

    public function testRequestScopedAuthorizationDetailsAreRestoredWhenClientAssertionCreationFails(): void
    {
        $history = [];
        $provider = $this->createEmbeddingProfileProviderWithFailingFirstAssertion([
            TestHelper::wellKnownResponse(),
            TestHelper::parResponse(),
        ], $history);

        try {
            $provider->debugAccessTokenRequestFromGrant('client_credentials', [
                'authorization_details' => [['type' => 'payment_initiation']],
            ]);
            self::fail('Expected createClientAssertion() to fail on first call');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('forced assertion failure', $e->getMessage());
        }

        $provider->getAuthorizationUrl();

        $parRequest = $history[count($history) - 1]['request'];
        parse_str((string) $parRequest->getBody(), $parParams);
        $parPayloadB64 = explode('.', $parParams['client_assertion'])[1];
        $parPayload = json_decode(base64_decode(strtr($parPayloadB64, '-_', '+/')), true);

        self::assertArrayNotHasKey('authorization_details', $parPayload);
    }

    public function testInvalidAuthorizationDetailsFailsFast(): void
    {
        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
        ], $history);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('authorization_details');

        $provider->setPkceCode('verifier');
        $provider->debugAccessTokenRequestFromGrant('authorization_code', [
            'code' => 'abc',
            'authorization_details' => [[
                'type' => 'payment_initiation',
                'bad' => "\xB1\x31",
            ]],
        ]);
    }

    private function createEmbeddingProfileProviderWithFailingFirstAssertion(array $responses, array &$history): \Hvatum\OpenIDConnect\Client\Test\TestProvider
    {
        [$privateKey, , $jwk] = TestHelper::generateEcKeyPair();
        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);
        $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
        $jwk['kid'] = 'test-client-key';

        [$dpopPriv, $dpopPub, ] = TestHelper::generateEcKeyPair();

        $httpClient = TestHelper::httpClient($responses, $history);
        $requestFactory = new \League\OAuth2\Client\Tool\RequestFactory();

        return new class([
            'clientId' => 'client-123',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'privateKeyPath' => TestHelper::createTempKeyFile(json_encode($jwk)),
            'dpopPrivateKeyPath' => TestHelper::createTempKeyFile($dpopPriv),
            'dpopPublicKeyPath' => TestHelper::createTempKeyFile($dpopPub),
            'cacheDir' => sys_get_temp_dir() . '/oauth2-oidc-tests-' . uniqid(),
        ], [
            'httpClient' => $httpClient,
            'requestFactory' => $requestFactory,
        ]) extends \Hvatum\OpenIDConnect\Client\Test\TestProvider {
            private int $assertionCreateCalls = 0;

            protected function getAuthorizationDetailsForClientAssertion(array $params, ?array $authorizationDetails): ?array
            {
                if (($params['grant_type'] ?? '') !== 'client_credentials') {
                    return null;
                }

                return $authorizationDetails;
            }

            protected function shouldSendAuthorizationDetailsInTokenRequestBody(array $params, ?array $authorizationDetails): bool
            {
                return false;
            }

            protected function createClientAssertion(string $audience, ?int $expiresIn = null): string
            {
                $this->assertionCreateCalls++;
                if ($this->assertionCreateCalls === 1) {
                    throw new \RuntimeException('forced assertion failure for test');
                }
                return parent::createClientAssertion($audience, $expiresIn);
            }
        };
    }

}
