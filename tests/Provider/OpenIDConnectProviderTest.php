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
}
