<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Provider;

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

        // Audience should be the PAR endpoint URL (RFC 7523 §3)
        $assertion = $parParams['client_assertion'];
        $payloadB64 = explode('.', $assertion)[1];
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
        self::assertSame('https://idp.test/oauth2/par', $payload['aud']);
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
        // Verify the custom well-known URL was fetched
        self::assertSame(
            'https://idp.test/custom/.well-known/openid-configuration',
            (string) $history[0]['request']->getUri()
        );
    }
}
