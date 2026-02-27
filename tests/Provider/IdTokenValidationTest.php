<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Provider;

use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;

final class IdTokenValidationTest extends TestCase
{
    public function testRejectsMismatchingNonce(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'expected',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('different');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $provider->validateIdToken($idToken);
    }

    public function testAcceptsSubClaimWithZeroValue(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => '0',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');

        $result = $provider->validateIdToken($idToken);
        self::assertSame('0', $result['sub']);
    }

    public function testRejectsMissingSubClaim(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
            // deliberately omitting 'sub'
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('missing required sub claim');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsMissingIssWhenAsAdvertisesSupport(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'authorization_response_iss_parameter_supported' => true,
            ]),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');
        // Do NOT set callbackIssuer — simulating missing iss in callback

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('missing the iss parameter');
        $provider->validateIdToken($idToken);
    }

    public function testAllowsMissingIssWhenAsDoesNotAdvertiseSupport(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),  // no iss param support flag
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');
        // No callbackIssuer set — should be fine since AS doesn't advertise support

        $result = $provider->validateIdToken($idToken);
        self::assertSame('user-1', $result['sub']);
    }

    public function testAllowsMissingIssWhenEnforcementDisabled(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse([
                'authorization_response_iss_parameter_supported' => true,
            ]),
            TestHelper::jwksResponse($jwk),
        ], $history, [
            'enforceIssuerIdentification' => false,
        ]);

        $provider->setNonce('n-1');
        // No callbackIssuer set but enforcement is disabled

        $result = $provider->validateIdToken($idToken);
        self::assertSame('user-1', $result['sub']);
    }

    public function testValidatesSignatureAndClaims(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $claims = [
            'iss' => 'https://idp.test',
            'sub' => 'user-456',
            'aud' => ['client-123'],
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ];

        $idToken = TestHelper::signIdToken($claims, $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $jwksRef = new \ReflectionMethod($provider, 'getJwks');
        $jwksRef->setAccessible(true);
        try {
            $jwksRef->invoke($provider);
        } catch (\Throwable $e) {
            // allow validation to surface assertion failures later
        }

        self::assertGreaterThanOrEqual(1, count($history));
        self::assertSame('https://idp.test/.well-known/openid-configuration', (string)$history[0]['request']->getUri());
        if (isset($history[1])) {
            self::assertSame('https://idp.test/oauth2/jwks', (string)$history[1]['request']->getUri());
        }

        $provider->setNonce('n-1');

        $result = $provider->validateIdToken($idToken);

        self::assertSame('https://idp.test', $result['iss']);
        self::assertSame('client-123', $result['aud'][0]);
        self::assertSame('n-1', $result['nonce']);
    }
}
