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

    public function testValidatesSignatureAndClaims(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $claims = [
            'iss' => 'https://idp.test',
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
