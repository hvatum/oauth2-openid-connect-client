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
        $this->expectExceptionMessage('sub');
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

    public function testRejectsIdTokenMissingNonceWhenNonceWasSent(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        // Token WITHOUT nonce — but nonce was sent in auth request
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            // deliberately omitting 'nonce'
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('expected-nonce');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('nonce');
        $provider->validateIdToken($idToken);
    }

    public function testAcceptsIdTokenWithoutNonceWhenNoneWasSent(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        // Token without nonce — no nonce was sent in auth request either
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        // Do NOT set nonce — validates without nonce requirement
        $result = $provider->validateIdToken($idToken);
        self::assertSame('user-1', $result['sub']);
    }

    public function testRejectsMissingMandatoryClaims(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        // Token missing 'exp' — should be rejected by mandatory claims check
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'iat' => time(),
            'nonce' => 'n-1',
            // deliberately omitting 'exp'
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('exp');
        $provider->validateIdToken($idToken);
    }

    public function testValidatesSignatureAndClaims(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-456',
            'aud' => ['client-123'],
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

        self::assertSame('https://idp.test', $result['iss']);
        self::assertSame('client-123', $result['aud'][0]);
        self::assertSame('n-1', $result['nonce']);
    }

    // --- Security tests ---

    public function testRejectsWrongSignature(): void
    {
        // Sign with key A, provide key B in JWKS
        [$privateA, , ] = TestHelper::generateEcKeyPair();
        [, , $jwkB] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'n-1',
        ], $privateA, $jwkB['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwkB),
        ], $history);

        $provider->setNonce('n-1');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Signature verification failed');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsExpiredIdToken(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'client-123',
            'exp' => time() - 3600, // expired 1 hour ago
            'iat' => time() - 7200,
            'nonce' => 'n-1',
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('exp');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsWrongIssuer(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://evil.example.com',
            'sub' => 'user-1',
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

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('iss');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsWrongAudience(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => 'wrong-client',
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

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('aud');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsAlgorithmNone(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::buildRawJwt(
            ['alg' => 'none', 'typ' => 'JWT', 'kid' => $jwk['kid']],
            [
                'iss' => 'https://idp.test',
                'sub' => 'user-1',
                'aud' => 'client-123',
                'exp' => time() + 3600,
                'iat' => time(),
            ]
        );

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid ID token algorithm');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsHmacAlgorithm(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::buildRawJwt(
            ['alg' => 'HS256', 'typ' => 'JWT', 'kid' => $jwk['kid']],
            [
                'iss' => 'https://idp.test',
                'sub' => 'user-1',
                'aud' => 'client-123',
                'exp' => time() + 3600,
                'iat' => time(),
            ]
        );

        $history = [];
        $provider = TestHelper::fullProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid ID token algorithm');
        $provider->validateIdToken($idToken);
    }

    public function testRejectsCallbackIssuerMismatch(): void
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
            TestHelper::wellKnownResponse(),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $provider->setNonce('n-1');
        $provider->setCallbackIssuer('https://evil.example.com');

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('Issuer mismatch');
        $provider->validateIdToken($idToken);
    }

    public function testMultipleAudiencesWithCorrectAzp(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => ['client-123', 'other-client'],
            'azp' => 'client-123',
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
        self::assertSame('user-1', $result['sub']);
        self::assertSame('client-123', $result['azp']);
    }

    public function testMultipleAudiencesWithWrongAzp(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => ['client-123', 'other-client'],
            'azp' => 'other-client',
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

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('azp');
        $provider->validateIdToken($idToken);
    }

    public function testMultipleAudiencesWithMissingAzp(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-1',
            'aud' => ['client-123', 'other-client'],
            // deliberately omitting 'azp'
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

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('azp');
        $provider->validateIdToken($idToken);
    }
}
