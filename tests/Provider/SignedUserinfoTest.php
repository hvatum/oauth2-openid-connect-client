<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Provider;

use GuzzleHttp\Psr7\Response;
use Hvatum\OpenIDConnect\Client\Test\TestHelper;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use PHPUnit\Framework\TestCase;

/**
 * Signed JWT userinfo responses (OIDC Core §5.3.2 / §5.3.4)
 *
 * The userinfo endpoint may return a compact JWS with content-type
 * application/jwt instead of plain JSON. The provider must verify the
 * signature against its JWKS, require iss/aud/sub, check time claims only
 * when present, and strip the JWT envelope before the resource-owner merge.
 */
final class SignedUserinfoTest extends TestCase
{
    private function userinfoClaims(array $overrides = []): array
    {
        return array_merge([
            'iss' => 'https://idp.test',
            'aud' => 'client-123',
            'sub' => 'user-123',
            'name' => 'Alice',
            'email' => 'alice@example.com',
        ], $overrides);
    }

    public function testSignedUserinfoIsVerifiedAndMergedIntoResourceOwner(): void
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
            TestHelper::wellKnownResponse(['userinfo_signing_alg_values_supported' => ['ES256']]),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::signedUserinfoResponse($this->userinfoClaims(), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
        self::assertSame('Alice', $owner->toArray()['name']);
        // Userinfo wins over ID token, exactly as with plain JSON userinfo
        self::assertSame('alice@example.com', $owner->toArray()['email']);
    }

    public function testSignedUserinfoFallsBackToIdTokenAlgsWhenNotAdvertised(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        // Default wellKnownResponse() has no userinfo_signing_alg_values_supported;
        // id_token_signing_alg_values_supported includes ES256.
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims(), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
    }

    public function testSignedUserinfoRejectsDisallowedAlgorithm(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(['userinfo_signing_alg_values_supported' => ['RS256']]),
            TestHelper::tokenResponse(),
            // JWT is signed with ES256, but the server only advertises RS256 for userinfo
            TestHelper::signedUserinfoResponse($this->userinfoClaims(), $private, $jwk['kid']),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage("Invalid UserInfo response algorithm: 'ES256'");
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoRejectsAlgNone(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            new Response(200, ['Content-Type' => 'application/jwt'], TestHelper::buildRawJwt(
                ['alg' => 'none', 'typ' => 'JWT'],
                $this->userinfoClaims()
            )),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('UserInfo response');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoRejectsTamperedSignature(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $jwt = TestHelper::signIdToken($this->userinfoClaims(), $private, $jwk['kid']);

        // Swap the payload for different claims, keeping the original signature
        $parts = explode('.', $jwt);
        $parts[1] = TestHelper::base64UrlEncode(json_encode(
            $this->userinfoClaims(['sub' => 'attacker']),
            JSON_UNESCAPED_SLASHES
        ));
        $tampered = implode('.', $parts);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            new Response(200, ['Content-Type' => 'application/jwt'], $tampered),
            // Verification fails, triggering one forced JWKS refresh — two responses needed
            TestHelper::jwksResponse($jwk),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Failed to validate UserInfo response: Signature verification failed');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoRetriesJwksOnceOnKeyRotation(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        [, , $staleJwk] = TestHelper::generateEcKeyPair();
        $staleJwk['kid'] = $jwk['kid']; // same kid, rotated key material

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims(), $private, $jwk['kid']),
            TestHelper::jwksResponse($staleJwk), // stale key: verification fails
            TestHelper::jwksResponse($jwk),      // forced refresh: current key
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
        $jwksFetches = array_filter(
            $history,
            static fn(array $t): bool => str_contains((string) $t['request']->getUri(), '/jwks')
        );
        self::assertCount(2, $jwksFetches);
    }

    public function testSignedUserinfoRejectsMissingSub(): void
    {
        $this->assertClaimRejection(['sub' => null], 'UserInfo response claim validation failed');
    }

    public function testSignedUserinfoRejectsMissingIss(): void
    {
        $this->assertClaimRejection(['iss' => null], 'UserInfo response claim validation failed');
    }

    public function testSignedUserinfoRejectsWrongAudience(): void
    {
        $this->assertClaimRejection(['aud' => 'other-client'], 'UserInfo response claim validation failed');
    }

    public function testSignedUserinfoRejectsExpiredExp(): void
    {
        // exp is not required on userinfo responses, but when present it is enforced
        $this->assertClaimRejection(['exp' => time() - 3600], 'UserInfo response claim validation failed');
    }

    private function assertClaimRejection(array $claimOverrides, string $expectedMessage): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $claims = array_filter(
            $this->userinfoClaims($claimOverrides),
            static fn($v): bool => $v !== null
        );

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($claims, $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage($expectedMessage);
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoAcceptsMissingExpAndIat(): void
    {
        // OIDC Core §5.3.2 does not require exp/iat/nbf on userinfo responses
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims(), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
    }

    public function testSignedUserinfoRejectsJweResponse(): void
    {
        // A compact JWE: five segments, protected header with an "enc" member
        $jweHeader = TestHelper::base64UrlEncode(json_encode(
            ['alg' => 'RSA-OAEP', 'enc' => 'A256GCM'],
            JSON_UNESCAPED_SLASHES
        ));

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            new Response(200, ['Content-Type' => 'application/jwt'], $jweHeader . '.key.iv.ciphertext.tag'),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Encrypted (JWE) UserInfo responses are not supported');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoGarbageWithFiveSegmentsIsAFormatErrorNotJwe(): void
    {
        // Not a JWE — the first segment does not decode to a header with "enc".
        // Must be diagnosed as malformed, not as an encryption-support problem.
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            new Response(200, ['Content-Type' => 'application/jwt'], 'aaa.bbb.ccc.ddd.eee'),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Invalid UserInfo response format');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoSubMismatchWithIdTokenRejected(): void
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
            TestHelper::signedUserinfoResponse(
                $this->userinfoClaims(['sub' => 'someone-else']),
                $private,
                $jwk['kid']
            ),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('UserInfo sub claim does not match ID token sub claim');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoStripsEnvelopeClaims(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();
        $idTokenExp = time() + 3600;
        $idToken = TestHelper::signIdToken([
            'iss' => 'https://idp.test',
            'sub' => 'user-123',
            'aud' => 'client-123',
            'exp' => $idTokenExp,
            'iat' => time(),
        ], $private, $jwk['kid']);

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(['id_token' => $idToken]),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'exp' => time() + 100, // JWT envelope, must not survive the merge
                'iat' => time() - 5,
                'nbf' => time() - 5,
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token)->toArray();

        // The ID token's own claims survive; the userinfo JWT envelope does not
        self::assertSame($idTokenExp, $owner['exp']);
        self::assertArrayNotHasKey('nbf', $owner);
        self::assertSame('Alice', $owner['name']);
    }

    public function testSignedUserinfoAcceptsContentTypeWithParameters(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse(
                $this->userinfoClaims(),
                $private,
                $jwk['kid'],
                'application/jwt; charset=utf-8'
            ),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
    }

    public function testSignedUserinfoErrorStatusThrowsIdentityProviderException(): void
    {
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            // HTTP error with jwt content type must map via checkResponse, not JWT parsing
            new Response(401, ['Content-Type' => 'application/jwt'], ''),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Unauthorized');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoRejectsAzpNamingAnotherClient(): void
    {
        // An azp naming a different party marks a JWT minted for another
        // client; aud membership alone must not let it through.
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'aud' => ['client-123', 'other-client'],
                'azp' => 'other-client',
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('UserInfo response azp mismatch');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoAcceptsMultipleAudiencesWithoutAzp(): void
    {
        // OIDC Core §5.3.2: aud need only *include* the client ID; unlike ID
        // tokens (§3.1.3.7) there is no azp requirement for multiple audiences.
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'aud' => ['client-123', 'other-client'],
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
    }

    public function testSignedUserinfoRejectsMismatchedAzpEvenWithSingleAudience(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'azp' => 'other-client',
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('UserInfo response azp mismatch');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoHonorsAllowedAuthorizedParties(): void
    {
        // The azp acceptance policy governs userinfo too, so an allow-listed
        // foreign azp passes; it is still stripped from the resource owner
        // as a transport claim.
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'azp' => 'trusted-native-app',
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history, ['allowedAuthorizedParties' => ['trusted-native-app']]);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
        self::assertArrayNotHasKey('azp', $owner->toArray());
    }

    public function testSignedUserinfoRejectsAllowListedAzpWithMultipleAudiences(): void
    {
        // Same invariant as ID tokens: an allow-listed presenter is trusted
        // with tokens minted solely for this client, not with multi-audience
        // tokens minted for the presenter itself.
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'aud' => ['client-123', 'trusted-native-app'],
                'azp' => 'trusted-native-app',
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history, ['allowedAuthorizedParties' => ['trusted-native-app']]);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('azp must name this client');
        $provider->getResourceOwner($token);
    }

    public function testSignedUserinfoAcceptsMultipleAudiencesWithMatchingAzp(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'aud' => ['client-123', 'other-client'],
                'azp' => 'client-123',
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
    }

    public function testSignedUserinfoStripsIdTokenTransportClaims(): void
    {
        // createResourceOwner() filters nonce/auth_time/azp/acr/amr/at_hash
        // from the ID token; a signed userinfo JWT must not re-introduce them.
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims([
                'nonce' => 'reused-nonce',
                'auth_time' => time() - 30,
                'acr' => 'urn:mace:incommon:iap:silver',
                'amr' => ['pwd'],
                'azp' => 'client-123',
            ]), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token)->toArray();

        self::assertSame('Alice', $owner['name']);
        foreach (['nonce', 'auth_time', 'acr', 'amr', 'azp', 'at_hash'] as $claim) {
            self::assertArrayNotHasKey($claim, $owner);
        }
    }

    public function testSignedUserinfoErrorPayloadSurvivesJwtContentType(): void
    {
        // Servers that pin Content-Type: application/jwt on the endpoint keep
        // it on error statuses while the body is a JSON error document.
        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(),
            TestHelper::tokenResponse(),
            new Response(400, ['Content-Type' => 'application/jwt'], json_encode([
                'error' => 'invalid_token',
                'error_description' => 'Access token expired',
            ])),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('Access token expired');
        $provider->getResourceOwner($token);
    }

    public function testExplicitlyEmptyUserinfoSigningAlgsFallsBackToIdTokenAlgs(): void
    {
        [$private, , $jwk] = TestHelper::generateEcKeyPair();

        $history = [];
        $provider = TestHelper::basicProvider([
            TestHelper::wellKnownResponse(['userinfo_signing_alg_values_supported' => []]),
            TestHelper::tokenResponse(),
            TestHelper::signedUserinfoResponse($this->userinfoClaims(), $private, $jwk['kid']),
            TestHelper::jwksResponse($jwk),
        ], $history);

        $token = $provider->getAccessToken('client_credentials');
        $owner = $provider->getResourceOwner($token);

        self::assertSame('user-123', $owner->getId());
    }

    public function testMalformedUserinfoSigningAlgsInDiscoveryRejected(): void
    {
        $history = [];

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('userinfo_signing_alg_values_supported must be an array of strings');
        TestHelper::basicProvider([
            TestHelper::wellKnownResponse(['userinfo_signing_alg_values_supported' => 'RS256']),
        ], $history);
    }
}
