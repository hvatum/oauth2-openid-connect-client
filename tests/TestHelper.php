<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use League\OAuth2\Client\Tool\RequestFactory;

final class TestHelper
{
    public static function httpClient(array $responses, array &$history): Client
    {
        $mock = new MockHandler($responses);
        $historyMiddleware = Middleware::history($history);
        $stack = HandlerStack::create($mock);
        $stack->push($historyMiddleware);

        return new Client(['handler' => $stack]);
    }

    public static function wellKnownResponse(array $overrides = []): Response
    {
        $body = array_merge([
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/oauth2/authorize',
            'token_endpoint' => 'https://idp.test/oauth2/token',
            'userinfo_endpoint' => 'https://idp.test/oauth2/userinfo',
            'jwks_uri' => 'https://idp.test/oauth2/jwks',
            'pushed_authorization_request_endpoint' => 'https://idp.test/oauth2/par',
        ], $overrides);

        return new Response(200, ['Content-Type' => 'application/json'], json_encode($body));
    }

    public static function jwksResponse(array $jwk): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => [$jwk]]));
    }

    public static function tokenResponse(array $overrides = []): Response
    {
        $body = array_merge([
            'access_token' => 'token123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ], $overrides);

        return new Response(200, ['Content-Type' => 'application/json'], json_encode($body));
    }

    public static function parResponse(string $requestUri = 'urn:ietf:params:oauth:request_uri:test-123'): Response
    {
        return new Response(201, ['Content-Type' => 'application/json'], json_encode([
            'request_uri' => $requestUri,
            'expires_in' => 60,
        ]));
    }

    /**
     * Create a provider with issuer (no client assertion, no DPoP)
     */
    public static function basicProvider(array $responses, array &$history, array $options = []): TestProvider
    {
        \Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider::clearWellKnownCache();

        $httpClient = self::httpClient($responses, $history);
        $requestFactory = new RequestFactory();

        $provider = new TestProvider(array_merge([
            'clientId' => 'client-123',
            'clientSecret' => 'secret-456',
            'redirectUri' => 'https://app.example/callback',
            'issuer' => 'https://idp.test',
            'cacheDir' => sys_get_temp_dir() . '/oauth2-oidc-tests-' . uniqid(),
        ], $options), [
            'httpClient' => $httpClient,
            'requestFactory' => $requestFactory,
        ]);

        return $provider;
    }

    /**
     * Create a provider with client assertion and DPoP configured
     */
    public static function fullProvider(array $responses, array &$history, array $options = []): TestProvider
    {
        // Auto-generate client assertion key if not provided
        if (!isset($options['privateKeyPath'])) {
            [$privateKey, , $jwk] = self::generateEcKeyPair();
            $resource = openssl_pkey_get_private($privateKey);
            $details = openssl_pkey_get_details($resource);
            $jwk['d'] = rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '=');
            $jwk['kid'] = 'test-client-key';
            $options['privateKeyPath'] = self::createTempKeyFile(json_encode($jwk));
        }

        // Auto-generate DPoP keys if not provided
        if (!isset($options['dpopPrivateKeyPath']) || !isset($options['dpopPublicKeyPath'])) {
            [$dpopPriv, $dpopPub, ] = self::generateEcKeyPair();
            $options['dpopPrivateKeyPath'] = self::createTempKeyFile($dpopPriv);
            $options['dpopPublicKeyPath'] = self::createTempKeyFile($dpopPub);
        }

        // Remove clientSecret since we're using client assertion
        unset($options['clientSecret']);

        return self::basicProvider($responses, $history, $options);
    }

    public static function generateEcKeyPair(): array
    {
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ];

        $resource = openssl_pkey_new($config);
        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);
        $publicKey = $details['key'];

        $x = rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '=');

        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'use' => 'sig',
            'kid' => 'test-key',
            'x' => $x,
            'y' => $y,
            'alg' => 'ES256',
        ];

        return [$privateKey, $publicKey, $jwk];
    }

    public static function createTempKeyFile(string $key): string
    {
        $path = tempnam(sys_get_temp_dir(), 'key_');
        file_put_contents($path, $key);
        return $path;
    }

    /**
     * Build a raw JWT with an arbitrary header (for algorithm confusion tests).
     * The signature is faked — this is for testing header validation, not crypto.
     */
    public static function buildRawJwt(array $header, array $payload): string
    {
        $encode = fn(array $data) => rtrim(strtr(
            base64_encode(json_encode($data, JSON_UNESCAPED_SLASHES)),
            '+/',
            '-_'
        ), '=');

        $h = $encode($header);
        $p = $encode($payload);
        // Fake signature (non-empty so it looks like a real compact JWT)
        $s = rtrim(strtr(base64_encode('fake-signature'), '+/', '-_'), '=');

        return "{$h}.{$p}.{$s}";
    }

    public static function tokenErrorResponse(int $status, string $error, string $description = ''): Response
    {
        $body = ['error' => $error];
        if ($description !== '') {
            $body['error_description'] = $description;
        }
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body));
    }

    public static function signIdToken(array $claims, string $privateKey, string $kid): string
    {
        // Convert PEM private key to JWK
        $resource = openssl_pkey_get_private($privateKey);
        $details = openssl_pkey_get_details($resource);

        $jwkData = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '='),
            'd' => rtrim(strtr(base64_encode($details['ec']['d']), '+/', '-_'), '='),
        ];

        $jwk = new JWK($jwkData);

        // Build and sign JWT
        $algorithmManager = new AlgorithmManager([new ES256()]);
        $jwsBuilder = new JWSBuilder($algorithmManager);

        $payload = json_encode($claims, JSON_UNESCAPED_SLASHES);
        $header = ['alg' => 'ES256', 'typ' => 'JWT', 'kid' => $kid];

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();

        $serializer = new CompactSerializer();
        return $serializer->serialize($jws, 0);
    }
}
