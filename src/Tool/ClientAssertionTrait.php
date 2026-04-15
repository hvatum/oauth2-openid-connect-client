<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Client Assertion Trait
 *
 * Implements private_key_jwt client authentication (RFC 7523)
 * Supports EC (ES256/384/512) and RSA (RS256/384/512, PS256/384/512) keys
 * Supports both PEM and JWK key formats
 *
 * Uses web-token/jwt-framework for JWT signing
 */
trait ClientAssertionTrait
{
    /**
     * Forbidden algorithms (insecure)
     * @var array<string>
     */
    protected static array $forbiddenAlgorithms = ['NONE', 'HS256', 'HS384', 'HS512'];

    /**
     * Supported algorithms for client assertions
     * @var array<string>
     */
    protected static array $allowedAlgorithms = [
        'ES256', 'ES384', 'ES512',
        'RS256', 'RS384', 'RS512',
        'PS256', 'PS384', 'PS512',
    ];

    /**
     * Map key type to default algorithm
     * @var array<string, string>
     */
    protected static array $ktyToAlg = [
        'EC' => 'ES256',
        'RSA' => 'RS256',
    ];

    /**
     * Resolved raw private key material (PEM or JWK JSON). Populated by
     * initializeClientAssertion() whether the input was a filesystem path or
     * raw content.
     */
    protected ?string $clientAssertionPrivateKeyContent = null;

    /**
     * Key ID for client assertions
     */
    protected ?string $clientAssertionKeyId = null;

    /**
     * Cached JWK object
     */
    protected ?JWK $clientAssertionJwk = null;

    /**
     * Key algorithm (ES256 or RS256)
     */
    protected string $clientAssertionAlgorithm = 'RS256';

    /**
     * Initialize client assertion with raw private key content.
     *
     * Callers pass already-loaded PEM or JWK content. The provider constructor
     * is responsible for reading filesystem paths via the `privateKeyPath`
     * option before reaching this method.
     *
     * @param string $privateKeyContent Raw PEM or JWK JSON content
     * @param string|null $keyId Key ID (kid) - if null, will be extracted from JWK
     */
    protected function initializeClientAssertion(string $privateKeyContent, ?string $keyId = null): void
    {
        $this->clientAssertionKeyId = $keyId;
        $this->clientAssertionPrivateKeyContent = $privateKeyContent;
    }

    /**
     * Check if client assertion is configured
     *
     * @return bool
     * @codeCoverageIgnore
     */
    protected function hasClientAssertion(): bool
    {
        return $this->clientAssertionPrivateKeyContent !== null;
    }

    /**
     * Authorization details to embed in client assertion JWT (RFC 9396 + profile-specific)
     */
    protected ?array $clientAuthorizationDetails = null;

    /**
     * Set authorization details for embedding in client assertion JWT.
     *
     * @param array|null $details
     * @codeCoverageIgnore
     */
    public function setClientAuthorizationDetails(?array $details): void
    {
        $this->clientAuthorizationDetails = $details;
    }

    /**
     * Create a client assertion JWT
     *
     * @param string $audience Token endpoint URL
     * @param int|null $expiresIn Expiration time in seconds (defaults to CLIENT_ASSERTION_TTL)
     * @return string Signed JWT
     * @throws \RuntimeException
     */
    protected function createClientAssertion(string $audience, ?int $expiresIn = null): string
    {
        if (!$this->hasClientAssertion()) {
            throw new \RuntimeException('Client assertion not configured');
        }

        $expiresIn = $expiresIn ?? static::CLIENT_ASSERTION_TTL;

        // Load JWK first (this detects the actual algorithm from the key)
        $jwk = $this->getClientAssertionJwk();

        // Validate algorithm against server's advertised list (if available)
        if ($this->tokenEndpointAuthSigningAlgValuesSupported !== null
            && !in_array($this->clientAssertionAlgorithm, $this->tokenEndpointAuthSigningAlgValuesSupported, true)
        ) {
            throw new \RuntimeException(
                sprintf(
                    'Client assertion algorithm "%s" is not supported by the authorization server. Supported: %s',
                    $this->clientAssertionAlgorithm,
                    implode(', ', $this->tokenEndpointAuthSigningAlgValuesSupported)
                )
            );
        }

        // Verify kid is available
        if ($this->clientAssertionKeyId === null) {
            throw new \RuntimeException(
                'Key ID (kid) not configured and not found in JWK file. ' .
                'Either provide keyId in configuration or use a JWK file with a kid property.'
            );
        }

        $now = time();

        // Build payload
        $payloadData = [
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'aud' => $audience,
            'jti' => bin2hex(random_bytes(16)),
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $expiresIn,
        ];

        // Embed authorization_details in JWT when set by profile-specific extension hooks
        if ($this->clientAuthorizationDetails !== null) {
            $payloadData['authorization_details'] = $this->clientAuthorizationDetails;
        }

        $payload = json_encode($payloadData, JSON_UNESCAPED_SLASHES);

        // Build header
        $header = [
            'alg' => $this->clientAssertionAlgorithm,
            'typ' => 'client-authentication+jwt',
            'kid' => $this->clientAssertionKeyId,
        ];

        // Create algorithm manager based on key type
        $algorithmManager = $this->createAlgorithmManager();

        // Build and sign the JWT
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();

        // Serialize to compact format
        $serializer = new CompactSerializer();
        return $serializer->serialize($jws, 0);
    }

    /**
     * Create algorithm manager based on configured algorithm
     *
     * @return AlgorithmManager
     */
    protected function createAlgorithmManager(): AlgorithmManager
    {
        $algorithms = [
            'ES256' => ES256::class, 'ES384' => ES384::class, 'ES512' => ES512::class,
            'RS256' => RS256::class, 'RS384' => RS384::class, 'RS512' => RS512::class,
            'PS256' => PS256::class, 'PS384' => PS384::class, 'PS512' => PS512::class,
        ];

        $alg = $this->clientAssertionAlgorithm;
        if (!isset($algorithms[$alg])) {
            throw new \RuntimeException("Unsupported algorithm: {$alg}");
        }

        return new AlgorithmManager([new $algorithms[$alg]()]);
    }

    /**
     * Get JWK for client assertion (loads and caches)
     *
     * @return JWK
     * @throws \RuntimeException
     */
    protected function getClientAssertionJwk(): JWK
    {
        if ($this->clientAssertionJwk !== null) {
            return $this->clientAssertionJwk;
        }

        if ($this->clientAssertionPrivateKeyContent === null) {
            throw new \RuntimeException(
                'Client assertion private key is not configured. '
                . 'Supply `privateKey` (raw PEM/JWK) or `privateKeyPath` (filesystem path) at construction.'
            );
        }

        $jwk = KeyMaterialParser::parseToJwk(
            $this->clientAssertionPrivateKeyContent,
            'Client assertion private key'
        );

        $this->clientAssertionJwk = $this->postProcessClientAssertionJwk($jwk);
        return $this->clientAssertionJwk;
    }

    /**
     * Apply client-assertion-specific bookkeeping to a freshly parsed JWK:
     * extract the kid (if not already configured), pick the signing algorithm,
     * and normalize the kty casing so the web-token signer accepts it.
     *
     * Works for any source format — PEM, DER, or JWK JSON — because the
     * parser hands us a JWK and we only inspect its fields here.
     *
     * @throws \RuntimeException for unsupported, forbidden, or missing alg/kty
     */
    private function postProcessClientAssertionJwk(JWK $jwk): JWK
    {
        if ($this->clientAssertionKeyId === null && $jwk->has('kid')) {
            $this->clientAssertionKeyId = $jwk->get('kid');
        }

        $kty = strtoupper($jwk->get('kty'));
        $alg = $jwk->has('alg') ? strtoupper($jwk->get('alg')) : null;

        if ($alg !== null) {
            if (in_array($alg, static::$forbiddenAlgorithms, true)) {
                throw new \RuntimeException(
                    "Algorithm '{$jwk->get('alg')}' is not allowed for client assertions"
                );
            }
            if (!in_array($alg, static::$allowedAlgorithms, true)) {
                throw new \RuntimeException(
                    "Unsupported algorithm '{$jwk->get('alg')}' for client assertion. "
                    . 'Allowed: ' . implode(', ', static::$allowedAlgorithms)
                );
            }
            $this->clientAssertionAlgorithm = $alg;
        } elseif (isset(static::$ktyToAlg[$kty])) {
            $this->clientAssertionAlgorithm = static::$ktyToAlg[$kty];
        } else {
            throw new \RuntimeException(
                "Unsupported key type '{$jwk->get('kty')}' for client assertion. "
                . 'Supported: ' . implode(', ', array_keys(static::$ktyToAlg))
            );
        }

        // web-token requires uppercase kty for signing; JWK JSON callers may
        // supply lowercase ('rsa', 'ec'), so normalize once here.
        $data = $jwk->all();
        if (isset($data['kty']) && $data['kty'] !== strtoupper($data['kty'])) {
            $data['kty'] = strtoupper($data['kty']);
            return new JWK($data);
        }

        return $jwk;
    }
}
