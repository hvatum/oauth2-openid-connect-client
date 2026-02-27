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
     * Map of supported algorithms
     * @var array<string, string>
     */
    protected static array $algFamily = [
        'ES256' => 'ES256', 'ES384' => 'ES384', 'ES512' => 'ES512',
        'RS256' => 'RS256', 'RS384' => 'RS384', 'RS512' => 'RS512',
        'PS256' => 'PS256', 'PS384' => 'PS384', 'PS512' => 'PS512',
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
     * Private key path for client assertions
     */
    protected ?string $clientAssertionPrivateKeyPath = null;

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
     * Initialize client assertion with private key
     *
     * @param string $privateKeyPath Path to PEM or JWK private key file
     * @param string|null $keyId Key ID (kid) - if null, will be extracted from JWK file
     */
    protected function initializeClientAssertion(string $privateKeyPath, ?string $keyId = null): void
    {
        $this->clientAssertionPrivateKeyPath = $privateKeyPath;
        $this->clientAssertionKeyId = $keyId;
    }

    /**
     * Check if client assertion is configured
     *
     * @return bool
     */
    protected function hasClientAssertion(): bool
    {
        return $this->clientAssertionPrivateKeyPath !== null;
    }

    /**
     * Assertion details for client assertion (organization info for M2M)
     */
    protected ?array $clientAssertionDetails = null;

    /**
     * Set assertion details for client assertion (for M2M organization delegation)
     *
     * @param array|null $details
     */
    public function setClientAssertionDetails(?array $details): void
    {
        $this->clientAssertionDetails = $details;
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

        // Load JWK (this may extract kid from JWK file)
        $jwk = $this->getClientAssertionJwk();

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

        // Add assertion_details for M2M organization delegation
        if ($this->clientAssertionDetails !== null) {
            $payloadData['assertion_details'] = $this->clientAssertionDetails;
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

        if (!file_exists($this->clientAssertionPrivateKeyPath)) {
            throw new \RuntimeException(
                "Private key file not found: {$this->clientAssertionPrivateKeyPath}"
            );
        }

        $content = file_get_contents($this->clientAssertionPrivateKeyPath);
        if ($content === false) {
            throw new \RuntimeException(
                "Failed to read private key file: {$this->clientAssertionPrivateKeyPath}"
            );
        }

        // Remove UTF-8 BOM if present and trim
        $content = preg_replace('/^\xEF\xBB\xBF/', '', $content);
        $trimmed = trim($content);

        // Detect format
        if (strpos($trimmed, '{') === 0) {
            // JWK format - parse directly
            $this->clientAssertionJwk = $this->loadJwkFromJson($trimmed);
        } elseif (strpos($trimmed, '-----BEGIN') === 0) {
            // PEM format - convert to JWK
            $this->clientAssertionJwk = $this->loadJwkFromPem($content);
        } else {
            throw new \RuntimeException(
                'Private key must be in PEM format (-----BEGIN...) or JWK format ({...})'
            );
        }

        return $this->clientAssertionJwk;
    }

    /**
     * Load JWK from JSON content
     *
     * @param string $jsonContent
     * @return JWK
     * @throws \RuntimeException
     */
    protected function loadJwkFromJson(string $jsonContent): JWK
    {
        $data = json_decode($jsonContent, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Invalid JWK: not valid JSON');
        }

        // Extract kid if not already configured
        if ($this->clientAssertionKeyId === null && isset($data['kid'])) {
            $this->clientAssertionKeyId = $data['kid'];
        }

        // Detect algorithm - prefer explicit 'alg' field, fallback to key type
        $kty = isset($data['kty']) ? strtoupper($data['kty']) : null;
        $alg = isset($data['alg']) ? strtoupper($data['alg']) : null;

        if ($alg !== null) {
            // Reject forbidden algorithms
            if (in_array($alg, static::$forbiddenAlgorithms, true)) {
                throw new \RuntimeException(
                    "Algorithm '{$data['alg']}' is not allowed for client assertions"
                );
            }

            // Validate against whitelist and map to supported algorithm
            if (!isset(static::$algFamily[$alg])) {
                throw new \RuntimeException(
                    "Unsupported algorithm in JWK: '{$data['alg']}'. " .
                    "Allowed: " . implode(', ', static::$allowedAlgorithms)
                );
            }

            $this->clientAssertionAlgorithm = static::$algFamily[$alg];
        } elseif ($kty !== null && isset(static::$ktyToAlg[$kty])) {
            $this->clientAssertionAlgorithm = static::$ktyToAlg[$kty];
        } else {
            throw new \RuntimeException(
                "Unsupported or missing key type (kty) in JWK: " . ($data['kty'] ?? 'null')
            );
        }

        // Normalize kty to uppercase (web-token requires uppercase)
        if (isset($data['kty'])) {
            $data['kty'] = strtoupper($data['kty']);
        }

        return new JWK($data);
    }

    /**
     * Load JWK from PEM content
     *
     * @param string $pemContent
     * @return JWK
     * @throws \RuntimeException
     */
    protected function loadJwkFromPem(string $pemContent): JWK
    {
        // web-token v4 handles both traditional (SEC1/PKCS#1) and PKCS#8 PEM
        // formats for both EC and RSA keys.
        $jwk = \Jose\Component\KeyManagement\JWKFactory::createFromKey($pemContent);

        // Detect algorithm from actual key type in the JWK
        $kty = strtoupper($jwk->get('kty'));
        if (isset(static::$ktyToAlg[$kty])) {
            $this->clientAssertionAlgorithm = static::$ktyToAlg[$kty];
        } else {
            throw new \RuntimeException(
                "Unsupported key type in PEM: '{$kty}'. Supported: " . implode(', ', array_keys(static::$ktyToAlg))
            );
        }

        return $jwk;
    }
}
