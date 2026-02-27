<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * DPoP (Demonstrating Proof of Possession) Trait
 *
 * Implements RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession
 * Binds access tokens to a cryptographic key pair to prevent token theft
 *
 * Uses web-token/jwt-framework for JWT signing
 *
 * Note: DPoP requires EC P-256 keys only (ES256 algorithm) per RFC 9449.
 * This is more restrictive than ClientAssertionTrait which supports EC and RSA.
 */
trait DPopTrait
{
    use Base64UrlTrait;
    /**
     * DPoP private key path
     */
    protected ?string $dpopPrivateKeyPath = null;

    /**
     * DPoP public key path
     */
    protected ?string $dpopPublicKeyPath = null;

    /**
     * Cached DPoP private JWK
     */
    protected ?JWK $dpopPrivateJwk = null;

    /**
     * Cached DPoP public key JWK (for embedding in header)
     */
    protected ?array $dpopPublicKeyJwk = null;

    /**
     * DPoP nonce from server
     */
    protected ?string $dpopNonce = null;

    /**
     * Initialize DPoP with key pair
     *
     * @param string $privateKeyPath Path to PEM-encoded EC private key
     * @param string $publicKeyPath Path to PEM-encoded EC public key
     */
    protected function initializeDPoP(string $privateKeyPath, string $publicKeyPath): void
    {
        $this->dpopPrivateKeyPath = $privateKeyPath;
        $this->dpopPublicKeyPath = $publicKeyPath;
    }

    /**
     * Check if DPoP is configured
     *
     * @return bool
     */
    protected function hasDPoP(): bool
    {
        return $this->dpopPrivateKeyPath !== null && $this->dpopPublicKeyPath !== null;
    }

    /**
     * Create DPoP proof JWT
     *
     * @param string $httpMethod HTTP method (e.g., 'POST', 'GET')
     * @param string $targetUri Target URI (without query/fragment)
     * @param string|null $accessToken Access token to bind (for API calls)
     * @param string|null $nonce Server-provided nonce
     * @return string DPoP proof JWT
     * @throws \RuntimeException
     */
    protected function createDPopProof(
        string $httpMethod,
        string $targetUri,
        ?string $accessToken = null,
        ?string $nonce = null
    ): string {
        if (!$this->hasDPoP()) {
            throw new \RuntimeException('DPoP not configured');
        }

        $privateJwk = $this->getDPopPrivateJwk();
        $publicKeyJwk = $this->getDPopPublicKeyJwk();
        $now = time();

        // Use stored nonce if not provided
        $nonce = $nonce ?? $this->dpopNonce;

        // Build DPoP proof payload (RFC 9449)
        $payloadData = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => strtoupper($httpMethod),
            'htu' => $targetUri,
            'iat' => $now,
        ];

        // Add nonce if available
        if ($nonce !== null) {
            $payloadData['nonce'] = $nonce;
        }

        // Add access token hash if provided
        if ($accessToken !== null) {
            $payloadData['ath'] = $this->calculateAccessTokenHash($accessToken);
        }

        $payload = json_encode($payloadData, JSON_UNESCAPED_SLASHES);

        // Build DPoP proof header
        $header = [
            'alg' => 'ES256',
            'typ' => 'dpop+jwt',
            'jwk' => $publicKeyJwk,
        ];

        // Create algorithm manager
        $algorithmManager = new AlgorithmManager([new ES256()]);

        // Build and sign the JWT
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($privateJwk, $header)
            ->build();

        // Serialize to compact format
        $serializer = new CompactSerializer();
        return $serializer->serialize($jws, 0);
    }

    /**
     * Calculate SHA-256 hash of access token for ath claim
     *
     * @param string $accessToken
     * @return string Base64url-encoded hash
     */
    protected function calculateAccessTokenHash(string $accessToken): string
    {
        $hash = hash('sha256', $accessToken, true);
        return $this->base64UrlEncode($hash);
    }

    /**
     * Get DPoP private key as JWK
     *
     * @return JWK
     * @throws \RuntimeException
     */
    protected function getDPopPrivateJwk(): JWK
    {
        if ($this->dpopPrivateJwk !== null) {
            return $this->dpopPrivateJwk;
        }

        if (!file_exists($this->dpopPrivateKeyPath)) {
            throw new \RuntimeException(
                "DPoP private key file not found: {$this->dpopPrivateKeyPath}"
            );
        }

        $content = file_get_contents($this->dpopPrivateKeyPath);
        if ($content === false) {
            throw new \RuntimeException(
                "Failed to read DPoP private key file: {$this->dpopPrivateKeyPath}"
            );
        }

        // Verify PEM format
        if (strpos(trim($content), '-----BEGIN') !== 0) {
            throw new \RuntimeException(
                'DPoP private key must be in PEM format (starting with -----BEGIN EC PRIVATE KEY-----)'
            );
        }

        // Convert PEM to JWK using OpenSSL
        $resource = openssl_pkey_get_private($content);
        if ($resource === false) {
            throw new \RuntimeException(
                'Failed to parse DPoP private key: ' . openssl_error_string()
            );
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new \RuntimeException('DPoP private key must be EC type');
        }

        $jwkData = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $this->base64UrlEncode($details['ec']['x']),
            'y' => $this->base64UrlEncode($details['ec']['y']),
            'd' => $this->base64UrlEncode($details['ec']['d']),
        ];

        $this->dpopPrivateJwk = new JWK($jwkData);
        return $this->dpopPrivateJwk;
    }

    /**
     * Get DPoP public key in JWK format (for embedding in JWT header)
     *
     * @return array
     * @throws \RuntimeException
     */
    protected function getDPopPublicKeyJwk(): array
    {
        if ($this->dpopPublicKeyJwk !== null) {
            return $this->dpopPublicKeyJwk;
        }

        if (!file_exists($this->dpopPublicKeyPath)) {
            throw new \RuntimeException(
                "DPoP public key file not found: {$this->dpopPublicKeyPath}"
            );
        }

        $content = file_get_contents($this->dpopPublicKeyPath);
        if ($content === false) {
            throw new \RuntimeException(
                "Failed to read DPoP public key file: {$this->dpopPublicKeyPath}"
            );
        }

        // Parse PEM public key using OpenSSL
        $publicKey = openssl_pkey_get_public($content);
        if ($publicKey === false) {
            throw new \RuntimeException(
                "Failed to parse DPoP public key: " . openssl_error_string()
            );
        }

        $details = openssl_pkey_get_details($publicKey);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new \RuntimeException('DPoP public key must be EC type');
        }

        // Verify P-256 curve
        $curveName = $details['ec']['curve_name'] ?? null;
        if ($curveName !== 'prime256v1') {
            throw new \RuntimeException(
                "DPoP public key must use P-256 (prime256v1) curve, got: " . ($curveName ?? 'unknown')
            );
        }

        // Convert to JWK format (RFC 7517) - public key only for embedding
        $this->dpopPublicKeyJwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $this->base64UrlEncode($details['ec']['x']),
            'y' => $this->base64UrlEncode($details['ec']['y']),
        ];

        return $this->dpopPublicKeyJwk;
    }

    /**
     * Get JWK thumbprint (SHA-256) of the public key
     *
     * @return string Base64url-encoded thumbprint
     */
    public function getDPopJwkThumbprint(): string
    {
        $jwk = $this->getDPopPublicKeyJwk();

        // RFC 7638: Canonical JSON for thumbprint (alphabetically sorted keys)
        $canonicalJwk = json_encode([
            'crv' => $jwk['crv'],
            'kty' => $jwk['kty'],
            'x' => $jwk['x'],
            'y' => $jwk['y'],
        ], JSON_UNESCAPED_SLASHES);

        $hash = hash('sha256', $canonicalJwk, true);
        return $this->base64UrlEncode($hash);
    }

    /**
     * Set DPoP nonce from server response
     *
     * @param string $nonce
     */
    public function setDPopNonce(string $nonce): void
    {
        $this->dpopNonce = $nonce;
    }

    /**
     * Get stored DPoP nonce
     *
     * @return string|null
     */
    public function getDPopNonce(): ?string
    {
        return $this->dpopNonce;
    }

    /**
     * Make authenticated request with DPoP
     * Automatically retries with server-provided nonce if required
     *
     * @param string $method HTTP method
     * @param string $url Target URL
     * @param string $accessToken Access token
     * @param array $options Additional request options
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function makeDPopRequest(
        string $method,
        string $url,
        string $accessToken,
        array $options = []
    ): \Psr\Http\Message\ResponseInterface {
        $response = $this->sendDPopRequest($method, $url, $accessToken, $options);

        // Check if we got a nonce error (401 with use_dpop_nonce)
        if ($response->getStatusCode() === 401) {
            $nonceHeader = $response->getHeader('DPoP-Nonce');
            if (!empty($nonceHeader)) {
                // Store nonce and retry
                $this->setDPopNonce($nonceHeader[0]);
                $response = $this->sendDPopRequest($method, $url, $accessToken, $options);
            }
        }

        return $response;
    }

    /**
     * Send a single DPoP request (internal helper)
     *
     * @param string $method HTTP method
     * @param string $url Target URL
     * @param string $accessToken Access token
     * @param array $options Additional request options
     * @return \Psr\Http\Message\ResponseInterface
     */
    protected function sendDPopRequest(
        string $method,
        string $url,
        string $accessToken,
        array $options = []
    ): \Psr\Http\Message\ResponseInterface {
        // Create DPoP proof (will include nonce if set)
        $dpopProof = $this->createDPopProof($method, $url, $accessToken);

        // Build request
        $request = $this->getRequest($method, $url);
        $request = $request
            ->withHeader('Authorization', 'DPoP ' . $accessToken)
            ->withHeader('DPoP', $dpopProof);

        // Add body if provided
        if (isset($options['body'])) {
            $request = $request->withBody(
                $this->getStreamFactory()->createStream($options['body'])
            );
        }

        // Add headers if provided
        if (isset($options['headers'])) {
            foreach ($options['headers'] as $name => $value) {
                $request = $request->withHeader($name, $value);
            }
        }

        // Send request
        $response = $this->getHttpClient()->send($request);

        // Store nonce from response for future requests
        $nonceHeader = $response->getHeader('DPoP-Nonce');
        if (!empty($nonceHeader)) {
            $this->setDPopNonce($nonceHeader[0]);
        }

        return $response;
    }
}
