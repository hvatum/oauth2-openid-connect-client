<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

/**
 * DPoP (Demonstrating Proof of Possession) Trait
 *
 * Implements RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession
 * Binds access tokens to a cryptographic key pair to prevent token theft
 *
 * Uses web-token/jwt-framework for JWT signing
 *
 * This library uses ES256 for DPoP (mandatory-to-implement per RFC 9449).
 * Other asymmetric algorithms are permitted by the spec but not supported here.
 */
trait DPopTrait
{
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
     * @param string|null $publicKeyPath Path to PEM-encoded EC public key (optional, derived from private key if null)
     */
    protected function initializeDPoP(string $privateKeyPath, ?string $publicKeyPath = null): void
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
        return $this->dpopPrivateKeyPath !== null;
    }

    /**
     * Create DPoP proof JWT
     *
     * @param string $httpMethod HTTP method (e.g., 'POST', 'GET')
     * @param string|UriInterface $targetUri Target URI
     * @param string|null $accessToken Access token to bind (for API calls)
     * @param string|null $nonce Server-provided nonce
     * @return string DPoP proof JWT
     * @throws \RuntimeException
     */
    protected function createDPopProof(
        string $httpMethod,
        string|UriInterface $targetUri,
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

        if (is_string($targetUri)) {
            $targetUri = $this->getRequest('GET', $targetUri)->getUri();
        }

        // RFC 9449 §4.2: htu is the target URI without query/fragment.
        $htuUri = $targetUri->withQuery('')->withFragment('');
        if ($htuUri->getPath() === '') {
            $htuUri = $htuUri->withPath('/');
        }
        $htu = (string) $htuUri;

        // Build DPoP proof payload (RFC 9449)
        $payloadData = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => strtoupper($httpMethod),
            'htu' => $htu,
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
        return Base64UrlSafe::encodeUnpadded($hash);
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

        $jwk = \Jose\Component\KeyManagement\JWKFactory::createFromKeyFile($this->dpopPrivateKeyPath);

        if ($jwk->get('kty') !== 'EC') {
            throw new \RuntimeException('DPoP private key must be EC type');
        }

        $this->dpopPrivateJwk = $jwk;
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

        if ($this->dpopPublicKeyPath !== null) {
            // Load from explicit public key file
            if (!file_exists($this->dpopPublicKeyPath)) {
                throw new \RuntimeException(
                    "DPoP public key file not found: {$this->dpopPublicKeyPath}"
                );
            }
            $jwk = \Jose\Component\KeyManagement\JWKFactory::createFromKeyFile($this->dpopPublicKeyPath);
        } else {
            // Derive from private key (private EC JWK contains all public components)
            $jwk = $this->getDPopPrivateJwk();
        }

        if ($jwk->get('kty') !== 'EC') {
            throw new \RuntimeException('DPoP public key must be EC type');
        }

        if ($jwk->get('crv') !== 'P-256') {
            throw new \RuntimeException(
                "DPoP public key must use P-256 curve, got: " . $jwk->get('crv')
            );
        }

        // Public key only (no 'd' parameter) for embedding in JWT header
        $values = $jwk->all();
        unset($values['d']);
        $this->dpopPublicKeyJwk = $values;

        return $this->dpopPublicKeyJwk;
    }

    /**
     * Get JWK thumbprint (SHA-256) of the public key
     *
     * @return string Base64url-encoded thumbprint
     */
    public function getDPopJwkThumbprint(): string
    {
        $jwkData = $this->getDPopPublicKeyJwk();
        $jwk = new JWK($jwkData);

        return $jwk->thumbprint('sha256');
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
        $previousNonce = $this->dpopNonce;
        $response = $this->executeDPopRequest($method, $url, $accessToken, $options);

        // RFC 9449 allows servers to provide/rotate nonce values proactively,
        // so the latest nonce should be captured whenever received.
        $this->updateDPopNonceFromResponse($response);

        // RFC 9449 §8 and §9: retry once when server explicitly signals use_dpop_nonce
        // and provides a different nonce in DPoP-Nonce.
        if ($this->shouldRetryWithDPopNonce($response, $previousNonce)) {
            $response = $this->executeDPopRequest($method, $url, $accessToken, $options);
            $this->updateDPopNonceFromResponse($response);
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
        // Build request
        $request = $this->getRequest($method, $url);
        // Create DPoP proof (will include nonce if set)
        $dpopProof = $this->createDPopProof($method, $request->getUri(), $accessToken);
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

        // Send request only; nonce extraction and retry policy live in makeDPopRequest().
        return $this->getHttpClient()->send($request);
    }

    /**
     * Send request and unwrap response from clients that throw on 4xx/5xx.
     */
    protected function executeDPopRequest(
        string $method,
        string $url,
        string $accessToken,
        array $options = []
    ): ResponseInterface {
        try {
            return $this->sendDPopRequest($method, $url, $accessToken, $options);
        } catch (\Throwable $e) {
            if (method_exists($e, 'getResponse')) {
                $response = $e->getResponse();
                if ($response instanceof ResponseInterface) {
                    return $response;
                }
            }
            throw $e;
        }
    }

    /**
     * Persist nonce from DPoP-Nonce response header if present.
     */
    protected function updateDPopNonceFromResponse(ResponseInterface $response): void
    {
        $nonceHeader = $response->getHeader('DPoP-Nonce');
        if (!empty($nonceHeader) && $nonceHeader[0] !== '') {
            $this->setDPopNonce($nonceHeader[0]);
        }
    }

    /**
     * Retry only when nonce requirement is explicitly signaled by the server.
     */
    protected function shouldRetryWithDPopNonce(ResponseInterface $response, ?string $previousNonce): bool
    {
        $status = $response->getStatusCode();
        if ($status !== 400 && $status !== 401) {
            return false;
        }

        if ($this->dpopNonce === null || $this->dpopNonce === $previousNonce) {
            return false;
        }

        return $this->isUseDPopNonceError($response);
    }

    /**
     * Detect RFC 9449 nonce-required error.
     */
    protected function isUseDPopNonceError(ResponseInterface $response): bool
    {
        $wwwAuthenticate = $response->getHeaderLine('WWW-Authenticate');
        if ($wwwAuthenticate !== ''
            && stripos($wwwAuthenticate, 'dpop') !== false
            && preg_match('/error\s*=\s*"?use_dpop_nonce"?/i', $wwwAuthenticate) === 1
        ) {
            return true;
        }

        $body = (string) $response->getBody();
        $data = json_decode($body, true);

        return is_array($data) && ($data['error'] ?? null) === 'use_dpop_nonce';
    }
}
