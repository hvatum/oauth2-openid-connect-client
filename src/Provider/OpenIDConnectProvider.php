<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Hvatum\OpenIDConnect\Client\OptionProvider\OpenIDConnectOptionProvider;
use Hvatum\OpenIDConnect\Client\Tool\ClientAssertionTrait;
use Hvatum\OpenIDConnect\Client\Tool\DPopTrait;
use Hvatum\OpenIDConnect\Client\Tool\PARTrait;
use Hvatum\OpenIDConnect\Client\Tool\WellKnownConfigTrait;
use Hvatum\OpenIDConnect\Client\Validator\NonceChecker;

/**
 * Generic OpenID Connect Provider
 *
 * Implements OAuth 2.0 Authorization Code Flow with:
 * - Well-known configuration discovery (auto-configuration)
 * - PAR (Pushed Authorization Requests) - RFC 9126
 * - PKCE (Proof Key for Code Exchange) - RFC 7636
 * - Private_key_jwt client authentication - RFC 7523
 * - DPoP (Demonstrating Proof of Possession) - RFC 9449
 * - OpenID Connect (ID token validation, nonces)
 * - Client Credentials flow for machine-to-machine API access
 *
 * Works with any OpenID Connect compliant server.
 */
class OpenIDConnectProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;
    use WellKnownConfigTrait;
    use PARTrait;
    use ClientAssertionTrait;
    use DPopTrait;

    /**
     * Scope delimiter (space-separated as per OAuth 2.0 spec)
     */
    public const SCOPE_DELIMITER = ' ';

    /**
     * Client assertion JWT expiration time in seconds
     */
    public const CLIENT_ASSERTION_TTL = 120;

    /**
     * Default scopes for OpenID Connect
     */
    public const DEFAULT_SCOPES = [
        'openid',
    ];

    /**
     * JWKS cache TTL in seconds (1 hour)
     */
    public const JWKS_CACHE_TTL = 3600;

    /**
     * Clock skew leeway for JWT validation in seconds
     */
    public const CLOCK_SKEW_LEEWAY = 60;

    /**
     * Configured issuer identifier (from constructor option)
     */
    protected string $expectedIssuer;

    /**
     * Dynamically loaded endpoints from well-known config
     */
    protected ?string $authorizationUrl = null;
    protected ?string $tokenUrl = null;
    protected ?string $userInfoUrl = null;
    protected ?string $parUrl = null;
    protected ?string $revocationUrl = null;
    protected ?string $jwksUrl = null;
    protected ?string $issuerUrl = null;

    /**
     * Current nonce for ID token validation
     */
    protected ?string $nonce = null;

    /**
     * Callback issuer for RFC 9207 validation
     */
    protected ?string $callbackIssuer = null;

    /**
     * Whether the AS advertises RFC 9207 issuer response parameter support
     * (authorization_response_iss_parameter_supported in discovery)
     */
    protected bool $issuerResponseParameterSupported = false;

    /**
     * Whether to enforce RFC 9207 issuer identification validation.
     * When true (default), if the AS advertises support, callbacks missing
     * the iss parameter will be rejected.
     */
    protected bool $enforceIssuerIdentification = true;

    /**
     * ID token from last token response
     */
    protected ?string $idToken = null;

    /**
     * Cached JWKS data
     */
    protected ?array $jwksCache = null;
    protected ?int $jwksCacheTime = null;

    /**
     * Last token request params (for DPoP nonce retry)
     */
    protected ?array $lastTokenParams = null;

    /**
     * PSR-3 Logger instance
     */
    protected LoggerInterface $logger;

    /**
     * Initialize OpenID Connect provider
     *
     * Required options:
     * - issuer: Issuer identifier URL (e.g., 'https://idp.example.com')
     *
     * Optional options:
     * - wellKnownUrl: Override the auto-derived well-known URL (for non-standard paths)
     * - privateKeyPath: Path to private key for client assertion (RFC 7523)
     * - keyId: Key ID for client assertion
     * - dpopPrivateKeyPath: Path to DPoP private key (RFC 9449)
     * - dpopPublicKeyPath: Path to DPoP public key (RFC 9449)
     * - cacheDir: Custom cache directory for well-known config
     *
     * @param array $options Provider configuration options
     * @param array $collaborators Optional collaborators (httpClient, requestFactory, logger)
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (empty($options['issuer'])) {
            throw new \InvalidArgumentException('issuer is required for OpenID Connect discovery');
        }

        // Initialize logger (use NullLogger if not provided)
        $this->logger = $collaborators['logger'] ?? new NullLogger();

        parent::__construct($options, $collaborators);

        // Use custom option provider that delegates body building to this provider
        $this->setOptionProvider(new OpenIDConnectOptionProvider(
            fn(array $params) => $this->getAccessTokenBody($params)
        ));

        if (isset($options['cacheDir'])) {
            $this->cacheDir = $options['cacheDir'];
        }

        // Derive well-known URL from issuer, or use explicit override
        $this->expectedIssuer = $options['issuer'];
        $wellKnownUrl = $options['wellKnownUrl']
            ?? rtrim($this->expectedIssuer, '/') . '/.well-known/openid-configuration';
        $this->loadWellKnownConfiguration($wellKnownUrl, $this->expectedIssuer);

        $this->logger->debug('OpenID Connect provider initialized', [
            'issuer' => $this->issuerUrl,
            'par_enabled' => $this->parUrl !== null,
        ]);

        // Optional: Disable strict RFC 9207 enforcement
        if (isset($options['enforceIssuerIdentification'])) {
            $this->enforceIssuerIdentification = (bool) $options['enforceIssuerIdentification'];
        }

        // Optional: Initialize client assertion (private_key_jwt)
        if (!empty($options['privateKeyPath'])) {
            $this->initializeClientAssertion(
                $options['privateKeyPath'],
                $options['keyId'] ?? null
            );
        }

        // Optional: Initialize DPoP
        if (!empty($options['dpopPrivateKeyPath']) && !empty($options['dpopPublicKeyPath'])) {
            $this->initializeDPoP(
                $options['dpopPrivateKeyPath'],
                $options['dpopPublicKeyPath']
            );
        }
    }

    /**
     * Get the base authorization URL
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        $this->ensureEndpointsLoaded();
        return $this->authorizationUrl;
    }

    /**
     * Get the base access token URL
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        $this->ensureEndpointsLoaded();
        return $this->tokenUrl;
    }

    /**
     * Get the user info URL
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        $this->ensureEndpointsLoaded();
        if ($this->userInfoUrl === null) {
            throw new \RuntimeException(
                'UserInfo endpoint not available. The authorization server discovery response '
                . 'did not include a userinfo_endpoint.'
            );
        }
        return $this->userInfoUrl;
    }

    /**
     * Add DPoP proof when fetching access tokens
     *
     * @param array $params
     * @return \Psr\Http\Message\RequestInterface
     */
    protected function getAccessTokenRequest(array $params)
    {
        // Store params for potential DPoP nonce retry
        $this->lastTokenParams = $params;

        $request = parent::getAccessTokenRequest($params);

        if ($this->hasDPoP()) {
            $proof = $this->createDPopProof('POST', (string) $request->getUri());
            $request = $request->withHeader('DPoP', $proof);
            $this->logger->debug('DPoP proof attached to token request', [
                'uri' => (string) $request->getUri(),
                'has_nonce' => $this->getDPopNonce() !== null,
            ]);
        }

        return $request;
    }

    /**
     * Build access token request body
     * Adds client assertion, DPoP thumbprint, and handles formatting
     *
     * @param array $params
     * @return string
     */
    protected function getAccessTokenBody(array $params): string
    {
        // Add client assertion (private_key_jwt) if configured
        if ($this->hasClientAssertion()) {
            $assertion = $this->createClientAssertion($this->tokenUrl);
            $params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $params['client_assertion'] = $assertion;
            unset($params['client_secret']);
        }

        // Add DPoP key thumbprint for token binding
        if ($this->hasDPoP() && !isset($params['dpop_jkt'])) {
            $params['dpop_jkt'] = $this->getDPopJwkThumbprint();
        }

        // Join scope array with separator (parent doesn't handle this)
        if (isset($params['scope']) && is_array($params['scope'])) {
            $params['scope'] = implode($this->getScopeSeparator(), $params['scope']);
        }

        return $this->buildQueryString($params);
    }

    /**
     * Get default scopes
     *
     * @return array
     */
    protected function getDefaultScopes(): array
    {
        return static::DEFAULT_SCOPES;
    }

    /**
     * Get scope separator
     *
     * @return string
     */
    protected function getScopeSeparator(): string
    {
        return static::SCOPE_DELIMITER;
    }

    /**
     * Enforce PKCE with S256
     */
    protected function getPkceMethod()
    {
        return static::PKCE_METHOD_S256;
    }

    /**
     * Check token response for errors
     *
     * @param ResponseInterface $response
     * @param array|string $data
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        // Extract DPoP nonce from any response (before potential throw)
        $this->extractDPopNonce($response);

        if ($response->getStatusCode() >= 400) {
            $this->logger->warning('Token request failed', [
                'status' => $response->getStatusCode(),
                'error' => is_array($data) ? ($data['error'] ?? 'unknown') : 'unknown',
            ]);
            throw new IdentityProviderException(
                $data['error_description'] ?? $data['error'] ?? $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }

        if (is_array($data) && isset($data['error'])) {
            $this->logger->warning('Token response contains error', [
                'error' => $data['error'],
            ]);
            throw new IdentityProviderException(
                $data['error_description'] ?? $data['error'],
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Create resource owner from successful response
     *
     * @param array $response
     * @param AccessToken $token
     * @return OpenIDConnectResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token): OpenIDConnectResourceOwner
    {
        // Merge ID token claims with userinfo response
        // ID token claims take precedence (more authoritative, signed by IdP)
        if ($this->idToken !== null) {
            $idTokenClaims = $this->validateIdToken($this->idToken);
            $response = array_merge($response, $idTokenClaims);
        }

        return new OpenIDConnectResourceOwner($response);
    }

    /**
     * Fetch resource owner details from userinfo endpoint
     *
     * @param AccessToken $token
     * @return array
     * @throws IdentityProviderException
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $url = $this->getResourceOwnerDetailsUrl($token);

        // Userinfo endpoint uses Bearer authentication
        $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new \UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    /**
     * Get authorization parameters including nonce and PKCE
     *
     * @param array $options
     * @return array
     */
    protected function getAuthorizationParameters(array $options): array
    {
        // Remove Google-specific parameter that the base library adds by default.
        // OIDC uses 'prompt' instead (none, login, consent, select_account)
        $params = parent::getAuthorizationParameters($options);

        unset($params['approval_prompt']);

        // Generate and store nonce for ID token validation
        $this->nonce = $this->generateNonce();
        $params['nonce'] = $this->nonce;

        // If PAR is enabled, push the authorization request
        if ($this->usePAR()) {
            $this->logger->debug('Using PAR (Pushed Authorization Request)');
            $requestUri = $this->pushAuthorizationRequest($params);
            // Replace all params with just client_id and request_uri
            return [
                'client_id' => $this->clientId,
                'request_uri' => $requestUri,
            ];
        }

        return $params;
    }

    /**
     * Parse the access token response
     *
     * @param ResponseInterface $response
     * @return array
     */
    protected function parseResponse(ResponseInterface $response): array
    {
        $parsed = parent::parseResponse($response);

        // Parent can return string/null for non-JSON responses
        if (!is_array($parsed)) {
            throw new \UnexpectedValueException(
                'Invalid response from Authorization Server. Expected JSON object, got: ' .
                (is_string($parsed) ? substr($parsed, 0, 100) : gettype($parsed))
            );
        }

        // Store ID token if present
        if (isset($parsed['id_token'])) {
            $this->idToken = $parsed['id_token'];
        }

        return $parsed;
    }

    /**
     * Get parsed response with DPoP nonce retry support
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @return mixed
     * @throws IdentityProviderException
     */
    public function getParsedResponse(\Psr\Http\Message\RequestInterface $request)
    {
        try {
            return parent::getParsedResponse($request);
        } catch (IdentityProviderException $e) {
            // Only retry for token endpoint with DPoP nonce errors
            $isTokenRequest = $this->lastTokenParams !== null
                && ((string) $request->getUri()) === $this->tokenUrl;

            if ($isTokenRequest && $this->hasDPoP() && $this->isDPopNonceError($e) && $this->getDPopNonce() !== null) {
                // Nonce was extracted in getResponse(), rebuild request and retry
                $this->logger->debug('Retrying token request with server-provided DPoP nonce');
                $retryRequest = $this->getAccessTokenRequest($this->lastTokenParams);
                $this->lastTokenParams = null; // Prevent infinite retry
                return parent::getParsedResponse($retryRequest);
            }
            throw $e;
        } catch (\UnexpectedValueException $e) {
            // Log raw response for debugging non-JSON responses
            $this->logger->error('Request failed with non-JSON response', [
                'exception' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    /**
     * Extract DPoP nonce from any response (success or error)
     *
     * Called from checkResponse() before throwing, so it works
     * with any PSR-18 HTTP client.
     *
     * @param ResponseInterface $response
     */
    protected function extractDPopNonce(ResponseInterface $response): void
    {
        if ($this->hasDPoP()) {
            $nonceHeader = $response->getHeader('DPoP-Nonce');
            if (!empty($nonceHeader)) {
                $this->setDPopNonce($nonceHeader[0]);
                $this->logger->debug('Received DPoP nonce from server response');
            }
        }
    }

    /**
     * Check if exception is a DPoP nonce error per RFC 9449
     *
     * Per RFC 9449 Section 8.2, when the server requires a nonce:
     * - HTTP status: 400
     * - Error code: "use_dpop_nonce"
     * - DPoP-Nonce header contains the nonce to use
     *
     * @param IdentityProviderException $e
     * @return bool
     */
    protected function isDPopNonceError(IdentityProviderException $e): bool
    {
        // Check for RFC 9449 compliant error code from response body
        $response = $e->getResponseBody();
        if ($response instanceof ResponseInterface) {
            $body = (string) $response->getBody();
            $response->getBody()->rewind();
            $data = json_decode($body, true);
            if (is_array($data) && ($data['error'] ?? null) === 'use_dpop_nonce') {
                return true;
            }
        }

        // Fallback: check exception message for exact RFC 9449 error code only
        return strpos(strtolower($e->getMessage()), 'use_dpop_nonce') !== false;
    }

    /**
     * Get the stored ID token from last authentication
     *
     * @return string|null
     */
    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    /**
     * Get the nonce used in the authorization request
     *
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * Set nonce (useful when restoring from session)
     *
     * @param string $nonce
     */
    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }

    /**
     * Get the callback issuer (RFC 9207)
     *
     * @return string|null
     */
    public function getCallbackIssuer(): ?string
    {
        return $this->callbackIssuer;
    }

    /**
     * Set callback issuer from authorization response (RFC 9207)
     *
     * This should be set from $_GET['iss'] in your callback handler.
     * It will be validated against the expected issuer in validateIdToken().
     *
     * @param string|null $issuer
     */
    public function setCallbackIssuer(?string $issuer): void
    {
        $this->callbackIssuer = $issuer;
    }

    /**
     * Generate a cryptographically secure nonce
     *
     * @return string
     */
    protected function generateNonce(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Get the issuer URL from well-known configuration
     *
     * @return string|null
     */
    public function getIssuerUrl(): ?string
    {
        return $this->issuerUrl;
    }

    /**
     * Validate ID token
     *
     * @param string $idToken The ID token JWT
     * @param string|null $nonce Expected nonce value
     * @param string|null $callbackIssuer Issuer from authorization callback (RFC 9207)
     * @return array Validated claims from ID token
     * @throws IdentityProviderException
     */
    public function validateIdToken(string $idToken, ?string $nonce = null, ?string $callbackIssuer = null): array
    {
        $nonce = $nonce ?? $this->nonce;
        $callbackIssuer = $callbackIssuer ?? $this->callbackIssuer;
        $this->ensureEndpointsLoaded();

        $this->logger->debug('Validating ID token', [
            'has_nonce' => $nonce !== null,
            'has_callback_issuer' => $callbackIssuer !== null,
        ]);

        // RFC 9207 - Authorization Server Issuer Identification
        // When the AS advertises support, reject callbacks that are missing the iss parameter
        if ($callbackIssuer === null
            && $this->issuerResponseParameterSupported
            && $this->enforceIssuerIdentification
        ) {
            $this->logger->warning('RFC 9207: AS supports issuer identification but callback is missing iss parameter');
            throw new IdentityProviderException(
                'Authorization response is missing the iss parameter. '
                . 'The authorization server advertises authorization_response_iss_parameter_supported. '
                . 'This may indicate a mix-up attack (RFC 9207).',
                0,
                null
            );
        }

        // Validate callback issuer parameter against expected issuer
        // This protects against mix-up attacks when using multiple identity providers
        if ($callbackIssuer !== null && $callbackIssuer !== $this->issuerUrl) {
            $this->logger->warning('Potential mix-up attack: issuer mismatch in callback', [
                'callback_issuer' => $callbackIssuer,
                'expected_issuer' => $this->issuerUrl,
            ]);
            throw new IdentityProviderException(
                sprintf(
                    'Issuer mismatch: callback iss parameter "%s" does not match expected issuer "%s"',
                    $callbackIssuer,
                    $this->issuerUrl
                ),
                0,
                null
            );
        }

        if ($this->jwksUrl === null) {
            throw new IdentityProviderException('JWKS URL not available for ID token validation', 0, null);
        }

        // Parse header to enforce expected algorithm
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new IdentityProviderException('Invalid ID token format', 0, null);
        }

        $header = json_decode(Base64UrlSafe::decode($parts[0]), true);
        if (!is_array($header)) {
            throw new IdentityProviderException('Invalid ID token header', 0, null);
        }

        // Whitelist of allowed algorithms (prevent algorithm confusion attacks)
        $allowedAlgorithms = ['ES256', 'RS256', 'PS256'];
        $tokenAlg = $header['alg'] ?? '';

        if (!in_array($tokenAlg, $allowedAlgorithms, true)) {
            $this->logger->warning('ID token uses disallowed algorithm', [
                'algorithm' => $tokenAlg,
                'allowed' => $allowedAlgorithms,
            ]);
            throw new IdentityProviderException(
                "Invalid ID token algorithm: '{$tokenAlg}'. Allowed: " . implode(', ', $allowedAlgorithms),
                0,
                null
            );
        }

        try {
            // Use web-token for signature verification with supported algorithms
            $algorithmManager = new AlgorithmManager([
                new ES256(),
                new RS256(),
                new PS256(),
            ]);
            $jwsVerifier = new JWSVerifier($algorithmManager);
            $serializer = new CompactSerializer();

            $jws = $serializer->unserialize($idToken);
            $jwkSet = JWKSet::createFromKeyData($this->getJwks());

            if (!$jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0)) {
                throw new \RuntimeException('Signature verification failed');
            }

            $decoded = json_decode($jws->getPayload(), true);
            if (!is_array($decoded)) {
                throw new \RuntimeException('Invalid payload');
            }

            // Validate registered claims using claim checkers with clock skew
            // PSR-20 clock required by web-token v4 time-based checkers
            $clock = new class implements \Psr\Clock\ClockInterface {
                public function now(): \DateTimeImmutable
                {
                    return new \DateTimeImmutable();
                }
            };
            $claimCheckerManager = new ClaimCheckerManager([
                new IssuerChecker([$this->issuerUrl]),
                new AudienceChecker($this->clientId),
                new ExpirationTimeChecker($clock, static::CLOCK_SKEW_LEEWAY),
                new NotBeforeChecker($clock, static::CLOCK_SKEW_LEEWAY),
                new IssuedAtChecker($clock, static::CLOCK_SKEW_LEEWAY),
                new NonceChecker($nonce),
            ]);

            /* Validate claims (throws on failure)
             * claimsChecker can return claims, but will
             * only return claims that are explicitly validated.
             *
             * We keep $decoded and use that as return value
             * in order to keep other claims as well
             */

            $claimCheckerManager->check($decoded, ['iss', 'sub', 'aud', 'exp', 'iat']);
        } catch (InvalidClaimException $e) {
            $this->logger->warning('ID token claim validation failed', [
                'reason' => $e->getMessage(),
                'claim' => method_exists($e, 'getClaim') ? $e->getClaim() : 'unknown',
            ]);
            throw new IdentityProviderException(
                'ID token claim validation failed: ' . $e->getMessage(),
                0,
                null,
                $e
            );
        } catch (\Throwable $e) {
            $this->logger->warning('ID token validation failed', [
                'reason' => $e->getMessage(),
            ]);
            throw new IdentityProviderException(
                'Failed to validate ID token: ' . $e->getMessage(),
                0,
                null,
                $e
            );
        }

        // Verify sub claim is present (OIDC Core Section 2)
        if (!isset($decoded['sub']) || !is_string($decoded['sub'])) {
            throw new IdentityProviderException('ID token missing required sub claim', 0, null);
        }

        // Verify azp when multiple audiences are present
        $audience = $decoded['aud'] ?? [];
        $audList = is_array($audience) ? $audience : [$audience];
        if (count($audList) > 1 && ($decoded['azp'] ?? null) !== $this->clientId) {
            throw new IdentityProviderException('ID token azp mismatch', 0, null);
        }

        $this->logger->debug('ID token validated successfully', [
            'sub' => $decoded['sub'],
            'iss' => $decoded['iss'] ?? 'unknown',
        ]);

        return $decoded;
    }

    /**
     * Fetch JWKS with basic in-memory caching
     *
     * @return array
     * @throws IdentityProviderException
     */
    protected function getJwks(): array
    {
        if ($this->jwksCache !== null && $this->jwksCacheTime !== null) {
            if ((time() - $this->jwksCacheTime) < static::JWKS_CACHE_TTL) {
                $this->logger->debug('Using cached JWKS', [
                    'cache_age_seconds' => time() - $this->jwksCacheTime,
                ]);
                return $this->jwksCache;
            }
        }

        try {
            $request = $this->getRequest('GET', $this->jwksUrl);
            $response = $this->getHttpClient()->send($request);

            if ($response->getStatusCode() !== 200) {
                throw new IdentityProviderException(
                    'Failed to fetch JWKS',
                    $response->getStatusCode(),
                    $response
                );
            }

            $body = (string)$response->getBody();
            $data = json_decode($body, true);
            if (!is_array($data) || !isset($data['keys']) || !is_array($data['keys'])) {
                throw new IdentityProviderException('Invalid JWKS response format', 0, $response);
            }

            $this->jwksCache = $data;
            $this->jwksCacheTime = time();

            $this->logger->debug('Fetched fresh JWKS', [
                'key_count' => count($data['keys']),
            ]);

            return $data;
        } catch (IdentityProviderException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new IdentityProviderException('Failed to fetch JWKS', 0, null, $e);
        }
    }

    /**
     * Ensure endpoints are loaded from well-known config
     *
     * @throws \RuntimeException
     */
    protected function ensureEndpointsLoaded(): void
    {
        if ($this->authorizationUrl === null) {
            throw new \RuntimeException(
                'Endpoints not loaded. Provide issuer in options or call loadWellKnownConfiguration()'
            );
        }
    }

    /**
     * Determine if PAR should be used
     * PAR is used when the endpoint is available
     *
     * @return bool
     */
    protected function usePAR(): bool
    {
        return $this->parUrl !== null;
    }
}
