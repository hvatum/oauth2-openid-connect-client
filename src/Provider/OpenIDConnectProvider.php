<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Provider;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Header;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Util\Base64UrlSafe;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Hvatum\OpenIDConnect\Client\OptionProvider\OpenIDConnectOptionProvider;
use Hvatum\OpenIDConnect\Client\Tool\ClientAssertionTrait;
use Hvatum\OpenIDConnect\Client\Tool\DPopTrait;
use Hvatum\OpenIDConnect\Client\Tool\PARTrait;
use Hvatum\OpenIDConnect\Client\Tool\WellKnownConfigTrait;
use Hvatum\OpenIDConnect\Client\Cache\FilesystemCache;
use Hvatum\OpenIDConnect\Client\Validator\NonceChecker;
use Psr\SimpleCache\CacheInterface;

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

    public const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'sub';

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
     * Minimum seconds between forced JWKS refreshes triggered by signature
     * failures. Rate-limits the key-rotation retry so a burst of invalid
     * tokens cannot turn into a JWKS fetch per token.
     */
    public const JWKS_FORCED_REFRESH_COOLDOWN = 60;

    /**
     * Protocol artifacts with no consumer meaning; never reach the
     * resource owner.
     */
    private const PROTOCOL_ARTIFACT_CLAIMS = ['at_hash', 'c_hash', 'nonce', 'azp'];

    /**
     * Auth-context claims: filtered from the ID-token side of the merge,
     * kept when userinfo provides them (OIDC Core §5.5). From userinfo they
     * describe the session at query time, which can drift from the login
     * event the ID token asserted.
     */
    private const AUTH_CONTEXT_CLAIMS = ['auth_time', 'acr', 'amr'];

    /**
     * JWT envelope claims; stripped from userinfo before the merge.
     */
    private const JWT_ENVELOPE_CLAIMS = ['iss', 'aud', 'exp', 'iat', 'nbf', 'jti'];

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
    protected ?string $endSessionUrl = null;
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
     * Algorithms the server supports for signing ID tokens.
     * REQUIRED per OIDC Discovery §3; defaults to ['RS256'] if absent.
     * @var array<string>
     */
    protected array $idTokenSigningAlgValuesSupported = ['RS256'];

    /**
     * Algorithms the server supports for signing userinfo responses
     * (OIDC Core §5.3.2). OPTIONAL per OIDC Discovery; null means not
     * advertised, in which case the id_token algorithms are assumed.
     * @var array<string>|null
     */
    protected ?array $userinfoSigningAlgValuesSupported = null;

    /**
     * Algorithms the server supports for token endpoint auth signing.
     * OPTIONAL per OIDC Discovery; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $tokenEndpointAuthSigningAlgValuesSupported = null;

    /**
     * Algorithms the server supports for DPoP proof signing (RFC 9449).
     * OPTIONAL; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $dpopSigningAlgValuesSupported = null;

    /**
     * Authentication methods the server supports at the token endpoint.
     * OPTIONAL per OIDC Discovery; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $tokenEndpointAuthMethodsSupported = null;

    /**
     * Code challenge methods the server supports for PKCE (RFC 7636).
     * OPTIONAL; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $codeChallengeMethodsSupported = null;

    /**
     * Whether the server requires Pushed Authorization Requests (RFC 9126).
     */
    protected bool $requirePushedAuthorizationRequests = false;

    /**
     * Whether to enforce RFC 9207 issuer identification validation.
     * When true (default), if the AS advertises support, callbacks missing
     * the iss parameter will be rejected.
     */
    protected bool $enforceIssuerIdentification = true;

    /**
     * Additional azp (authorized party) values accepted by
     * isAcceptedAuthorizedParty(), from the `allowedAuthorizedParties`
     * constructor option. This client's own ID is always accepted.
     * @var array<string>
     */
    protected array $allowedAuthorizedParties = [];

    /**
     * ID token from last token response
     */
    protected ?string $idToken = null;
    protected ?array $validatedIdTokenClaims = null;

    /**
     * JWKS cache TTL in seconds (configurable via options)
     */
    protected int $jwksCacheTtl = self::JWKS_CACHE_TTL;

    /**
     * Last token request params (for DPoP nonce retry)
     */
    protected ?array $lastTokenParams = null;

    /**
     * In-process memoization for JWT validation machinery derived from
     * post-discovery-immutable state. The parsed JWKSet is keyed by the raw
     * JWKS data, so PSR-16 TTL expiry and forced refreshes invalidate it
     * naturally; checkers/verifiers never change after discovery.
     */
    private ?array $jwkSetMemoSource = null;
    private ?JWKSet $jwkSetMemo = null;
    private ?array $baseClaimCheckersMemo = null;
    /** @var array<string, JWSVerifier> */
    private array $jwsVerifierMemo = [];

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
     * - privateKeyPath: Filesystem path to a PEM or JWK private key file for
     *   client assertion (RFC 7523).
     * - privateKey: Raw PEM or JWK JSON private key content for client assertion
     *   — for env-var / Kubernetes-style deployments where keys are not on disk.
     *   Mutually exclusive with privateKeyPath; setting both throws.
     * - keyId: Key ID for client assertion
     * - dpopPrivateKeyPath / dpopPublicKeyPath: Filesystem paths to PEM/JWK
     *   DPoP key files (RFC 9449).
     * - dpopPrivateKey / dpopPublicKey: Raw PEM/JWK content for DPoP keys.
     *   Each *Key option is mutually exclusive with its *KeyPath counterpart.
     * - cacheDir: Custom cache directory (used when no PSR-16 cache is provided)
     * - wellKnownCacheTtl: Discovery metadata cache TTL in seconds (non-negative integer)
     * - jwksCacheTtl: JWKS cache TTL in seconds (non-negative integer)
     * - allowedAuthorizedParties: Additional azp values accepted during JWT
     *   validation (array of non-empty strings); see isAcceptedAuthorizedParty()
     *
     * @param array $options Provider configuration options
     * @param array $collaborators Optional collaborators (httpClient, requestFactory, logger, cache)
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (empty($options['issuer'])) {
            throw new \InvalidArgumentException('issuer is required for OpenID Connect discovery');
        }

        // Initialize logger (use NullLogger if not provided)
        $this->logger = $collaborators['logger'] ?? new NullLogger();

        // Options validated manually below; league's option-to-property mass
        // assignment must not write them onto the typed properties unchecked
        // (non-coercible values would surface as vendor TypeErrors).
        array_push(
            $this->guarded,
            'allowedAuthorizedParties',
            'enforceIssuerIdentification',
            'jwksCacheTtl',
            'wellKnownCacheTtl'
        );

        parent::__construct($options, $collaborators);

        // Use custom option provider that delegates body building to this provider
        $this->setOptionProvider(new OpenIDConnectOptionProvider(
            fn(array $params) => $this->getAccessTokenBody($params)
        ));

        // Initialize PSR-16 cache (use provided, or default to filesystem)
        if (isset($collaborators['cache']) && $collaborators['cache'] instanceof CacheInterface) {
            $this->cache = $collaborators['cache'];
        } else {
            $cacheDir = $options['cacheDir'] ?? $this->getDefaultCacheDir();
            $this->cache = new FilesystemCache($cacheDir);
        }

        $this->wellKnownCacheTtl = $this->resolveCacheTtlOption(
            $options,
            'wellKnownCacheTtl',
            $this->wellKnownCacheTtl
        );
        $this->jwksCacheTtl = $this->resolveCacheTtlOption(
            $options,
            'jwksCacheTtl',
            static::JWKS_CACHE_TTL
        );

        // All option validation happens before discovery so bad config
        // fails without network I/O
        $this->allowedAuthorizedParties = $this->resolveStringListOption(
            $options,
            'allowedAuthorizedParties',
            []
        );
        $this->enforceIssuerIdentification = $this->resolveBoolOption(
            $options,
            'enforceIssuerIdentification',
            $this->enforceIssuerIdentification
        );

        // Derive well-known URL from issuer, or use explicit override
        $this->expectedIssuer = $options['issuer'];
        $wellKnownUrl = $options['wellKnownUrl']
            ?? rtrim($this->expectedIssuer, '/') . '/.well-known/openid-configuration';
        $this->loadWellKnownConfiguration($wellKnownUrl, $this->expectedIssuer);

        $this->logger->debug('OpenID Connect provider initialized', [
            'issuer' => $this->issuerUrl,
            'par_enabled' => $this->parUrl !== null,
        ]);

        // Optional: Initialize client assertion (private_key_jwt). `privateKey`
        // and `privateKeyPath` are mutually exclusive; the helper resolves to
        // raw key content (reading the file when given a path) and the trait
        // never sees a path at all.
        $clientAssertionContent = self::resolveKeyMaterialOption(
            $options,
            'privateKey',
            'privateKeyPath'
        );
        if ($clientAssertionContent !== null) {
            $this->initializeClientAssertion(
                $clientAssertionContent,
                self::extractStringOption($options, 'keyId')
            );
        }

        // Optional: Initialize DPoP. Resolve BOTH options upfront so wrong
        // types fail-fast even when only the public side is misconfigured —
        // otherwise the public option would never be inspected at all.
        $dpopPrivateContent = self::resolveKeyMaterialOption(
            $options,
            'dpopPrivateKey',
            'dpopPrivateKeyPath'
        );
        $dpopPublicContent = self::resolveKeyMaterialOption(
            $options,
            'dpopPublicKey',
            'dpopPublicKeyPath'
        );
        if ($dpopPrivateContent === null && $dpopPublicContent !== null) {
            throw new \InvalidArgumentException(
                '`dpopPublicKey` / `dpopPublicKeyPath` requires a corresponding '
                . '`dpopPrivateKey` / `dpopPrivateKeyPath` — a public key alone '
                . 'cannot sign DPoP proofs.'
            );
        }
        if ($dpopPrivateContent !== null) {
            // Public key may be omitted; the trait derives it from the private key.
            $this->initializeDPoP($dpopPrivateContent, $dpopPublicContent);
        }
    }

    /**
     * Resolve a pair of mutually-exclusive raw / path key options into raw content.
     *
     * Empty strings and explicit nulls are treated as unset (typical for unset
     * env vars). Setting both options throws. Wrong-typed values throw rather
     * than silently disabling auth. A path option is read at construction so
     * file problems surface fast.
     *
     * @param array<string,mixed> $options
     * @return string|null Raw key content, or null if neither option is set
     */
    private static function resolveKeyMaterialOption(
        array $options,
        string $rawOption,
        string $pathOption
    ): ?string {
        $raw = self::extractStringOption($options, $rawOption);
        $path = self::extractStringOption($options, $pathOption);

        if ($raw !== null && $path !== null) {
            throw new \InvalidArgumentException(sprintf(
                'Provide either `%s` (raw PEM/JWK content) or `%s` (filesystem path), not both.',
                $rawOption,
                $pathOption
            ));
        }

        if ($raw !== null) {
            return $raw;
        }

        if ($path === null) {
            return null;
        }

        if (!is_file($path)) {
            throw new \InvalidArgumentException(sprintf(
                '`%s` must be a readable file: %s',
                $pathOption,
                $path
            ));
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            throw new \InvalidArgumentException(sprintf(
                'Failed to read `%s` file: %s',
                $pathOption,
                $path
            ));
        }

        return $content;
    }

    /**
     * Extract a non-empty string from a constructor option, fail-fast on type
     * confusion.
     *
     * Returns null when the option is unset, explicitly null, or an empty
     * string — empty is treated as unset so deployments can write
     * `'foo' => getenv('BAR') ?: ''` without silently disabling features. Any
     * other type throws InvalidArgumentException: silently coercing an array
     * or int to "absent" can downgrade auth in production deployments where
     * a typo in env-var plumbing would otherwise go unnoticed.
     *
     * @param array<string,mixed> $options
     */
    private static function extractStringOption(array $options, string $key): ?string
    {
        if (!array_key_exists($key, $options)) {
            return null;
        }
        $value = $options[$key];
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_string($value)) {
            throw new \InvalidArgumentException(sprintf(
                '`%s` must be a string, got %s',
                $key,
                get_debug_type($value)
            ));
        }
        return $value;
    }

    /**
     * Get default cache directory with per-user namespace.
     */
    protected function getDefaultCacheDir(): string
    {
        $identifier = null;

        if (function_exists('posix_geteuid')) {
            $uid = posix_geteuid();
            if ($uid >= 0) {
                $identifier = 'uid:' . $uid;
            }
        }

        if ($identifier === null) {
            $user = getenv('USER') ?: getenv('USERNAME');
            if (is_string($user) && $user !== '') {
                $identifier = 'user:' . $user;
            }
        }

        $namespace = $identifier !== null ? hash('sha256', $identifier) : 'default';
        return sys_get_temp_dir() . '/oauth2-oidc/' . $namespace;
    }

    /**
     * Resolve and validate cache TTL option.
     *
     * @param array<string,mixed> $options
     */
    protected function resolveCacheTtlOption(array $options, string $optionName, int $default): int
    {
        if (!array_key_exists($optionName, $options)) {
            return $default;
        }

        $value = $options[$optionName];
        if (!is_int($value) || $value < 0) {
            throw new \InvalidArgumentException(
                sprintf('%s must be a non-negative integer number of seconds', $optionName)
            );
        }

        return $value;
    }

    protected function resolveBoolOption(array $options, string $optionName, bool $default): bool
    {
        if (!array_key_exists($optionName, $options)) {
            return $default;
        }

        $value = $options[$optionName];
        if (!is_bool($value)) {
            throw new \InvalidArgumentException(sprintf(
                '`%s` must be a bool, got %s',
                $optionName,
                get_debug_type($value)
            ));
        }

        return $value;
    }

    /**
     * @param array<string> $default
     * @return array<string>
     */
    protected function resolveStringListOption(array $options, string $optionName, array $default): array
    {
        if (!array_key_exists($optionName, $options)) {
            return $default;
        }

        $value = $options[$optionName];
        // Empty strings rejected too: config like explode(',', '') yields ['']
        $isNonEmptyString = static fn($v): bool => is_string($v) && $v !== '';
        if (!is_array($value) || $value !== array_filter($value, $isNonEmptyString)) {
            throw new \InvalidArgumentException(
                sprintf('`%s` must be an array of non-empty strings', $optionName)
            );
        }

        return array_values($value);
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
     * Get an access token from the authorization code.
     *
     * Automatically extracts the RFC 9207 `iss` parameter from options
     * so callers can pass it alongside `code`:
     *
     *     $token = $provider->getAccessToken('authorization_code', [
     *         'code' => $_GET['code'],
     *         'iss'  => $_GET['iss'] ?? null,
     *     ]);
     *
     * @param mixed $grant
     * @param array $options
     * @return AccessToken
     */
    public function getAccessToken($grant, array $options = [])
    {
        // Extract RFC 9207 iss parameter before passing to parent
        if (array_key_exists('iss', $options)) {
            $this->setCallbackIssuer($options['iss']);
            unset($options['iss']);
        }

        $token = parent::getAccessToken($grant, $options);
        if (!$token instanceof AccessToken) {
            // League types getResourceOwner() on the concrete AccessToken, so a
            // custom createAccessToken() override must stay within that class.
            throw new \UnexpectedValueException(sprintf(
                'createAccessToken() must return %s, got %s',
                AccessToken::class,
                get_debug_type($token)
            ));
        }

        return $token;
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
            $proof = $this->createDPopProof('POST', $request->getUri());
            $request = $request->withHeader('DPoP', $proof);
            $this->logger->debug('DPoP proof attached to token request', [
                'uri' => (string) $request->getUri(),
                'has_nonce' => $this->getDPopNonce() !== null,
            ]);
        }

        return $request;
    }

    /**
     * Get the audience URL for client assertion JWTs.
     *
     * Default: the issuer identifier. draft-ietf-oauth-rfc7523bis §4
     * (updating RFC 7523 §3) requires the issuer identifier as the client
     * authentication assertion's *sole* audience value and forbids the token
     * endpoint URL, tightening both the original RFC 7523 §3 (which merely
     * allowed the token endpoint) and OpenID Connect Core §9 (which
     * recommended it). Servers following the newer rule reject token-endpoint
     * audiences outright.
     *
     * Override in subclasses for legacy servers that only accept the token
     * endpoint URL:
     *
     *     protected function getClientAssertionAudience(): string
     *     {
     *         return $this->tokenUrl;
     *     }
     *
     * See https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/
     * section 4
     *
     * @return string
     */
    protected function getClientAssertionAudience(): string
    {
        return $this->issuerUrl;
    }

    /**
     * Build access token request body
     *
     * Adds client assertion, authorization_details (RFC 9396), and handles formatting.
     *
     * @param array $params
     * @return string
     */
    protected function getAccessTokenBody(array $params): string
    {
        // Validate token endpoint auth method against server's advertised list
        if ($this->tokenEndpointAuthMethodsSupported !== null) {
            $method = $this->hasClientAssertion() ? 'private_key_jwt' : 'client_secret_post';
            if (!in_array($method, $this->tokenEndpointAuthMethodsSupported, true)) {
                throw new \RuntimeException(
                    sprintf(
                        'Client uses %s authentication but the authorization server does not support it. Supported: %s',
                        $method,
                        implode(', ', $this->tokenEndpointAuthMethodsSupported)
                    )
                );
            }
        }

        // RFC 9396: authorization_details is sent as a JSON string parameter.
        $params = $this->normalizeAuthorizationDetailsParameter($params);
        $authorizationDetails = $this->decodeAuthorizationDetailsValue($params['authorization_details'] ?? null);

        // Add client assertion (private_key_jwt) if configured
        if ($this->hasClientAssertion()) {
            $previousAuthorizationDetails = $this->clientAuthorizationDetails;
            $assertionDetails = $this->getAuthorizationDetailsForClientAssertion($params, $authorizationDetails);
            if ($assertionDetails !== null) {
                $this->setClientAuthorizationDetails($assertionDetails);

                if (!$this->shouldSendAuthorizationDetailsInTokenRequestBody($params, $authorizationDetails)) {
                    unset($params['authorization_details']);
                }
            }

            try {
                $assertion = $this->createClientAssertion($this->getClientAssertionAudience());
                $params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
                $params['client_assertion'] = $assertion;
                unset($params['client_secret']);
            } finally {
                $this->setClientAuthorizationDetails($previousAuthorizationDetails);
            }
        }

        // Join scope array with separator (parent doesn't handle this)
        if (isset($params['scope']) && is_array($params['scope'])) {
            $params['scope'] = implode($this->getScopeSeparator(), $params['scope']);
        }

        return $this->buildQueryString($params);
    }

    /**
     * Normalize authorization_details parameter to a JSON string (RFC 9396).
     *
     * @param array $params
     * @return array
     */
    protected function normalizeAuthorizationDetailsParameter(array $params): array
    {
        if (isset($params['authorization_details']) && !is_string($params['authorization_details'])) {
            try {
                $params['authorization_details'] = json_encode(
                    $params['authorization_details'],
                    JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
                );
            } catch (\JsonException $e) {
                throw new \RuntimeException(
                    'Failed to JSON-encode authorization_details: ' . $e->getMessage(),
                    0,
                    $e
                );
            }
        }

        return $params;
    }

    /**
     * Decode authorization_details value into array form for internal extension hooks.
     *
     * @param mixed $authorizationDetails
     * @return array|null
     */
    protected function decodeAuthorizationDetailsValue($authorizationDetails): ?array
    {
        if (is_array($authorizationDetails)) {
            return $authorizationDetails;
        }

        if (is_string($authorizationDetails)) {
            $decoded = json_decode($authorizationDetails, true);
            return is_array($decoded) ? $decoded : null;
        }

        return null;
    }

    /**
     * Extension hook for profile-specific claim embedding in client assertions.
     * Default keeps RFC 9396 behavior and does not copy authorization_details into JWT claims.
     *
     * @param array $params
     * @param array|null $authorizationDetails Decoded authorization_details if available
     * @return array|null Details to pass to setClientAuthorizationDetails(), or null for no embedding
     */
    protected function getAuthorizationDetailsForClientAssertion(array $params, ?array $authorizationDetails): ?array
    {
        return null;
    }

    /**
     * Extension hook to optionally omit authorization_details from the token request body
     * when getAuthorizationDetailsForClientAssertion() returns details.
     *
     * @param array $params
     * @param array|null $authorizationDetails
     * @return bool
     */
    protected function shouldSendAuthorizationDetailsInTokenRequestBody(array $params, ?array $authorizationDetails): bool
    {
        return true;
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
        // Nonces are scoped to the issuing server (RFC 9449 §9); the userinfo
        // path skips this hook and calls throwOnResponseError() directly so
        // resource-server nonces stay out of token-endpoint proofs.
        $this->extractDPopNonce($response);

        $this->throwOnResponseError($response, $data);
    }

    /**
     * Throw for HTTP error statuses or error-carrying bodies.
     *
     * Userinfo error handling dispatches through this hook instead of
     * checkResponse() (see there for why); subclasses mapping
     * provider-specific userinfo errors should override this method.
     *
     * @param ResponseInterface $response
     * @param array|string $data Parsed response body
     * @param bool $throwOnSuccessfulErrorBody Whether an `error` member in a
     *        2xx body is treated as an error (token-endpoint semantics).
     *        UserInfo passes false — a claims document may legally contain
     *        an `error` claim; real userinfo errors arrive via HTTP status
     *        (OIDC Core §5.3.3).
     * @throws IdentityProviderException
     */
    protected function throwOnResponseError(
        ResponseInterface $response,
        $data,
        bool $throwOnSuccessfulErrorBody = true
    ): void
    {
        $error = is_array($data) ? $data : [];

        // error/error_description are server-controlled; only strings may
        // reach the exception message or logs
        $errorCode = $this->nonEmptyStringOrNull($error['error'] ?? null);
        $message = $this->nonEmptyStringOrNull($error['error_description'] ?? null) ?? $errorCode;

        if ($response->getStatusCode() >= 400) {
            // RFC 6750 §3 (via OIDC Core §5.3.3): resource endpoints convey
            // error details in the WWW-Authenticate header, often with an
            // empty body — fall back to it before the bare reason phrase.
            $message ??= $this->wwwAuthenticateErrorMessage($response);

            $this->logger->warning('Request failed', [
                'status' => $response->getStatusCode(),
                'error' => $errorCode ?? 'unknown',
            ]);
            throw new IdentityProviderException(
                $message ?? $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }

        if ($throwOnSuccessfulErrorBody && isset($error['error'])) {
            $this->logger->warning('Response contains error', [
                'error' => $errorCode ?? gettype($error['error']),
            ]);
            throw new IdentityProviderException(
                $message ?? 'Authorization server returned an error response',
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Extract error/error_description from a WWW-Authenticate header
     * (RFC 6750 §3), e.g.:
     *
     *     WWW-Authenticate: Bearer error="invalid_token",
     *                       error_description="The Access Token expired"
     *
     * @return string|null error_description, error, or null when absent
     */
    private function wwwAuthenticateErrorMessage(ResponseInterface $response): ?string
    {
        $headers = $response->getHeader('WWW-Authenticate');
        if ($headers === []) {
            return null;
        }

        $params = [];
        foreach (Header::parse($headers) as $part) {
            foreach ($part as $name => $value) {
                if (!is_string($name)) {
                    continue;
                }

                $name = strtolower($name);
                if (str_starts_with($name, 'bearer ')) {
                    $name = substr($name, strlen('bearer '));
                }

                if (($name === 'error' || $name === 'error_description') && is_string($value) && $value !== '') {
                    $params[$name] = $value;
                }
            }
        }

        return $params['error_description'] ?? $params['error'] ?? null;
    }

    private function nonEmptyStringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Create resource owner from successful response
     *
     * @param array $response
     * @param AccessToken $token
     * @return OpenIDConnectResourceOwner
     * @throws IdentityProviderException If ID token validation fails or UserInfo sub does not match
     */
    protected function createResourceOwner(array $response, AccessToken $token): OpenIDConnectResourceOwner
    {
        // Uniform for all userinfo content types; sub survives for the
        // §5.3.2 match below
        $response = array_diff_key(
            $response,
            array_flip(array_merge(self::JWT_ENVELOPE_CLAIMS, self::PROTOCOL_ARTIFACT_CLAIMS))
        );

        // Merge ID token claims with userinfo (OIDC Core §5.3.2); userinfo
        // takes precedence
        if ($this->idToken !== null) {
            $idTokenClaims = $this->getValidatedIdTokenClaims();

            // OIDC Core §5.3.2: sub in UserInfo MUST exactly match ID token sub.
            if (isset($response['sub']) && $response['sub'] !== $idTokenClaims['sub']) {
                throw new IdentityProviderException(
                    'UserInfo sub claim does not match ID token sub claim',
                    0,
                    null
                );
            }

            $identityClaims = array_diff_key(
                $idTokenClaims,
                array_flip(array_merge(self::PROTOCOL_ARTIFACT_CLAIMS, self::AUTH_CONTEXT_CLAIMS))
            );
            $response = array_merge($identityClaims, $response);
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

        try {
            $response = $this->getResponse($request);
        } catch (RequestException $e) {
            // Guzzle 7 exposes the response on RequestException itself; Guzzle 8
            // only on its ResponseException subclass. Look it up on the instance
            // so one code path serves both.
            $response = method_exists($e, 'getResponse') ? $e->getResponse() : null;
            if (!$response instanceof ResponseInterface) {
                throw new IdentityProviderException($e->getMessage(), $e->getCode(), null);
            }
        }

        // Error statuses must surface as IdentityProviderException whatever
        // the body is (JSON, form-encoded, HTML, empty). Parse leniently for
        // error/error_description — parent::parseResponse() handles both JSON
        // and form-encoded bodies without this class's side effects.
        if ($response->getStatusCode() >= 400) {
            try {
                $error = parent::parseResponse($response);
            } catch (\UnexpectedValueException $e) {
                $error = [];
            }
            $parsed = is_array($error) ? $error : [];
        } elseif ($this->isJwtContentType($response)) {
            // OIDC Core §5.3.2: signed JWT userinfo, indicated by media type
            $this->logger->debug('UserInfo returned application/jwt; verifying signed response');
            return $this->decodeSignedUserinfoResponse((string) $response->getBody());
        } else {
            try {
                $parsed = $this->parseResponse($response);
            } catch (\UnexpectedValueException $e) {
                throw new IdentityProviderException($e->getMessage(), $response->getStatusCode(), $response);
            }
        }

        // Single dispatch through the error hook; when an override chooses
        // not to throw, the leniently parsed body is returned as-is.
        $this->throwOnResponseError($response, $parsed, $response->getStatusCode() >= 400);

        return $parsed;
    }

    /**
     * Whether a response carries the application/jwt media type (RFC 7519 §10.3.1)
     */
    private function isJwtContentType(ResponseInterface $response): bool
    {
        // parent::getContentType() so this reads the header the same way
        // parent::parseResponse() does
        $contentType = explode(';', $this->getContentType($response))[0];

        return strtolower(trim($contentType)) === 'application/jwt';
    }

    /**
     * Verify and decode a signed JWT userinfo response (OIDC Core §5.3.2)
     *
     * The signature is verified against the provider JWKS, iss/aud/sub are
     * required and checked, and exp/nbf/iat are checked when present (the
     * spec does not require them on userinfo responses).
     *
     * @return array<string,mixed>
     * @throws IdentityProviderException
     */
    protected function decodeSignedUserinfoResponse(string $jwt): array
    {
        $claims = $this->verifyJwsAgainstProviderKeys(
            trim($jwt),
            $this->getUserinfoSigningAlgValuesSupported(),
            'UserInfo response'
        );

        $this->checkRegisteredClaims($claims, [], ['iss', 'sub', 'aud'], 'UserInfo response', false);

        // Claim stripping happens in createResourceOwner()
        return $claims;
    }

    /**
     * Validate registered claims on a decoded JWT payload.
     *
     * Shared by ID-token and signed-userinfo validation so hardening lands in
     * both paths: issuer, audience and time-based checkers (with clock-skew
     * leeway), the caller's mandatory-claim list, a non-empty string sub
     * (OIDC Core §2), and azp screening — a present azp not accepted by
     * isAcceptedAuthorizedParty() is rejected on both paths.
     *
     * @param array<string,mixed> $claims Decoded JWT claims
     * @param array<\Jose\Component\Checker\ClaimChecker> $extraCheckers Additional checkers (e.g. NonceChecker)
     * @param array<string> $mandatoryClaims Claim names that must be present
     * @param string $label JWT type for error messages ('ID token', 'UserInfo response')
     * @param bool $requireAzpWithMultipleAudiences Whether multiple audiences require
     *        azp naming this client itself (conservative policy for ID tokens;
     *        signed userinfo does not require it, per OIDC Core §5.3.2)
     * @throws IdentityProviderException
     */
    private function checkRegisteredClaims(
        array $claims,
        array $extraCheckers,
        array $mandatoryClaims,
        string $label,
        bool $requireAzpWithMultipleAudiences
    ): void {
        try {
            $claimCheckerManager = new ClaimCheckerManager(
                array_merge($this->baseClaimCheckers(), $extraCheckers)
            );

            $claimCheckerManager->check($claims, $mandatoryClaims);
        } catch (MissingMandatoryClaimException $e) {
            $this->logger->warning("{$label} missing mandatory claims", [
                'reason' => $e->getMessage(),
                'claims' => $e->getClaims(),
            ]);
            throw new IdentityProviderException(
                "{$label} claim validation failed: " . $e->getMessage(),
                0,
                null
            );
        } catch (InvalidClaimException $e) {
            $this->logger->warning("{$label} claim validation failed", [
                'reason' => $e->getMessage(),
                'claim' => $e->getClaim(),
            ]);
            throw new IdentityProviderException(
                "{$label} claim validation failed: " . $e->getMessage(),
                0,
                null
            );
        } catch (\Throwable $e) {
            $this->logger->warning("{$label} validation failed", [
                'reason' => $e->getMessage(),
            ]);
            throw new IdentityProviderException(
                "Failed to validate {$label}: " . $e->getMessage(),
                0,
                null
            );
        }

        // Presence is enforced by the mandatory list; this adds the type check
        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new IdentityProviderException("{$label} sub claim must be a non-empty string", 0, null);
        }

        // A present azp naming an unaccepted party marks a JWT minted for a
        // different client (OIDC Core §3.1.3.7 #5)
        $azp = $claims['azp'] ?? null;
        if ($azp !== null && !$this->isAcceptedAuthorizedParty($azp)) {
            throw new IdentityProviderException("{$label} azp mismatch", 0, null);
        }

        // Local conservative policy, not literal spec wording: OIDC Core
        // §3.1.3.7 requires additional audiences to be trusted by the client.
        // A multi-audience JWT must name this client as the authorized party
        // — deliberately NOT the allow-list: an accepted foreign presenter is
        // only trusted with tokens minted solely for this client, not with
        // tokens minted for the presenter itself that happen to co-audience
        // us. That holds on both paths whenever azp is present; only ID
        // tokens additionally demand azp for multi-audience (userinfo may
        // omit it, per §5.3.2).
        if (count((array) ($claims['aud'] ?? [])) > 1
            && $azp !== $this->clientId
            && ($azp !== null || $requireAzpWithMultipleAudiences)
        ) {
            throw new IdentityProviderException(
                "{$label} azp must name this client when multiple audiences are present",
                0,
                null
            );
        }
    }

    /**
     * Whether an azp (authorized party) claim value is acceptable.
     *
     * Default: this client's ID, plus any IDs given in the
     * `allowedAuthorizedParties` constructor option. OIDC Core §3.1.3.7 (as
     * revised by the errata) leaves azp validation to the extension that put
     * the claim there, and some deployments legitimately present a different
     * party — e.g. Google hybrid app flows set azp to the native app's
     * client ID while aud names the web client.
     *
     * Applies to both ID tokens and signed userinfo responses, and only to
     * single-audience JWTs: a multi-audience JWT must carry azp naming this
     * client itself — the allow-list cannot loosen that. Override for
     * policies a static list cannot express (pattern matching, per-tenant
     * lookups).
     *
     * @param mixed $azp Raw azp claim value
     * @return bool
     */
    protected function isAcceptedAuthorizedParty($azp): bool
    {
        return $azp === $this->clientId
            || in_array($azp, $this->allowedAuthorizedParties, true);
    }

    /**
     * The claim checkers shared by every JWT validation, built once —
     * their inputs (issuer, client ID, leeway) are fixed after discovery.
     *
     * @return array<\Jose\Component\Checker\ClaimChecker>
     */
    private function baseClaimCheckers(): array
    {
        if ($this->baseClaimCheckersMemo === null) {
            // PSR-20 clock required by web-token v4 time-based checkers
            $clock = new class implements \Psr\Clock\ClockInterface {
                public function now(): \DateTimeImmutable
                {
                    return new \DateTimeImmutable();
                }
            };
            $this->baseClaimCheckersMemo = [
                new IssuerChecker([$this->issuerUrl]),
                new AudienceChecker($this->clientId),
                new ExpirationTimeChecker($clock, static::CLOCK_SKEW_LEEWAY),
                new NotBeforeChecker($clock, static::CLOCK_SKEW_LEEWAY),
                new IssuedAtChecker($clock, static::CLOCK_SKEW_LEEWAY),
            ];
        }

        return $this->baseClaimCheckersMemo;
    }

    /**
     * Signing algorithms accepted for signed userinfo responses
     *
     * Falls back to the id_token algorithms when the server does not
     * advertise userinfo_signing_alg_values_supported — a server signing
     * userinfo uses the same JWKS, and the result is still intersected with
     * what this library can verify. Override in provider-specific subclasses
     * when a server signs userinfo with algorithms it does not advertise.
     *
     * @return array<string>
     */
    protected function getUserinfoSigningAlgValuesSupported(): array
    {
        // ?: (not ??) so an explicit empty userinfo_signing_alg_values_supported
        // in discovery also falls back — an empty allow-list would reject every
        // signed response with an error naming an empty server list.
        return $this->userinfoSigningAlgValuesSupported ?: $this->idTokenSigningAlgValuesSupported;
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

        // RFC 9396: authorization_details in authorization and PAR requests is JSON.
        $params = $this->normalizeAuthorizationDetailsParameter($params);

        if ($this->shouldSendDpopJktInAuthorizationRequest() && !isset($params['dpop_jkt'])) {
            $params['dpop_jkt'] = $this->getDPopJwkThumbprint();
        }

        // Validate PKCE method against server's advertised list
        if ($this->codeChallengeMethodsSupported !== null
            && !in_array('S256', $this->codeChallengeMethodsSupported, true)
        ) {
            throw new \RuntimeException(
                'PKCE method S256 is not supported by the authorization server. Supported: '
                . implode(', ', $this->codeChallengeMethodsSupported)
            );
        }

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
     * Determine whether authorization requests should include dpop_jkt.
     *
     * Override in provider-specific subclasses when an authorization server's
     * interoperability profile rejects dpop_jkt on front-channel auth or PAR.
     */
    protected function shouldSendDpopJktInAuthorizationRequest(): bool
    {
        return $this->hasDPoP();
    }

    /**
     * Store token-response ID token metadata before constructing the access token.
     *
     * UserInfo responses are arbitrary claim documents and may legally contain
     * an `id_token` claim, so this must not happen in generic response parsing.
     *
     * @param array<string, mixed> $result
     * @return array<string, mixed>
     */
    protected function prepareAccessTokenResponse(array $result)
    {
        if (isset($result['id_token'])) {
            if (!is_string($result['id_token'])) {
                throw new \UnexpectedValueException('Invalid response from Authorization Server. id_token must be a string');
            }

            $this->idToken = $result['id_token'];
            $this->validatedIdTokenClaims = null;
        }

        return parent::prepareAccessTokenResponse($result);
    }

    /**
     * Parse the access token response
     *
     * @param ResponseInterface $response
     * @return array
     */
    protected function parseResponse(ResponseInterface $response): array
    {
        try {
            $parsed = parent::parseResponse($response);
        } catch (\UnexpectedValueException $e) {
            $this->logNonJsonResponse($e->getMessage());
            throw $e;
        }

        // Parent can return string/null for non-JSON responses
        if (!is_array($parsed)) {
            $message = 'Invalid response from Authorization Server. Expected JSON object, got: ' .
                (is_string($parsed) ? substr($parsed, 0, 100) : gettype($parsed));
            $this->logNonJsonResponse($message);
            throw new \UnexpectedValueException($message);
        }

        return $parsed;
    }

    private function logNonJsonResponse(string $reason): void
    {
        $this->logger->error('Request failed with non-JSON response', [
            'exception' => $reason,
        ]);
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
        // checkResponse() sets the exception message from the parsed error field,
        // so use_dpop_nonce will appear in the message if the server sent it.
        if (strpos(strtolower($e->getMessage()), 'use_dpop_nonce') !== false) {
            return true;
        }

        // Fallback: check the response body directly (safe stream read)
        $response = $e->getResponseBody();
        if ($response instanceof ResponseInterface) {
            $stream = $response->getBody();
            try {
                $stream->rewind();
                $body = (string) $stream;
                $data = json_decode($body, true);
                if (is_array($data) && ($data['error'] ?? null) === 'use_dpop_nonce') {
                    return true;
                }
            } catch (\Throwable $ignored) {
                // Stream may not be seekable; message check above is sufficient
            }
        }

        return false;
    }

    /**
     * Get the stored ID token from last authentication
     *
     * @return string|null
     * @throws IdentityProviderException If the stored ID token fails validation
     */
    public function getIdToken(): ?string
    {
        if ($this->idToken !== null) {
            // Ensure callers do not consume an unvalidated ID token.
            // Throws on error
            $this->getValidatedIdTokenClaims();
        }

        // Return all the original token, not just the validated claims
        return $this->idToken;
    }

    /**
     * Validate and cache claims for the stored ID token.
     *
     * @return array|null
     * @throws IdentityProviderException If the stored ID token fails validation
     */
    protected function getValidatedIdTokenClaims(): ?array
    {
        if ($this->idToken === null) {
            return null;
        }

        if ($this->validatedIdTokenClaims === null) {
            $this->validatedIdTokenClaims = $this->validateIdToken($this->idToken);
        }

        return $this->validatedIdTokenClaims;
    }

    /**
     * Get the nonce used in the authorization request
     *
     * @return string|null
     * @codeCoverageIgnore
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
        $this->validatedIdTokenClaims = null;
    }

    /**
     * Get the callback issuer (RFC 9207)
     *
     * @return string|null
     * @codeCoverageIgnore
     */
    public function getCallbackIssuer(): ?string
    {
        return $this->callbackIssuer;
    }

    /**
     * Set callback issuer from authorization response (RFC 9207)
     *
     * Automatically set when passing 'iss' in getAccessToken() options.
     * Can also be called manually if needed before getIdToken()/validateIdToken().
     *
     * @param string|null $issuer
     */
    public function setCallbackIssuer(?string $issuer): void
    {
        $this->callbackIssuer = $issuer;
        $this->validatedIdTokenClaims = null;
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
     * @codeCoverageIgnore
     */
    public function getIssuerUrl(): ?string
    {
        return $this->issuerUrl;
    }

    /**
     * Get the end session endpoint from well-known configuration
     * (RP-Initiated Logout 1.0)
     *
     * @return string|null
     * @codeCoverageIgnore
     */
    public function getEndSessionEndpoint(): ?string
    {
        return $this->endSessionUrl;
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

        $decoded = $this->verifyJwsAgainstProviderKeys(
            $idToken,
            $this->idTokenSigningAlgValuesSupported,
            'ID token'
        );

        // Mandatory claims per OIDC Core; add nonce when one was sent (§3.1.3.7).
        // checkRegisteredClaims() only validates — $decoded is returned whole so
        // callers keep claims beyond the explicitly checked ones.
        $mandatoryClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
        if ($nonce !== null) {
            $mandatoryClaims[] = 'nonce';
        }
        $this->checkRegisteredClaims($decoded, [new NonceChecker($nonce)], $mandatoryClaims, 'ID token', true);

        $this->logger->debug('ID token validated successfully', [
            'sub' => $decoded['sub'],
            'iss' => $decoded['iss'] ?? 'unknown',
        ]);

        return $decoded;
    }

    /**
     * Parse a compact JWS, enforce the signing-algorithm allow-list, verify
     * the signature against the provider JWKS (with one forced-refresh retry
     * to absorb key rotation) and decode the payload.
     *
     * Claim validation is deliberately NOT done here — mandatory claims
     * differ per JWT type (ID token vs userinfo response), so callers apply
     * their own ClaimCheckerManager to the returned claims.
     *
     * @param array<string> $serverAlgorithms Algorithms the server advertises for this JWT type
     * @param string $label Human-readable JWT type used in error messages ('ID token', 'UserInfo response')
     * @return array<string,mixed> Decoded claims
     * @throws IdentityProviderException
     */
    private function verifyJwsAgainstProviderKeys(string $jwt, array $serverAlgorithms, string $label): array
    {
        if ($this->jwksUrl === null) {
            throw new IdentityProviderException("JWKS URL not available for {$label} validation", 0, null);
        }

        // Parse with serializer (avoid hand-rolled JWT decoding).
        $serializer = new CompactSerializer();
        try {
            $jws = $serializer->unserialize($jwt);
            $header = $jws->getSignature(0)->getProtectedHeader();
        } catch (\Throwable $e) {
            // Distinguish encrypted tokens from garbage: a JWE protected
            // header carries an "enc" member (RFC 7516 §4.1.2). Decryption
            // is not supported.
            $segments = explode('.', $jwt);
            try {
                $protected = json_decode(Base64UrlSafe::decodeNoPadding($segments[0]), true);
            } catch (\Throwable $decodeError) {
                $protected = null;
            }
            if (is_array($protected) && isset($protected['enc'])) {
                throw new IdentityProviderException(
                    "Encrypted (JWE) {$label}s are not supported. "
                    . 'Configure the authorization server to use signed (JWS) responses instead.',
                    0,
                    null
                );
            }
            throw new IdentityProviderException("Invalid {$label} format", 0, null);
        }

        // Algorithms this library can verify (prevent algorithm confusion attacks)
        $librarySupported = [
            'ES256', 'ES384', 'ES512',
            'RS256', 'RS384', 'RS512',
            'PS256', 'PS384', 'PS512',
        ];

        // Intersect with what the server advertises (from discovery)
        $allowedAlgorithms = array_values(array_intersect(
            $librarySupported,
            $serverAlgorithms
        ));

        if (empty($allowedAlgorithms)) {
            throw new IdentityProviderException(
                "No mutually supported {$label} signing algorithms. "
                . 'Server supports: ' . implode(', ', $serverAlgorithms)
                . '. Library supports: ' . implode(', ', $librarySupported),
                0,
                null
            );
        }

        $tokenAlg = $header['alg'] ?? null;

        if (!is_string($tokenAlg) || !in_array($tokenAlg, $allowedAlgorithms, true)) {
            $this->logger->warning("{$label} uses disallowed algorithm", [
                'algorithm' => $tokenAlg,
                'allowed' => $allowedAlgorithms,
            ]);
            throw new IdentityProviderException(
                "Invalid {$label} algorithm: '{$tokenAlg}'. Allowed: " . implode(', ', $allowedAlgorithms),
                0,
                null
            );
        }

        try {
            $jwsVerifier = $this->jwsVerifierFor($allowedAlgorithms);
            $jwks = $this->getJwks();
            $jwkSet = $this->jwkSetFor($jwks);

            if (!$jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0)) {
                // Retry once with fresh JWKS in case the key set rotated
                // recently. A kid missing from the current set is the
                // rotation signal and always refreshes; retries for a kid
                // the set already contains rarely help, so those are
                // rate-limited to stop bursts of invalid tokens hammering
                // the jwks_uri or evicting a valid cached key set.
                $kid = $header['kid'] ?? null;
                $unknownKid = is_string($kid) && !$this->jwksContainsKid($jwks, $kid);
                if (!$unknownKid && !$this->mayForceJwksRefresh()) {
                    throw new \RuntimeException('Signature verification failed');
                }
                $jwkSet = $this->jwkSetFor($this->getJwks(true));
                if (!$jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0)) {
                    throw new \RuntimeException('Signature verification failed');
                }
            }

            $decoded = json_decode($jws->getPayload(), true);
            if (!is_array($decoded)) {
                throw new \RuntimeException('Invalid payload');
            }
        } catch (\Throwable $e) {
            $this->logger->warning("{$label} validation failed", [
                'reason' => $e->getMessage(),
            ]);
            throw new IdentityProviderException(
                "Failed to validate {$label}: " . $e->getMessage(),
                0,
                null
            );
        }

        return $decoded;
    }

    /**
     * A JWSVerifier restricted to the given algorithms, reused per list.
     *
     * @param array<string> $allowedAlgorithms Already intersected allow-list
     */
    private function jwsVerifierFor(array $allowedAlgorithms): JWSVerifier
    {
        $memoKey = implode(',', $allowedAlgorithms);
        if (!isset($this->jwsVerifierMemo[$memoKey])) {
            $algorithmMap = [
                'ES256' => ES256::class, 'ES384' => ES384::class, 'ES512' => ES512::class,
                'RS256' => RS256::class, 'RS384' => RS384::class, 'RS512' => RS512::class,
                'PS256' => PS256::class, 'PS384' => PS384::class, 'PS512' => PS512::class,
            ];
            $algorithms = [];
            foreach ($allowedAlgorithms as $alg) {
                $algorithms[] = new $algorithmMap[$alg]();
            }
            $this->jwsVerifierMemo[$memoKey] = new JWSVerifier(new AlgorithmManager($algorithms));
        }

        return $this->jwsVerifierMemo[$memoKey];
    }

    /**
     * Parse a raw JWKS array into a JWKSet, reusing the parsed set while
     * the raw data is unchanged.
     */
    private function jwkSetFor(array $jwks): JWKSet
    {
        if ($this->jwkSetMemoSource !== $jwks) {
            $this->jwkSetMemo = JWKSet::createFromKeyData($jwks);
            $this->jwkSetMemoSource = $jwks;
        }

        return $this->jwkSetMemo;
    }

    /**
     * Whether the JWKS document lists a key with the given kid.
     *
     * @param array<string,mixed> $jwks Raw JWKS document
     */
    private function jwksContainsKid(array $jwks, string $kid): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $kid) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a known-kid signature failure may trigger a forced JWKS
     * refresh now.
     *
     * At most one such refresh per JWKS_FORCED_REFRESH_COOLDOWN, tracked in
     * the PSR-16 cache so the limit holds across requests. Unknown-kid
     * failures bypass this entirely (see verifyJwsAgainstProviderKeys) so
     * invalid tokens can never suppress recovery from a real key rotation.
     */
    private function mayForceJwksRefresh(): bool
    {
        if ($this->cache === null) {
            return true;
        }

        $cacheKey = 'jwks_forced_refresh_' . md5($this->jwksUrl ?? '');
        $last = $this->cache->get($cacheKey);
        if (is_int($last) && time() - $last < static::JWKS_FORCED_REFRESH_COOLDOWN) {
            return false;
        }

        $this->cache->set($cacheKey, time(), static::JWKS_FORCED_REFRESH_COOLDOWN);
        return true;
    }

    /**
     * Fetch JWKS with PSR-16 caching
     *
     * @return array
     * @throws IdentityProviderException
     */
    protected function getJwks(bool $forceRefresh = false): array
    {
        // Check PSR-16 cache
        $cacheKey = 'jwks_' . md5($this->jwksUrl ?? '');
        if (!$forceRefresh && $this->cache !== null) {
            $cached = $this->cache->get($cacheKey);
            if (is_array($cached) && isset($cached['keys']) && is_array($cached['keys'])) {
                $this->logger->debug('Using cached JWKS', [
                    'key_count' => count($cached['keys']),
                ]);
                return $cached;
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

            $this->cache?->set($cacheKey, $data, $this->jwksCacheTtl);

            $this->logger->debug('Fetched fresh JWKS', [
                'key_count' => count($data['keys']),
            ]);

            return $data;
        } catch (IdentityProviderException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new IdentityProviderException(
                'Failed to fetch JWKS: ' . $e->getMessage(),
                0,
                null
            );
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
        if ($this->requirePushedAuthorizationRequests && $this->parUrl === null) {
            throw new \RuntimeException(
                'The authorization server requires Pushed Authorization Requests (PAR) '
                . 'but no pushed_authorization_request_endpoint was found in the discovery document'
            );
        }

        return $this->parUrl !== null;
    }
}
