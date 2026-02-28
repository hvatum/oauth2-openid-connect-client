<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

/**
 * Well-Known Configuration Discovery Trait
 *
 * Implements automatic endpoint discovery from OpenID Connect
 * well-known configuration endpoint with file-based caching
 */
trait WellKnownConfigTrait
{
    /**
     * Static in-memory cache for well-known config
     */
    protected static array $wellKnownConfigCache = [];

    /**
     * Cache TTL in seconds (24 hours)
     */
    protected int $wellKnownCacheTtl = 86400;

    /**
     * Cache directory path
     */
    protected ?string $cacheDir = null;

    /**
     * Load well-known configuration from endpoint
     *
     * @param string $wellKnownUrl
     * @param string $expectedIssuer Expected issuer for validation (OIDC Discovery §4.3)
     * @throws IdentityProviderException
     * @throws \InvalidArgumentException
     */
    protected function loadWellKnownConfiguration(string $wellKnownUrl, string $expectedIssuer): void
    {
        // Enforce HTTPS for security - prevents MITM attacks on configuration discovery
        $scheme = parse_url($wellKnownUrl, PHP_URL_SCHEME);
        if ($scheme === null || strtolower($scheme) !== 'https') {
            throw new \InvalidArgumentException(
                'Well-known configuration URL must use HTTPS to prevent man-in-the-middle attacks'
            );
        }

        // Check in-memory cache first
        if (isset(self::$wellKnownConfigCache[$wellKnownUrl])) {
            $cachedEntry = self::$wellKnownConfigCache[$wellKnownUrl];
            if ($this->isFreshInMemoryWellKnownCacheEntry($cachedEntry)) {
                $config = $cachedEntry['config'];
                $this->validateWellKnownConfig($config, $expectedIssuer);
                $this->setEndpointsFromConfig($config);
                return;
            }

            unset(self::$wellKnownConfigCache[$wellKnownUrl]);
        }

        // Check file cache
        $cacheFile = $this->getWellKnownCacheFile($wellKnownUrl);
        $cachedConfig = $this->loadWellKnownFromCache($cacheFile);

        if ($cachedConfig !== null) {
            $this->validateWellKnownConfig($cachedConfig, $expectedIssuer);
            $loadedAt = filemtime($cacheFile);
            self::$wellKnownConfigCache[$wellKnownUrl] = [
                'config' => $cachedConfig,
                // Preserve file cache age so in-memory cache does not outlive TTL.
                'loaded_at' => is_int($loadedAt) ? $loadedAt : time(),
            ];
            $this->setEndpointsFromConfig($cachedConfig);
            return;
        }

        // Fetch fresh configuration
        try {
            $request = $this->getRequest('GET', $wellKnownUrl);
            $response = $this->getHttpClient()->send($request);

            if ($response->getStatusCode() !== 200) {
                throw new IdentityProviderException(
                    "Failed to fetch well-known configuration: HTTP {$response->getStatusCode()}",
                    $response->getStatusCode(),
                    $response
                );
            }

            $body = (string)$response->getBody();
            $config = json_decode($body, true);

            if (!is_array($config)) {
                throw new IdentityProviderException(
                    'Invalid well-known configuration: not valid JSON',
                    0,
                    $response
                );
            }

            $this->validateWellKnownConfig($config, $expectedIssuer);

            // Cache the configuration
            self::$wellKnownConfigCache[$wellKnownUrl] = [
                'config' => $config,
                'loaded_at' => time(),
            ];
            $this->saveWellKnownToCache($cacheFile, $config);

            // Set endpoints
            $this->setEndpointsFromConfig($config);

        } catch (IdentityProviderException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                "Failed to fetch well-known configuration: " . $e->getMessage(),
                0,
                null
            );
        }
    }

    /**
     * Validate well-known configuration has required fields and correct issuer
     *
     * @param array $config
     * @param string $expectedIssuer
     * @throws IdentityProviderException
     */
    protected function validateWellKnownConfig(array $config, string $expectedIssuer): void
    {
        $requiredFields = ['issuer', 'authorization_endpoint', 'token_endpoint'];
        foreach ($requiredFields as $field) {
            if (!isset($config[$field])) {
                throw new IdentityProviderException(
                    "Invalid well-known configuration: missing {$field}",
                    0,
                    null
                );
            }
        }

        // OIDC Discovery / RFC 8414: issuer identifier is an https URL.
        $this->assertHttpsUrl('issuer', $config['issuer']);

        // Endpoint URLs in discovery metadata must use HTTPS.
        $endpointFields = [
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'pushed_authorization_request_endpoint',
            'revocation_endpoint',
        ];

        foreach ($endpointFields as $field) {
            if (isset($config[$field]) && $config[$field] !== null) {
                $this->assertHttpsUrl($field, $config[$field]);
            }
        }

        // OIDC Discovery §4.3: issuer in response must match expected issuer
        if ($config['issuer'] !== $expectedIssuer) {
            throw new IdentityProviderException(
                sprintf(
                    'Issuer mismatch in discovery document: expected "%s", got "%s"',
                    $expectedIssuer,
                    $config['issuer']
                ),
                0,
                null
            );
        }
    }

    /**
     * Validate metadata URL is an HTTPS URL.
     *
     * @param string $field
     * @param mixed $value
     * @throws IdentityProviderException
     */
    protected function assertHttpsUrl(string $field, $value): void
    {
        if (!is_string($value)) {
            throw new IdentityProviderException(
                sprintf('Invalid well-known configuration: %s must be a string URL', $field),
                0,
                null
            );
        }

        $scheme = parse_url($value, PHP_URL_SCHEME);
        if ($scheme === null || strtolower($scheme) !== 'https') {
            throw new IdentityProviderException(
                sprintf('Invalid well-known configuration: %s must use https URL', $field),
                0,
                null
            );
        }
    }

    /**
     * Set endpoint URLs from configuration
     *
     * @param array $config
     */
    protected function setEndpointsFromConfig(array $config): void
    {
        $this->authorizationUrl = $config['authorization_endpoint'];
        $this->tokenUrl = $config['token_endpoint'];
        $this->userInfoUrl = $config['userinfo_endpoint'] ?? null;
        $this->issuerUrl = $config['issuer'];
        $this->jwksUrl = $config['jwks_uri'] ?? null;
        $this->parUrl = $config['pushed_authorization_request_endpoint'] ?? null;
        $this->revocationUrl = $config['revocation_endpoint'] ?? null;
        $this->issuerResponseParameterSupported = !empty($config['authorization_response_iss_parameter_supported']);
    }

    /**
     * Get cache file path for well-known config
     *
     * @param string $wellKnownUrl
     * @return string
     */
    protected function getWellKnownCacheFile(string $wellKnownUrl): string
    {
        $cacheDir = $this->getWellKnownCacheDir();
        $cacheKey = md5($wellKnownUrl);
        return $cacheDir . '/wellknown_' . $cacheKey . '.json';
    }

    /**
     * Get cache directory
     *
     * @return string
     */
    protected function getWellKnownCacheDir(): string
    {
        if ($this->cacheDir !== null) {
            return $this->cacheDir;
        }

        // Default to a per-user directory inside system temp
        return sys_get_temp_dir() . '/oauth2-oidc/' . $this->getCacheNamespace();
    }

    /**
     * Derive a namespace so caches are not shared across system users.
     */
    protected function getCacheNamespace(): string
    {
        $identifier = $this->getRuntimeUserIdentifier();
        return $identifier !== null ? hash('sha256', $identifier) : 'default';
    }

    /**
     * Get runtime user identifier for cache namespacing.
     */
    protected function getRuntimeUserIdentifier(): ?string
    {
        if (function_exists('posix_geteuid')) {
            $uid = posix_geteuid();
            if (is_int($uid) && $uid >= 0) {
                return 'uid:' . $uid;
            }
        }

        $user = getenv('USER');
        if (is_string($user) && $user !== '') {
            return 'user:' . $user;
        }

        $username = getenv('USERNAME');
        if (is_string($username) && $username !== '') {
            return 'user:' . $username;
        }

        return null;
    }

    /**
     * Validate structure and TTL of in-memory well-known cache entry.
     *
     * @param mixed $entry
     */
    protected function isFreshInMemoryWellKnownCacheEntry($entry): bool
    {
        if (!is_array($entry)) {
            return false;
        }

        if (!isset($entry['config'], $entry['loaded_at'])) {
            return false;
        }

        if (!is_array($entry['config']) || !is_int($entry['loaded_at'])) {
            return false;
        }

        return (time() - $entry['loaded_at']) <= $this->wellKnownCacheTtl;
    }

    /**
     * Set custom cache directory
     *
     * @param string $dir
     */
    public function setCacheDir(string $dir): void
    {
        $this->cacheDir = $dir;
    }

    /**
     * Load configuration from cache file
     *
     * @param string $cacheFile
     * @return array|null
     */
    protected function loadWellKnownFromCache(string $cacheFile): ?array
    {
        if (!file_exists($cacheFile)) {
            return null;
        }

        // Check if cache expired
        $fileTime = filemtime($cacheFile);
        if ($fileTime === false || (time() - $fileTime) > $this->wellKnownCacheTtl) {
            @unlink($cacheFile);
            return null;
        }

        $content = @file_get_contents($cacheFile);
        if ($content === false) {
            return null;
        }

        $config = json_decode($content, true);
        if (!is_array($config)) {
            @unlink($cacheFile);
            return null;
        }

        return $config;
    }

    /**
     * Save configuration to cache file
     *
     * @param string $cacheFile
     * @param array $config
     */
    protected function saveWellKnownToCache(string $cacheFile, array $config): void
    {
        $cacheDir = dirname($cacheFile);

        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0700, true);
        }

        $content = json_encode($config, JSON_PRETTY_PRINT);
        @file_put_contents($cacheFile, $content, \LOCK_EX);
        @chmod($cacheFile, 0600);
    }

    /**
     * Clear in-memory well-known cache (mainly for tests)
     */
    public static function clearWellKnownCache(): void
    {
        self::$wellKnownConfigCache = [];
    }
}
