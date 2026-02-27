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
     * @throws IdentityProviderException
     * @throws \InvalidArgumentException
     */
    protected function loadWellKnownConfiguration(string $wellKnownUrl): void
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
            $this->setEndpointsFromConfig(self::$wellKnownConfigCache[$wellKnownUrl]);
            return;
        }

        // Check file cache
        $cacheFile = $this->getWellKnownCacheFile($wellKnownUrl);
        $cachedConfig = $this->loadWellKnownFromCache($cacheFile);

        if ($cachedConfig !== null) {
            self::$wellKnownConfigCache[$wellKnownUrl] = $cachedConfig;
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

            // Validate required fields
            $requiredFields = ['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'];
            foreach ($requiredFields as $field) {
                if (!isset($config[$field])) {
                    throw new IdentityProviderException(
                        "Invalid well-known configuration: missing {$field}",
                        0,
                        $response
                    );
                }
            }

            // Cache the configuration
            self::$wellKnownConfigCache[$wellKnownUrl] = $config;
            $this->saveWellKnownToCache($cacheFile, $config);

            // Set endpoints
            $this->setEndpointsFromConfig($config);

        } catch (IdentityProviderException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                "Failed to fetch well-known configuration: " . $e->getMessage(),
                0,
                null,
                $e
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
        $this->userInfoUrl = $config['userinfo_endpoint'];
        $this->issuerUrl = $config['issuer'];
        $this->jwksUrl = $config['jwks_uri'] ?? null;
        $this->parUrl = $config['pushed_authorization_request_endpoint'] ?? null;
        $this->revocationUrl = $config['revocation_endpoint'] ?? null;
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
        $user = function_exists('get_current_user') ? get_current_user() : null;
        return $user !== false && $user !== null ? md5((string)$user) : 'default';
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
