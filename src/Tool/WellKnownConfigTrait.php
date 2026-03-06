<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\SimpleCache\CacheInterface;

/**
 * Well-Known Configuration Discovery Trait
 *
 * Implements automatic endpoint discovery from OpenID Connect
 * well-known configuration endpoint with PSR-16 caching
 */
trait WellKnownConfigTrait
{
    /**
     * Cache TTL in seconds (24 hours)
     */
    protected int $wellKnownCacheTtl = 86400;

    /**
     * PSR-16 cache instance
     */
    protected ?CacheInterface $cache = null;

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

        // Check PSR-16 cache
        $cacheKey = 'wellknown_' . md5($wellKnownUrl);
        if ($this->cache !== null) {
            $cachedConfig = $this->cache->get($cacheKey);
            if (is_array($cachedConfig)) {
                $this->validateWellKnownConfig($cachedConfig, $expectedIssuer);
                $this->setEndpointsFromConfig($cachedConfig);
                return;
            }
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
            $this->cache?->set($cacheKey, $config, $this->wellKnownCacheTtl);

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
        $this->endSessionUrl = $config['end_session_endpoint'] ?? null;
        $this->issuerResponseParameterSupported = !empty($config['authorization_response_iss_parameter_supported']);

        // Algorithm and method metadata from discovery
        $this->idTokenSigningAlgValuesSupported = $this->getStringArrayMetadataOrDefault(
            $config,
            'id_token_signing_alg_values_supported',
            ['RS256']
        );
        $this->tokenEndpointAuthSigningAlgValuesSupported = $this->getNullableStringArrayMetadata(
            $config,
            'token_endpoint_auth_signing_alg_values_supported'
        );
        $this->dpopSigningAlgValuesSupported = $this->getNullableStringArrayMetadata(
            $config,
            'dpop_signing_alg_values_supported'
        );
        $this->tokenEndpointAuthMethodsSupported = $this->getNullableStringArrayMetadata(
            $config,
            'token_endpoint_auth_methods_supported'
        );
        $this->codeChallengeMethodsSupported = $this->getNullableStringArrayMetadata(
            $config,
            'code_challenge_methods_supported'
        );
        $this->requirePushedAuthorizationRequests = !empty($config['require_pushed_authorization_requests']);
    }

    /**
     * @param array<string,mixed> $config
     * @param string $field
     * @param array<string> $default
     * @return array<string>
     * @throws IdentityProviderException
     */
    protected function getStringArrayMetadataOrDefault(array $config, string $field, array $default): array
    {
        if (!array_key_exists($field, $config) || $config[$field] === null) {
            return $default;
        }

        return $this->assertStringArrayMetadata($field, $config[$field]);
    }

    /**
     * @param array<string,mixed> $config
     * @param string $field
     * @return array<string>|null
     * @throws IdentityProviderException
     */
    protected function getNullableStringArrayMetadata(array $config, string $field): ?array
    {
        if (!array_key_exists($field, $config) || $config[$field] === null) {
            return null;
        }

        return $this->assertStringArrayMetadata($field, $config[$field]);
    }

    /**
     * @param string $field
     * @param mixed $value
     * @return array<string>
     * @throws IdentityProviderException
     */
    protected function assertStringArrayMetadata(string $field, $value): array
    {
        if (!is_array($value)) {
            throw new IdentityProviderException(
                sprintf('Invalid well-known configuration: %s must be an array of strings', $field),
                0,
                null
            );
        }

        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new IdentityProviderException(
                    sprintf('Invalid well-known configuration: %s must be an array of strings', $field),
                    0,
                    null
                );
            }
        }

        return $value;
    }
}
