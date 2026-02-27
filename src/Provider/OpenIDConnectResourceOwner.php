<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * OpenID Connect Resource Owner (User)
 *
 * Represents a user authenticated via an OpenID Connect provider.
 * Provides getters for standard OIDC claims.
 */
class OpenIDConnectResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response data
     */
    protected array $response;

    /**
     * Create resource owner from response
     *
     * @param array $response
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * Get resource owner ID (subject claim)
     *
     * @return string|null
     */
    public function getId(): ?string
    {
        return $this->response['sub'] ?? null;
    }

    /**
     * Get user's full name
     * Requires scope: profile
     *
     * @return string|null
     */
    public function getName(): ?string
    {
        return $this->response['name'] ?? null;
    }

    /**
     * Get user's given name
     * Requires scope: profile
     *
     * @return string|null
     */
    public function getGivenName(): ?string
    {
        return $this->response['given_name'] ?? null;
    }

    /**
     * Get user's family name
     * Requires scope: profile
     *
     * @return string|null
     */
    public function getFamilyName(): ?string
    {
        return $this->response['family_name'] ?? null;
    }

    /**
     * Get user's middle name
     * Requires scope: profile
     *
     * @return string|null
     */
    public function getMiddleName(): ?string
    {
        return $this->response['middle_name'] ?? null;
    }

    /**
     * Get user's email address
     * Requires scope: email
     *
     * @return string|null
     */
    public function getEmail(): ?string
    {
        return $this->response['email'] ?? null;
    }

    /**
     * Get whether user's email is verified
     * Requires scope: email
     *
     * @return bool|null
     */
    public function getEmailVerified(): ?bool
    {
        $verified = $this->response['email_verified'] ?? null;
        return $verified !== null ? (bool)$verified : null;
    }

    /**
     * Get user's preferred username
     * Requires scope: profile
     *
     * @return string|null
     */
    public function getPreferredUsername(): ?string
    {
        return $this->response['preferred_username'] ?? null;
    }

    /**
     * Get user's locale
     * Requires scope: profile
     *
     * @return string|null
     */
    public function getLocale(): ?string
    {
        return $this->response['locale'] ?? null;
    }

    /**
     * Get all resource owner data
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
