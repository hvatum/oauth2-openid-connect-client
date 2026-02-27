<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

/**
 * Base64 URL Encoding Trait
 *
 * Provides RFC 4648 base64url encoding/decoding utilities
 * used for JWT and JWK operations.
 */
trait Base64UrlTrait
{
    /**
     * Base64url encode data (RFC 4648)
     *
     * @param string $data
     * @return string
     */
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64url decode data (RFC 4648)
     *
     * @param string $data
     * @return string
     */
    protected function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
