<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Parses raw key material (PEM, DER, or JWK JSON) into a single JWK.
 *
 * Centralizes the BOM-strip + format-sniff + parse + JWKSet-rejection logic
 * so ClientAssertionTrait and DPopTrait don't drift. Anything callers do
 * after parsing (kty validation, kid extraction, EC enforcement) stays in
 * the calling trait — this helper is parsing only.
 */
final class KeyMaterialParser
{
    /**
     * Parse raw key content into a single JWK.
     *
     * Format detection is by leading character after BOM/whitespace strip:
     * `{` is treated as JWK JSON, anything else is delegated to
     * JWKFactory::createFromKey() which handles PEM, DER, and encrypted PEM.
     *
     * @param string $content Raw key material
     * @param string $label Human-readable label used in error messages
     * @return JWK A single key (never a JWKSet)
     * @throws \RuntimeException when the content is empty, malformed, or a JWK set
     */
    public static function parseToJwk(string $content, string $label): JWK
    {
        $content = preg_replace('/^\xEF\xBB\xBF/', '', $content);
        $trimmed = trim($content);

        if ($trimmed === '') {
            throw new \RuntimeException("{$label}: content is empty");
        }

        if (str_starts_with($trimmed, '{')) {
            return self::parseJsonKey($trimmed, $label);
        }

        // Anything non-JSON: delegate to the library, which tries DER first
        // then falls back to PEM (including encrypted PEM with DEK-Info).
        try {
            return JWKFactory::createFromKey($content);
        } catch (\Throwable $e) {
            throw new \RuntimeException(
                "{$label}: unable to parse as PEM/DER key — {$e->getMessage()}",
                0,
                $e
            );
        }
    }

    private static function parseJsonKey(string $json, string $label): JWK
    {
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException("{$label}: not valid JSON");
        }

        // Detect a JWK set upfront. JWKFactory::createFromValues() would also
        // route this to JWKSet, but catching it here gives a clearer message
        // and avoids the JWK|JWKSet union-return-type dance at the call site.
        if (array_key_exists('keys', $decoded) && is_array($decoded['keys'])) {
            throw new \RuntimeException("{$label}: must be a single JWK, not a JWK set");
        }

        if (!isset($decoded['kty'])) {
            throw new \RuntimeException(
                "{$label}: Unsupported or missing key type (kty) in JWK"
            );
        }

        $jwk = JWKFactory::createFromValues($decoded);

        // createFromValues() can still produce a JWKSet for malformed inputs
        // that have a 'keys' array buried elsewhere. Defense in depth.
        if ($jwk instanceof JWKSet) {
            throw new \RuntimeException("{$label}: must be a single JWK, not a JWK set");
        }

        return $jwk;
    }
}
