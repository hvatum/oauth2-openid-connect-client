<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Validator;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

/**
 * Validates the nonce claim against the expected value.
 */
class NonceChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'nonce';

    /**
     * @var string|null
     */
    private $expectedNonce;

    /**
     * @param string|null $expectedNonce The nonce that was sent in the auth request
     */
    public function __construct(?string $expectedNonce)
    {
        $this->expectedNonce = $expectedNonce;
    }

    /**
     * @param mixed $value
     * @throws InvalidClaimException
     */
    public function checkClaim($value): void
    {
        if ($this->expectedNonce === null) {
            // Nothing to validate when no nonce was sent.
            return;
        }

        if (!is_string($value) || !hash_equals($this->expectedNonce, $value)) {
            throw new InvalidClaimException('Invalid nonce', self::CLAIM_NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
