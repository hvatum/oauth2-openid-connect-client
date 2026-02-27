<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Validator;

use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Validator\NonceChecker;
use Jose\Component\Checker\InvalidClaimException;

final class NonceCheckerTest extends TestCase
{
    public function testAcceptsMatchingNonce(): void
    {
        $checker = new NonceChecker('expected-nonce');
        // Should not throw
        $checker->checkClaim('expected-nonce');
        self::assertTrue(true); // Assert we got here
    }

    public function testRejectsMismatchingNonce(): void
    {
        $checker = new NonceChecker('expected-nonce');

        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim('wrong-nonce');
    }

    public function testSkipsValidationWhenNoNonceExpected(): void
    {
        $checker = new NonceChecker(null);
        // Should not throw
        $checker->checkClaim('any-value');
        self::assertTrue(true);
    }

    public function testSupportedClaimIsNonce(): void
    {
        $checker = new NonceChecker(null);
        self::assertSame('nonce', $checker->supportedClaim());
    }
}
