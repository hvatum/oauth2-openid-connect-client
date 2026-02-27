<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Provider;

use PHPUnit\Framework\TestCase;
use Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectResourceOwner;

final class ResourceOwnerTest extends TestCase
{
    public function testStandardOidcClaims(): void
    {
        $owner = new OpenIDConnectResourceOwner([
            'sub' => 'user-123',
            'name' => 'John Doe',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'middle_name' => 'M',
            'email' => 'john@example.com',
            'email_verified' => true,
            'preferred_username' => 'johnd',
            'locale' => 'en-US',
        ]);

        self::assertSame('user-123', $owner->getId());
        self::assertSame('John Doe', $owner->getName());
        self::assertSame('John', $owner->getGivenName());
        self::assertSame('Doe', $owner->getFamilyName());
        self::assertSame('M', $owner->getMiddleName());
        self::assertSame('john@example.com', $owner->getEmail());
        self::assertTrue($owner->getEmailVerified());
        self::assertSame('johnd', $owner->getPreferredUsername());
        self::assertSame('en-US', $owner->getLocale());
    }

    public function testNullForMissingClaims(): void
    {
        $owner = new OpenIDConnectResourceOwner([]);

        self::assertNull($owner->getId());
        self::assertNull($owner->getName());
        self::assertNull($owner->getEmail());
        self::assertNull($owner->getEmailVerified());
    }

    public function testToArrayReturnsAll(): void
    {
        $data = ['sub' => 'user-1', 'custom_claim' => 'value'];
        $owner = new OpenIDConnectResourceOwner($data);

        self::assertSame($data, $owner->toArray());
    }
}
