<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test;

/**
 * Test double proving isAcceptedAuthorizedParty() is overridable for
 * policies a static allow-list cannot express.
 */
final class AzpAllowListTestProvider extends TestProvider
{
    protected function isAcceptedAuthorizedParty($azp): bool
    {
        return parent::isAcceptedAuthorizedParty($azp)
            || $azp === 'hook-accepted-app';
    }
}
