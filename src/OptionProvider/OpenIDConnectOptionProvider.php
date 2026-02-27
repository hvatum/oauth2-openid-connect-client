<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\OptionProvider;

use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;

/**
 * OptionProvider that delegates body building to a callable
 *
 * This allows the OpenID Connect provider to customize the access token request body
 * (adding client assertion, DPoP thumbprint, etc.) while still using the
 * parent's getAccessTokenRequest() implementation.
 */
class OpenIDConnectOptionProvider extends PostAuthOptionProvider
{
    /** @var \Closure */
    private $bodyBuilder;

    /**
     * @param callable $bodyBuilder Function that builds the request body from params
     */
    public function __construct(callable $bodyBuilder)
    {
        $this->bodyBuilder = \Closure::fromCallable($bodyBuilder);
    }

    /**
     * @inheritdoc
     */
    protected function getAccessTokenBody(array $params): string
    {
        return ($this->bodyBuilder)($params);
    }
}
