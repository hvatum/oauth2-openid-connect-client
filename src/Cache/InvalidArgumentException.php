<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Cache;

class InvalidArgumentException extends \InvalidArgumentException implements \Psr\SimpleCache\InvalidArgumentException
{
}
