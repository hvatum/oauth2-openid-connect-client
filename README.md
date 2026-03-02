# OpenID Connect Client for The PHP League OAuth2 Client

A generic OpenID Connect provider for [The PHP League's OAuth2 Client](https://github.com/thephpleague/oauth2-client), with built-in support for modern OAuth 2.0 security features:

- **OpenID Connect Discovery** — Automatic endpoint configuration via `.well-known/openid-configuration`
- **PAR** (Pushed Authorization Requests) — [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)
- **PKCE** (Proof Key for Code Exchange) — [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) with S256
- **DPoP** (Demonstrating Proof of Possession) — [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- **Private Key JWT** client authentication — [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)
- **ID Token validation** — Signature verification, claim validation, nonce checking
- **RFC 9207** — Authorization Server Issuer Identification (mix-up attack protection)

## Disclaimer

OAuth2 and its related standards are complex topics to understand and to get right. This library strives to be correct
but mistakes can be made. There is NO WARRANTY, use at your own risk, and please leave a bug report or a pull request if you find something that seems off.

## Requirements

- PHP 8.2 or later
- `ext-json`
- `ext-openssl`

## Installation

```bash
composer require hvatum/oauth2-openid-connect-client
```

## Basic Usage

The simplest setup — just point to the issuer:

```php
use Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider;

$provider = new OpenIDConnectProvider([
    
    'clientId'     => 'your-client-id',
    'clientSecret' => 'your-client-secret',
    'redirectUri'  => 'https://your-app.example/callback',
    'issuer'       => 'https://your-idp.example',
]);
```

All endpoints (authorization, token, userinfo, JWKS, PAR) are automatically discovered
from `{issuer}/.well-known/openid-configuration`.

### Authorization Code Flow

```php
// Step 1: Redirect user to authorization endpoint
if (!isset($_GET['code'])) {
    $authUrl = $provider->getAuthorizationUrl([
        'scope' => ['openid', 'profile', 'email'],
    ]);

    // Store state and nonce in session for validation
    $_SESSION['oauth2_state'] = $provider->getState();
    $_SESSION['oauth2_nonce'] = $provider->getNonce();
    $_SESSION['oauth2_pkce']  = $provider->getPkceCode();

    header('Location: ' . $authUrl);
    exit;
}

// Step 2: Handle callback
if ($_GET['state'] !== $_SESSION['oauth2_state']) {
    throw new \RuntimeException('Invalid state');
}

// Restore state from session
$provider->setNonce($_SESSION['oauth2_nonce']);
$provider->setCallbackIssuer($_GET['iss'] ?? null); // RFC 9207

// Exchange code for tokens
$token = $provider->getAccessToken('authorization_code', [
    'code' => $_GET['code'],
    'code_verifier' => $_SESSION['oauth2_pkce'],
]);

// Get user info (ID token claims merged with userinfo endpoint)
$user = $provider->getResourceOwner($token);
echo $user->getName();
echo $user->getEmail();
```

## Advanced Usage

### Private Key JWT Authentication (RFC 7523)

Use `private_key_jwt` instead of `client_secret` for client authentication:

```php
$provider = new OpenIDConnectProvider([
    'clientId'       => 'your-client-id',
    'redirectUri'    => 'https://your-app.example/callback',
    'issuer'         => 'https://your-idp.example',
    'privateKeyPath' => '/path/to/private-key.pem',  // or .jwk
    'keyId'          => 'your-key-id',                // optional if in JWK file
]);
```

Supports EC (ES256) and RSA (RS256, PS256) keys in both PEM and JWK formats.

### DPoP Token Binding (RFC 9449)

Bind access tokens to a cryptographic key pair to prevent token theft:

```php
$provider = new OpenIDConnectProvider([
    'clientId'            => 'your-client-id',
    'redirectUri'         => 'https://your-app.example/callback',
    'issuer'              => 'https://your-idp.example',
    'privateKeyPath'      => '/path/to/client-key.pem',
    'dpopPrivateKeyPath'  => '/path/to/dpop-private.pem',
    'dpopPublicKeyPath'   => '/path/to/dpop-public.pem',
]);

// DPoP proofs are automatically included in token requests.
// For API calls with DPoP-bound tokens:
$response = $provider->makeDPopRequest('GET', 'https://api.example/resource', $token->getToken());
```

### ID Token Validation

ID tokens are automatically validated when fetching resource owner details. You can also validate manually:

```php
$claims = $provider->validateIdToken($idTokenJwt, $expectedNonce);
```

Validates: signature (ES256/RS256/PS256), issuer, audience, expiration, nonce, and more.

### Caching

Well-known configuration is cached to file (24h TTL) and in memory. Customize the cache directory:

```php
$provider = new OpenIDConnectProvider([
    // ...
    'cacheDir' => '/path/to/cache',
]);
```

### PSR-3 Logging

Pass a PSR-3 logger for debug output:

```php
$provider = new OpenIDConnectProvider([
    // ...
], [
    'logger' => $yourPsrLogger,
]);
```

## Key Generation

### EC Key Pair (for DPoP or client assertion)

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

### RSA Key Pair (for client assertion)

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

## Extending for Specific Providers

This package is designed to be extended for provider-specific requirements:

```php
use Hvatum\OpenIDConnect\Client\Provider\OpenIDConnectProvider;

class MyProvider extends OpenIDConnectProvider
{
    public const CLIENT_ASSERTION_TTL = 10; // Override default TTL

    protected function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'my-custom-scope'];
    }

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new MyResourceOwner($response);
    }
}
```

## Supported RFCs

| RFC | Feature | Status |
|-----|---------|--------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 Authorization Framework | Supported (via League) |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key (JWK) | Supported |
| [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | JWT Bearer Client Authentication | Supported |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE (S256) | Supported |
| [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) | JWK Thumbprint | Supported |
| [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) | Pushed Authorization Requests (PAR) | Supported |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | Authorization Server Issuer Identification | Supported |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP (Demonstrating Proof of Possession) | Supported |

## License

MIT License. See [LICENSE](LICENSE) for details.
