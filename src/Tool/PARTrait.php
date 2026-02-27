<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Tool;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

/**
 * PAR (Pushed Authorization Requests) Trait
 *
 * Implements RFC 9126 - OAuth 2.0 Pushed Authorization Requests
 * Pushes authorization parameters to the authorization server before redirecting the user
 */
trait PARTrait
{
    /**
     * Push authorization request to PAR endpoint
     *
     * @param array $params Authorization parameters
     * @return string request_uri to use in authorization URL
     * @throws IdentityProviderException
     */
    protected function pushAuthorizationRequest(array $params): string
    {
        if ($this->parUrl === null) {
            throw new \RuntimeException('PAR endpoint not configured');
        }

        // Authenticate the PAR request (implementors can override this method)
        $params = $this->authenticatePARRequest($params);

        // Make PAR request
        try {
            $request = $this->getRequest('POST', $this->parUrl);

            // Set body with form data
            $body = http_build_query($params, '', '&', \PHP_QUERY_RFC1738);
            $request = $request
                ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withBody($this->getStreamFactory()->createStream($body));

            $response = $this->getHttpClient()->send($request);
            $statusCode = $response->getStatusCode();

            // RFC 9126 specifies 201 Created, but also accept 200 OK
            if ($statusCode !== 200 && $statusCode !== 201) {
                $data = json_decode((string)$response->getBody(), true);

                if (isset($data['error'], $data['error_description'])) {
                    throw new IdentityProviderException(
                        sprintf('PAR error: "%s" (%s)', $data['error'], $data['error_description']),
                        $statusCode,
                        $response
                    );
                }

                throw new IdentityProviderException(
                    sprintf('PAR request error: (HTTP/%s)', $statusCode),
                    $statusCode,
                    $response
                );
            }

            $data = json_decode((string)$response->getBody(), true);

            if (!isset($data['request_uri'])) {
                throw new IdentityProviderException(
                    'PAR response error: "request_uri" missing',
                    $statusCode,
                    $response
                );
            }

            return $data['request_uri'];

        } catch (IdentityProviderException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                'PAR request failed: ' . $e->getMessage(),
                0,
                null,
                $e
            );
        }
    }

    /**
     * Authenticate the PAR request. Override to customize authentication method.
     * Default: adds client_assertion if client assertion is configured.
     *
     * @param array $params
     * @return array Modified params with authentication added
     */
    protected function authenticatePARRequest(array $params): array
    {
        if (method_exists($this, 'hasClientAssertion') && $this->hasClientAssertion()) {
            // private_key_jwt authentication (RFC 7523 §3: audience is the endpoint being authenticated to)
            $assertion = $this->createClientAssertion($this->parUrl);
            $params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $params['client_assertion'] = $assertion;
        } elseif (isset($this->clientSecret) && $this->clientSecret !== null && $this->clientSecret !== '') {
            // client_secret_post authentication (RFC 9126 §2: same auth as token endpoint)
            $params['client_id'] = $this->clientId;
            $params['client_secret'] = $this->clientSecret;
        }
        return $params;
    }

    /**
     * Get stream factory for creating request body
     *
     * @return \Psr\Http\Message\StreamFactoryInterface
     */
    protected function getStreamFactory()
    {
        // Check if the request factory also implements StreamFactoryInterface
        if (method_exists($this, 'getRequestFactory')) {
            $requestFactory = $this->getRequestFactory();
            if ($requestFactory instanceof \Psr\Http\Message\StreamFactoryInterface) {
                return $requestFactory;
            }
        }

        // Guzzle is a transitive dependency via league/oauth2-client
        if (class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            return new \GuzzleHttp\Psr7\HttpFactory();
        }

        throw new \RuntimeException(
            'No PSR-17 StreamFactory available. Ensure a PSR-17 compatible HTTP factory is configured.'
        );
    }
}
