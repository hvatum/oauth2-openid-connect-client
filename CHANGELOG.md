# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is 0, breaking changes are released in minor versions.

Releases before 0.4.0 predate this file; see the git history for those.

## [Unreleased]

### Added

- Signed JWT userinfo responses (OIDC Core §5.3.2) are now verified and
  decoded natively. When the userinfo endpoint responds with content-type
  `application/jwt`, the compact JWS is verified against the provider JWKS
  (with one forced-refresh retry to absorb key rotation), `iss`, `aud` and
  `sub` are required and checked, `exp`/`nbf`/`iat` are checked when
  present, and an unaccepted `azp` claim (by default anything other than
  this client's ID; see `allowedAuthorizedParties`) is rejected.
  Multiple audiences without `azp` are accepted — OIDC Core §5.3.2 only
  asks that `aud` be or include the client ID, unlike ID token validation
  (§3.1.3.7) which keeps requiring `azp` for multiple audiences. The
  accepted algorithms come from
  the discovery document's `userinfo_signing_alg_values_supported`, falling
  back to the id_token algorithms when absent or empty; both are intersected
  with the algorithms this library can verify. The JWT envelope claims
  (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`) and the ID-token transport
  claims (`nonce`, `auth_time`, `azp`, `acr`, `amr`, `at_hash`, `c_hash`)
  are stripped before the resource-owner merge, so the envelope cannot
  clobber ID-token claims and the transport claims filtered from the ID
  token cannot re-enter through userinfo. Encrypted (JWE) userinfo
  responses are rejected with a clear error. Plain JSON userinfo behavior
  is unchanged. Subclasses can override
  `getUserinfoSigningAlgValuesSupported()` for servers that sign userinfo
  with algorithms they do not advertise.

### Changed

- **BREAKING:** ID tokens carrying an `azp` claim whose value is not
  accepted — anything other than this client's ID by default, including
  type-mismatched values such as numeric client IDs — are now rejected
  even when the token has a single audience. Previously `azp` was only
  checked for multi-audience tokens. OIDC Core §3.1.3.7 leaves `azp`
  validation to the extension that produced the claim, so deployments
  where a different `azp` is legitimate (e.g. Google-style hybrid app
  flows) can pass the `allowedAuthorizedParties` constructor option or
  override the `isAcceptedAuthorizedParty()` hook. An allow-listed foreign
  `azp` is only accepted on single-audience JWTs, and multi-audience ID
  tokens still require `azp` to name this client itself. Several validation
  error message texts also changed (`azp` failures, non-string `sub`
  values, and the "UserInfo" label is now "UserInfo response").

- **BREAKING:** The `client_assertion` `aud` claim now defaults to the issuer
  identifier instead of the token endpoint URL. This applies to token requests
  and to PAR requests (RFC 9126 §2 uses the same client authentication).

  [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) §4
  (updating RFC 7523 §3) requires the issuer identifier as the client
  authentication assertion's sole audience value and states the token endpoint
  URL "MUST NOT be used as an audience value"; §5 applies the same rule to PAR
  (updating RFC 9126 §2). The draft — not yet published as an RFC, but in the
  RFC Editor queue — tightens the original RFC 7523 §3 rule (which permitted
  the token endpoint) and OpenID Connect Core §9 (which recommended it).
  Authorization servers that have adopted the newer rule reject token-endpoint
  audiences with `invalid_client`.

  Servers still expecting the legacy value are supported by overriding the
  existing hook:

  ```php
  protected function getClientAssertionAudience(): string
  {
      return $this->tokenUrl;
  }
  ```

  Providers that already override `getClientAssertionAudience()` to return the
  issuer are unaffected, and the override can now be removed.

### Fixed

- Userinfo failures now consistently throw `IdentityProviderException`
  (previously `UnexpectedValueException` or raw transport exceptions could
  leak). Error details are surfaced from JSON and form-encoded bodies and
  from the RFC 6750 `WWW-Authenticate` header.
- A 2xx userinfo body containing an `error` claim is no longer treated as
  an error response.
- **BREAKING** for subclasses: userinfo errors dispatch through the new
  `throwOnResponseError()` hook; `checkResponse()` overrides no longer see
  userinfo responses.
- Non-string `error`/`error_description` values no longer cause a
  `TypeError`.
- Userinfo responses no longer update the stored DPoP nonce (RFC 9449 §9).
- A userinfo body containing an `id_token` member can no longer replace
  the validated ID token from the token response.
