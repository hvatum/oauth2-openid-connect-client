# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is 0, breaking changes are released in minor versions.

Releases before 0.4.0 predate this file; see the git history for those.

## [Unreleased]

### Added

- Signed JWT userinfo responses (OIDC Core §5.3.2, content-type
  `application/jwt`) are now verified against the provider JWKS and fully
  validated (`iss`/`aud`/`sub` required, time claims when present, `azp`
  screening) before their claims are merged into the resource owner. JWT
  envelope and ID-token transport claims are stripped from the merge, and
  encrypted (JWE) responses are rejected. Accepted algorithms follow
  `userinfo_signing_alg_values_supported`, falling back to the id_token
  algorithms; override `getUserinfoSigningAlgValuesSupported()` for
  servers that sign with unadvertised algorithms. Plain JSON userinfo
  behavior is unchanged.

### Changed

- **BREAKING:** An `azp` claim not naming this client is now rejected on
  all validated JWTs; previously `azp` was only checked on multi-audience
  ID tokens. Deployments where a foreign `azp` is legitimate (e.g.
  Google-style hybrid app flows) can allow additional presenters via the
  `allowedAuthorizedParties` option or the `isAcceptedAuthorizedParty()`
  hook — single-audience JWTs only; multi-audience ID tokens always
  require `azp` to name this client. Some validation error message texts
  changed.

- **BREAKING:** The `client_assertion` `aud` claim now defaults to the
  issuer identifier instead of the token endpoint URL, for token and PAR
  requests, per
  [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/)
  (which forbids the token endpoint URL as audience). For servers still
  expecting the legacy value, override `getClientAssertionAudience()` to
  return `$this->tokenUrl`; overrides that already return the issuer can
  be removed.

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
- Userinfo claim stripping is now uniform across content types: JWT
  envelope claims and protocol artifacts (`nonce`, `azp`, `at_hash`,
  `c_hash`) never reach the resource owner, while auth-context claims
  (`auth_time`, `acr`, `amr`) provided by the userinfo endpoint are now
  kept — previously signed responses dropped them.
- The forced JWKS refresh after a signature failure with an already-known
  `kid` is rate-limited (at most one per 60s); an unknown `kid` — the key
  rotation signal — always refreshes. Parsed key sets, claim checkers and
  verifiers are reused across validations in the same request.
