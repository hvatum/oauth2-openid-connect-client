# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is 0, breaking changes are released in minor versions.

Releases before 0.4.0 predate this file; see the git history for those.

## [Unreleased]

### Changed

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
