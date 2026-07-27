# Changelog

## 0.4.0 — Unreleased

### Changed

- Replaced `pbkdf2_elixir` with OTP `:crypto.pbkdf2_hmac/5`. Existing
  canonical `$pbkdf2-sha256$` hashes with non-empty salts, 32-byte digests,
  and costs within the configured verification budget remain verifiable.
- Removed the `Digestif.PBKDF2` `:backend` option. PBKDF2 now has one
  implementation and requires no optional dependency.
- Made PBKDF2 stored encodings canonical: salt and digest segments reject
  padding, non-adapted alphabet characters, and non-zero trailing Base64 bits;
  round counts reject leading zeroes.
- Missing users and malformed PBKDF2 hashes now derive dummy work from the
  supplied password through OTP `:crypto`.

Earlier releases predate this changelog. Their source history and tags remain
the authoritative record.
