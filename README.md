# Digestif

[![CI](https://github.com/UntangleDev/digestif/actions/workflows/ci.yml/badge.svg)](https://github.com/UntangleDev/digestif/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/digestif.svg)](https://hex.pm/packages/digestif)
[![HexDocs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/digestif)

Digestif is a password-hashing library with a deliberately small application
API and strict resource bounds around stored hashes.

```elixir
hash = Digestif.hash("correct horse battery staple")

Digestif.verify?("correct horse battery staple", hash)
#=> true

Digestif.needs_rehash?(hash)
#=> false
```

The default is Argon2id with 32 MiB of memory, two iterations, and one lane:

```elixir
def deps do
  [
    {:digestif, "~> 0.2"}
  ]
end
```

## Configuration

Select one primary hasher in application configuration:

```elixir
config :digestif,
  hasher: {Digestif.Argon2id, []}
```

Set work factors centrally so hashing and verification always share one
validated resource budget:

```elixir
config :digestif,
  hasher: {Digestif.Argon2id, m_cost: 16}
```

Existing hashes can migrate without a flag that accepts arbitrary algorithms.
Declare the exact legacy hashers that may verify:

```elixir
config :digestif,
  hasher: {Digestif.Argon2id, []},
  legacy_hashers: [
    {Digestif.PBKDF2, iterations: 600_000, max_iterations: 1_000_000},
    {Digestif.Bcrypt, log_rounds: 12, max_cost: 16}
  ]
```

After a successful `verify?/2`, `needs_rehash?/1` returns `true` for a legacy
hash. Create and persist a new hash with the primary hasher.

## Algorithms

Argon2id is included by default. `argon2_elixir` compiles a native extension,
so deployments need a C toolchain when precompiled artifacts are unavailable.
PBKDF2 and bcrypt support are optional; add only the backends the application
uses:

```elixir
{:pbkdf2_elixir, "~> 2.3"}
{:bcrypt_elixir, "~> 3.0"}
```

Configure `{Digestif.PBKDF2, options}` when PBKDF2 is specifically required.
Bcrypt is primarily for migration because it distinguishes only the first 72
password bytes.

Every bundled adapter:

- validates options before use;
- bounds encoded-hash length and attacker-controlled verification cost;
- performs configured dummy work for malformed or over-budget hashes;
- emits self-describing hashes; and
- reports when its work factor should be upgraded.

Verification budgets default to the cost used for new hashes. Imported hashes
with higher legitimate costs require an explicit larger budget. See each
adapter's module documentation for the allowed ranges.

## Libraries and multiple policies

The top-level facade uses application configuration for the common single
policy case. Authentication libraries and multi-tenant applications should
pass explicit `{module, options}` tuples through `Digestif.Hasher`:

```elixir
primary = {Digestif.Argon2id, []}
legacy = [{Digestif.PBKDF2, []}]

case Digestif.Hasher.verify_with_hashers(password, stored_hash, primary, legacy) do
  {:ok, selected} ->
    Digestif.Hasher.needs_rehash?(stored_hash, selected, primary)

  :error ->
    false
end
```

## License

MIT
