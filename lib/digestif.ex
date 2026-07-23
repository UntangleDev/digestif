defmodule Digestif do
  @moduledoc """
  Password hashing with secure defaults and a small public API.

  The common case is deliberately three functions:

      hash = Digestif.hash("correct horse battery staple")
      true = Digestif.verify?("correct horse battery staple", hash)
      false = Digestif.needs_rehash?(hash)

  Argon2id with 32 MiB of memory, two iterations, and one lane is the
  default. Select a different primary hasher or declare legacy hashers in
  application configuration:

      config :digestif,
        hasher: {Digestif.Argon2id, []},
        legacy_hashers: [{Digestif.PBKDF2, []}]

  PBKDF2 and bcrypt require their corresponding optional backend
  dependencies before their adapters can be configured.

  `verify?/2` dispatches only to the configured primary hasher and explicit
  legacy hashers. A successful legacy verification is therefore visible to
  `needs_rehash?/1`, allowing the application to replace the stored hash.

  Authentication libraries and applications with several independent
  hashing policies can use the explicit `{module, options}` API in
  `Digestif.Hasher` rather than global application configuration.
  """

  alias Digestif.{Argon2id, Hasher}

  @default_hasher {Argon2id, []}

  @doc """
  Hashes a value with the configured primary hasher.

  Work factors come from application configuration so hashing and
  verification share one resource budget. Invalid configuration and backend
  failures raise rather than returning an unusable hash.
  """
  @spec hash(String.t()) :: String.t()
  def hash(value) when is_binary(value) do
    {module, _configured_options} = hasher = primary_hasher()
    Hasher.validate!(hasher)

    case module.hash(value, elem(hasher, 1)) do
      {:ok, encoded_hash} when is_binary(encoded_hash) ->
        encoded_hash

      result ->
        raise "hasher #{inspect(module)} returned invalid result: #{inspect(result)}"
    end
  end

  @doc """
  Returns whether a value matches a stored hash.

  Only the configured primary and legacy hashers are considered. Foreign,
  unknown, malformed, and over-budget hashes fail closed as `false`.
  """
  @spec verify?(String.t(), String.t()) :: boolean()
  def verify?(value, encoded_hash) when is_binary(value) and is_binary(encoded_hash) do
    {primary, legacy_hashers} = configured_hashers()

    match?(
      {:ok, _hasher},
      Hasher.verify_with_hashers(value, encoded_hash, primary, legacy_hashers)
    )
  end

  @doc """
  Returns whether a stored hash should be replaced by the primary hasher.

  Call this after successful verification. Hashes belonging to an explicit
  legacy hasher always return `true`; primary hashes defer to that adapter's
  work-factor policy.
  """
  @spec needs_rehash?(String.t()) :: boolean()
  def needs_rehash?(encoded_hash) when is_binary(encoded_hash) do
    {primary, legacy_hashers} = configured_hashers()
    selected = Hasher.selected_hasher(encoded_hash, primary, legacy_hashers)
    Hasher.needs_rehash?(encoded_hash, selected, primary)
  end

  defp configured_hashers do
    primary = primary_hasher()
    legacy_hashers = Application.get_env(:digestif, :legacy_hashers, [])
    Hasher.validate_set!(primary, legacy_hashers)
    {primary, legacy_hashers}
  end

  defp primary_hasher do
    Application.get_env(:digestif, :hasher, @default_hasher)
  end
end
