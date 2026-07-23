defmodule Digestif.Bcrypt do
  @moduledoc """
  Optional bcrypt password hashing backed by `bcrypt_elixir`, for migrating
  existing bcrypt user databases.

  Add `{:bcrypt_elixir, "~> 3.0"}` to the host application's dependencies
  before configuring this adapter. Bcrypt is an interoperability feature,
  not a recommendation: list this adapter under `:legacy_hashers`
  so existing `$2a$` and `$2b$` hashes — and PHP crypt_blowfish `$2y$`
  hashes, which verify by normalizing the prefix for the backend only —
  keep working and upgrade to the primary algorithm on the next successful
  login. PBKDF2 and Argon2id remain the documented primary choices.

  `:log_rounds` (default `12`, floor `10`) is the cost used for new hashes
  and dummy work. `:max_cost` (default `16`, ceiling `31`) bounds the cost
  accepted from stored hashes before the backend is invoked, so a stored
  hash cannot request effectively unbounded work; raise it only if a legacy
  database legitimately holds stronger hashes. `:log_rounds` must not
  exceed `:max_cost` — such a configuration would mint hashes its own
  verifier rejects.

  ## Trust boundary

  Stored hashes are application-controlled database values, not untrusted
  network input. This adapter is a minimal resource preflight, defence in
  depth for corrupted, imported, or unexpectedly modified values: every
  bcrypt-family encoding is exactly 60 bytes, so the preflight checks that
  fixed length, reads the prefix and two-digit cost it needs for dispatch,
  `$2y$` normalization, and the `:max_cost` decision, and hands everything
  else to `bcrypt_elixir`, which owns complete format parsing and
  cryptographic validation. Values the preflight rejects fail closed after
  the configured dummy work; malformed values that fit the length and cost
  bounds are the backend's to reject.

  Bcrypt distinguishes only the first 72 bytes of a password, and the
  adapter declares that limit through `password_byte_limit/0`. A host that
  configures it as the primary hasher must therefore cap accepted passwords
  at 72 bytes. No such policy restriction is needed when bcrypt only verifies
  legacy hashes that already exist.
  """

  @behaviour Digestif.Hasher

  @algorithm "2b"
  @algorithm_aliases ["2a", "2y"]
  @backend Bcrypt

  # Every bcrypt-family encoding is exactly this long: prefix, two-digit
  # cost, and the 53-character salt-plus-digest body the backend validates.
  @encoded_length 60
  # Just enough fixed structure to read the fields Digestif needs: the
  # family prefix for dispatch and $2y$ normalization, and the two-digit
  # cost for the :max_cost decision.
  @hash_prefix ~r"\A\$(2[aby])\$([0-9]{2})\$"

  @minimum_cost 4
  @maximum_cost 31
  @password_byte_limit 72

  @default_options [backend: @backend, log_rounds: 12, max_cost: 16]

  @impl true
  def algorithm, do: @algorithm

  @impl true
  def algorithm_aliases, do: @algorithm_aliases

  @doc "Returns the number of password bytes bcrypt distinguishes."
  @impl true
  @spec password_byte_limit() :: pos_integer()
  def password_byte_limit, do: @password_byte_limit

  @impl true
  def hash(password, options) when is_binary(password) and is_list(options) do
    normalized = normalize_options!(options)
    backend = backend!(normalized.backend)

    encoded = apply(backend, :hash_pwd_salt, [password, [log_rounds: normalized.log_rounds]])
    {:ok, ensure_bcrypt!(encoded)}
  end

  @impl true
  def verify(password, encoded_hash, options)
      when is_binary(password) and is_binary(encoded_hash) and is_list(options) do
    normalized = normalize_options!(options)
    backend = backend!(normalized.backend)

    case parse_hash(encoded_hash) do
      {:ok, %{cost: cost} = parsed} when cost <= normalized.max_cost ->
        verify_parsed(backend, password, parsed.backend_hash, normalized)

      _malformed_or_out_of_bounds ->
        dummy_verify(backend, normalized)
    end
  end

  @impl true
  def no_user_verify(_password, options) when is_list(options) do
    normalized = normalize_options!(options)
    dummy_verify(backend!(normalized.backend), normalized)
  end

  @doc "Returns whether a stored bcrypt hash differs from the configured prefix and cost."
  @impl true
  def needs_rehash?(encoded_hash, options \\ []) when is_binary(encoded_hash) do
    normalized = normalize_options!(options)

    case parse_hash(encoded_hash) do
      {:ok, parsed} -> parsed.prefix != @algorithm or parsed.cost != normalized.log_rounds
      :error -> true
    end
  end

  @doc false
  @impl true
  @spec validate_options!(keyword()) :: :ok
  def validate_options!(options) when is_list(options) do
    normalized = normalize_options!(options)
    backend!(normalized.backend)
    :ok
  end

  defp verify_parsed(backend, password, backend_hash, normalized) do
    apply(backend, :verify_pass, [password, backend_hash])
  rescue
    ArgumentError -> dummy_verify(backend, normalized)
  end

  defp dummy_verify(backend, normalized) do
    apply(backend, :no_user_verify, [[log_rounds: normalized.log_rounds]])
  end

  defp backend!(backend) when is_atom(backend) do
    if Code.ensure_loaded?(backend) and
         function_exported?(backend, :hash_pwd_salt, 2) and
         function_exported?(backend, :verify_pass, 2) and
         function_exported?(backend, :no_user_verify, 1) do
      backend
    else
      raise ArgumentError,
            "Digestif.Bcrypt requires the optional :bcrypt_elixir " <>
              "dependency; add {:bcrypt_elixir, \"~> 3.0\"} to your deps"
    end
  end

  defp backend!(_backend), do: raise(ArgumentError, ":backend must be a module")

  defp normalize_options!(options) do
    options = Keyword.validate!(options, @default_options)
    backend = Keyword.fetch!(options, :backend)
    log_rounds = integer_option!(options, :log_rounds, 10, @maximum_cost)
    max_cost = integer_option!(options, :max_cost, @minimum_cost, @maximum_cost)

    if log_rounds > max_cost do
      raise ArgumentError,
            "bcrypt :log_rounds must not exceed :max_cost; the configuration would " <>
              "mint hashes its own verification bound rejects"
    end

    %{backend: backend, log_rounds: log_rounds, max_cost: max_cost}
  end

  defp integer_option!(options, name, minimum, maximum) do
    value = Keyword.fetch!(options, name)

    if is_integer(value) and value >= minimum and value <= maximum do
      value
    else
      raise ArgumentError,
            "bcrypt :#{name} must be an integer between #{minimum} and #{maximum}"
    end
  end

  defp ensure_bcrypt!(<<"$2b$", _remainder::binary>> = encoded) do
    case parse_hash(encoded) do
      {:ok, _parsed} -> encoded
      :error -> raise ArgumentError, "bcrypt_elixir returned an unexpected hash format"
    end
  end

  defp ensure_bcrypt!(_unexpected) do
    raise ArgumentError, "bcrypt_elixir returned an unexpected hash format"
  end

  defp parse_hash(encoded_hash) when byte_size(encoded_hash) != @encoded_length, do: :error

  defp parse_hash(encoded_hash) do
    case Regex.run(@hash_prefix, encoded_hash, capture: :all_but_first) do
      [prefix, raw_cost] ->
        {:ok,
         %{
           prefix: prefix,
           cost: String.to_integer(raw_cost),
           backend_hash: normalize_prefix(encoded_hash)
         }}

      nil ->
        :error
    end
  end

  # crypt_blowfish's $2y$ marks the same fixed algorithm bcrypt_elixir
  # implements as $2b$; the stored hash is never modified, only the copy
  # handed to the backend.
  defp normalize_prefix(<<"$2y$", remainder::binary>>), do: "$2b$" <> remainder
  defp normalize_prefix(encoded_hash), do: encoded_hash
end
