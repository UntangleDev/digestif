defmodule Digestif.PBKDF2 do
  @moduledoc """
  PBKDF2-HMAC-SHA-256 password hashing backed by `pbkdf2_elixir`.

  `pbkdf2_elixir` is a required Digestif dependency and owns salt
  generation, key derivation, the modular (passlib-style) encoded format,
  and verification. Digestif owns adapter dispatch, configuration policy,
  transparent migration, and the minimal resource preflight described
  below.

  Hashes are always minted explicitly as HMAC-SHA-256 with a 16-byte salt
  and a 32-byte derived key — the backend's HMAC-SHA-512/160,000-round
  defaults are never inherited. `:iterations` (default 600,000) is the
  round count for new hashes and dummy work, translated once to the
  backend's `:rounds` option; the validator rejects fewer than 600,000,
  the OWASP minimum for PBKDF2-HMAC-SHA-256. Do not tune below the floor
  for tests; use a deliberately cheap custom test hasher instead.
  `pbkdf2_elixir` derives
  in pure Elixir rather than through OTP's native `:crypto` PBKDF2, so
  benchmark login latency on production hardware before raising
  `:iterations`.

  Stored hashes are held to a verification budget: `:max_iterations`
  defaults to the configured `:iterations` and may not fall below it
  (every hash this configuration mints must stay verifiable), so a
  hostile, imported, or corrupted value can never make one verification
  more expensive than a login the host already pays for. Hosts that must
  keep verifying stronger imported hashes raise the budget explicitly:

      {Digestif.PBKDF2,
       iterations: 600_000, max_iterations: 1_000_000}

  ## Trust boundary

  Stored hashes are application-controlled database values, not untrusted
  network input. This adapter is a minimal resource preflight, defence in
  depth for corrupted, imported, or unexpectedly modified values: it
  bounds the total encoded length before any other work, extracts only
  the algorithm identifier and round count for the budget decision, and
  hands everything else to `pbkdf2_elixir`, which owns complete format
  parsing and cryptographic validation. Values the preflight rejects fail
  closed after the configured dummy work, and malformed values below its
  ceilings are the backend's to reject — the backend signals rejection by
  raising, which this adapter normalizes to the same fail-closed dummy
  path.

  Hashes minted by Bonafide's pre-extraction, pre-backend adapter used
  URL-safe Base64 for the salt and digest segments and are not accepted by
  the backend's passlib-style decoder.
  """

  @behaviour Digestif.Hasher

  @algorithm "pbkdf2-sha256"
  @backend Pbkdf2

  @default_iterations 600_000
  @minimum_iterations 600_000
  @maximum_iterations 10_000_000
  # The conventional salt and derived-key sizes minted hashes always use.
  @salt_len 16
  @derived_key_length 32
  # Total encoded ceiling checked before any other inspection: the
  # algorithm label, an 8-digit round count, and the conventional salt and
  # digest segments come to under 100 bytes, and 160 leaves room for
  # imported passlib values with larger salts. Longer values fail closed
  # without input-proportional work.
  @maximum_encoded_length 160
  # Just enough fixed structure to find the fields Digestif's resource
  # policy needs — the digest identifier for dispatch and the round count
  # for the budget decision. Every other validity question belongs to the
  # backend.
  @phc_prefix ~r/\A\$pbkdf2-sha256\$(\d{1,8})\$/

  @default_options [
    backend: @backend,
    iterations: @default_iterations,
    max_iterations: nil
  ]

  @impl true
  def algorithm, do: @algorithm

  @impl true
  def hash(password, options) when is_binary(password) and is_list(options) do
    normalized = normalize_options!(options)
    backend = backend!(normalized.backend)

    encoded = apply(backend, :hash_pwd_salt, [password, normalized.backend_options])
    {:ok, ensure_phc!(encoded)}
  end

  @impl true
  def verify(password, encoded_hash, options)
      when is_binary(password) and is_binary(encoded_hash) and is_list(options) do
    normalized = normalize_options!(options)
    backend = backend!(normalized.backend)

    case parse_hash(encoded_hash, normalized) do
      {:ok, _rounds} -> verify_parsed(backend, password, encoded_hash, normalized)
      :error -> dummy_verify(backend, normalized)
    end
  end

  @impl true
  def no_user_verify(_password, options) when is_list(options) do
    normalized = normalize_options!(options)
    dummy_verify(backend!(normalized.backend), normalized)
  end

  @doc """
  Returns whether a stored PBKDF2 hash differs from the configured round
  count. Hashes beyond the verification budget report `true` as well:
  they cannot verify under this configuration at all.
  """
  @impl true
  def needs_rehash?(encoded_hash, options \\ []) when is_binary(encoded_hash) do
    normalized = normalize_options!(options)

    case parse_hash(encoded_hash, normalized) do
      {:ok, rounds} -> rounds != normalized.iterations
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

  # The backend rejects malformed segments below the preflight ceilings by
  # raising; normalize every rejection to the fail-closed dummy path
  # rather than reproducing the backend's parser to predict it.
  defp verify_parsed(backend, password, encoded_hash, normalized) do
    apply(backend, :verify_pass, [password, encoded_hash])
  rescue
    _exception -> dummy_verify(backend, normalized)
  end

  defp dummy_verify(backend, normalized) do
    apply(backend, :no_user_verify, [normalized.backend_options])
    false
  end

  defp backend!(backend) when is_atom(backend) do
    if Code.ensure_loaded?(backend) and
         function_exported?(backend, :hash_pwd_salt, 2) and
         function_exported?(backend, :verify_pass, 2) and
         function_exported?(backend, :no_user_verify, 1) do
      backend
    else
      raise ArgumentError,
            "Digestif.PBKDF2 requires the :pbkdf2_elixir dependency"
    end
  end

  defp backend!(_backend), do: raise(ArgumentError, ":backend must be a module")

  defp normalize_options!(options) do
    options = Keyword.validate!(options, @default_options)
    backend = Keyword.fetch!(options, :backend)
    iterations = integer_option!(options, :iterations, @minimum_iterations, @maximum_iterations)

    # The budget may not fall below the configured cost — every hash this
    # configuration mints must stay verifiable.
    max_iterations =
      case Keyword.fetch!(options, :max_iterations) do
        nil ->
          iterations

        value when is_integer(value) and value >= iterations and value <= @maximum_iterations ->
          value

        _out_of_bounds ->
          raise ArgumentError,
                "PBKDF2 :max_iterations must be an integer between the configured " <>
                  ":iterations (#{iterations}) and #{@maximum_iterations}"
      end

    %{
      backend: backend,
      iterations: iterations,
      max_iterations: max_iterations,
      backend_options: [
        rounds: iterations,
        digest: :sha256,
        length: @derived_key_length,
        salt_len: @salt_len,
        format: :modular
      ]
    }
  end

  defp integer_option!(options, name, minimum, maximum) do
    value = Keyword.fetch!(options, name)

    if is_integer(value) and value >= minimum and value <= maximum do
      value
    else
      raise ArgumentError,
            "PBKDF2 :#{name} must be an integer between #{minimum} and #{maximum}"
    end
  end

  defp ensure_phc!(<<"$pbkdf2-sha256$", remainder::binary>> = encoded)
       when byte_size(remainder) > 0,
       do: encoded

  defp ensure_phc!(_unexpected) do
    raise ArgumentError, "pbkdf2_elixir returned an unexpected non-PBKDF2-SHA-256 hash"
  end

  defp parse_hash(encoded_hash, _normalized)
       when byte_size(encoded_hash) > @maximum_encoded_length,
       do: :error

  defp parse_hash(encoded_hash, normalized) do
    case Regex.run(@phc_prefix, encoded_hash, capture: :all_but_first) do
      [raw_rounds] ->
        rounds = String.to_integer(raw_rounds)

        # A zero round count would send the backend's derivation loop past
        # its terminating clause, so the floor of one round is a resource
        # bound, not a validity opinion.
        if rounds >= 1 and rounds <= normalized.max_iterations do
          {:ok, rounds}
        else
          :error
        end

      nil ->
        :error
    end
  end
end
