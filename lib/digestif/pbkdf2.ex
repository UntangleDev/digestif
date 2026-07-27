defmodule Digestif.PBKDF2 do
  @moduledoc """
  PBKDF2-HMAC-SHA-256 password hashing backed by OTP `:crypto`.

  OTP owns salt generation and key derivation. Digestif owns the narrow
  password-hash layer around it: the modular (passlib-style) encoding,
  constant-time verification, configuration policy, transparent migration,
  and the resource preflight described below. The encoding remains compatible
  with hashes minted by `pbkdf2_elixir`: unpadded Base64 with `.` in place of
  `+`.

  Hashes are always minted explicitly as HMAC-SHA-256 with a 16-byte salt
  and a 32-byte derived key. `:iterations` (default 600,000) is the round
  count for new hashes and dummy work; the validator rejects fewer than
  600,000, the OWASP minimum for PBKDF2-HMAC-SHA-256. Do not tune below
  the floor for tests; use a deliberately cheap custom test hasher instead.
  Benchmark login latency on production hardware before raising
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
  network input. This adapter bounds the total encoded length before any
  other inspection and extracts only the algorithm identifier and round
  count for the budget decision. Values the preflight rejects fail closed
  after the configured dummy work. Values within that budget must then
  contain a non-empty salt and one 32-byte digest in the passlib-adapted
  Base64 alphabet, both canonically encoded; malformed values take the same
  dummy path.
  """

  @behaviour Digestif.Hasher

  @algorithm "pbkdf2-sha256"

  @default_iterations 600_000
  @minimum_iterations 600_000
  @maximum_iterations 10_000_000
  # The conventional salt and derived-key sizes minted hashes always use.
  @salt_len 16
  @minimum_salt_length 1
  @derived_key_length 32
  # Total encoded ceiling checked before any other inspection: the
  # algorithm label, an 8-digit round count, and the conventional salt and
  # digest segments come to under 100 bytes, and 160 leaves room for
  # imported passlib values with larger salts. Longer values fail closed
  # without input-proportional work.
  @maximum_encoded_length 160
  @dummy_salt <<0::128>>
  @dummy_digest <<0::256>>
  # Just enough fixed structure to find the fields Digestif's resource
  # policy needs — the digest identifier for dispatch and the round count
  # for the budget decision. Full format parsing happens only after these
  # resource bounds pass.
  @phc_prefix ~r/\A\$pbkdf2-sha256\$(0|[1-9]\d{0,7})\$/

  @default_options [
    iterations: @default_iterations,
    max_iterations: nil
  ]

  @impl true
  def algorithm, do: @algorithm

  @impl true
  def hash(password, options) when is_binary(password) and is_list(options) do
    normalized = normalize_options!(options)
    salt = :crypto.strong_rand_bytes(@salt_len)
    digest = derive(password, salt, normalized.iterations)

    {:ok, encode_hash(normalized.iterations, salt, digest)}
  end

  @impl true
  def verify(password, encoded_hash, options)
      when is_binary(password) and is_binary(encoded_hash) and is_list(options) do
    normalized = normalize_options!(options)

    case preflight_hash(encoded_hash, normalized) do
      {:ok, iterations} -> verify_preflighted(password, encoded_hash, iterations, normalized)
      :error -> dummy_verify(password, normalized)
    end
  end

  @impl true
  def no_user_verify(password, options) when is_binary(password) and is_list(options) do
    normalized = normalize_options!(options)
    dummy_verify(password, normalized)
  end

  @doc """
  Returns whether a stored PBKDF2 hash differs from the configured round
  count. Hashes beyond the verification budget report `true` as well:
  they cannot verify under this configuration at all.
  """
  @impl true
  def needs_rehash?(encoded_hash, options \\ []) when is_binary(encoded_hash) do
    normalized = normalize_options!(options)

    case preflight_hash(encoded_hash, normalized) do
      {:ok, rounds} -> rounds != normalized.iterations
      :error -> true
    end
  end

  @doc false
  @impl true
  @spec validate_options!(keyword()) :: :ok
  def validate_options!(options) when is_list(options) do
    normalize_options!(options)
    :ok
  end

  defp verify_preflighted(password, encoded_hash, iterations, normalized) do
    case decode_hash(encoded_hash) do
      {:ok, salt, expected_digest} ->
        actual_digest = derive(password, salt, iterations)
        :crypto.hash_equals(actual_digest, expected_digest)

      :error ->
        dummy_verify(password, normalized)
    end
  end

  defp dummy_verify(password, normalized) do
    actual_digest = derive(password, @dummy_salt, normalized.iterations)

    # A dummy credential never authenticates, including in the vanishingly
    # unlikely event that its derived value equals the fixed comparison value.
    case :crypto.hash_equals(actual_digest, @dummy_digest) do
      true -> false
      false -> false
    end
  end

  defp derive(password, salt, iterations) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, @derived_key_length)
  end

  defp encode_hash(iterations, salt, digest) do
    "$#{@algorithm}$#{iterations}$#{encode_adapted64(salt)}$#{encode_adapted64(digest)}"
  end

  defp encode_adapted64(binary) do
    encoded = Base.encode64(binary, padding: false)
    :binary.replace(encoded, "+", ".", [:global])
  end

  defp decode_adapted64(encoded) do
    # OTP's standard decoder accepts `+` and optional `=` padding. Neither is
    # part of the adapted alphabet pbkdf2_elixir used, so reject them before
    # translating `.` back to the standard alphabet.
    if adapted64?(encoded) do
      translated = :binary.replace(encoded, ".", "+", [:global])
      Base.decode64(translated, padding: false)
    else
      :error
    end
  end

  defp adapted64?(<<>>), do: true

  defp adapted64?(<<character, rest::binary>>)
       when character in ?A..?Z or character in ?a..?z or character in ?0..?9 or
              character in ~c"./",
       do: adapted64?(rest)

  defp adapted64?(_invalid), do: false

  defp decode_hash(encoded_hash) do
    case :binary.split(encoded_hash, "$", [:global]) do
      [<<>>, @algorithm, _iterations, encoded_salt, encoded_digest] ->
        with {:ok, salt} when byte_size(salt) >= @minimum_salt_length <-
               decode_adapted64(encoded_salt),
             true <- encode_adapted64(salt) == encoded_salt,
             {:ok, digest} when byte_size(digest) == @derived_key_length <-
               decode_adapted64(encoded_digest),
             true <- encode_adapted64(digest) == encoded_digest do
          {:ok, salt, digest}
        else
          _malformed -> :error
        end

      _malformed ->
        :error
    end
  end

  defp normalize_options!(options) do
    options = Keyword.validate!(options, @default_options)
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
      iterations: iterations,
      max_iterations: max_iterations
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

  defp preflight_hash(encoded_hash, _normalized)
       when byte_size(encoded_hash) > @maximum_encoded_length,
       do: :error

  defp preflight_hash(encoded_hash, normalized) do
    case Regex.run(@phc_prefix, encoded_hash, capture: :all_but_first) do
      [raw_rounds] ->
        rounds = String.to_integer(raw_rounds)

        # OTP rejects zero, but checking it before the NIF keeps malformed
        # stored data on the deliberate dummy path rather than an exception.
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
