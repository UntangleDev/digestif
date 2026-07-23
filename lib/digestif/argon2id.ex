defmodule Digestif.Argon2id do
  @moduledoc """
  Argon2id password hashing backed by the required `argon2_elixir`
  dependency.

  This is Digestif's default adapter. The optional `Digestif.PBKDF2`
  adapter remains available for compatibility and environments with a
  specific PBKDF2 requirement.

  The defaults are `m_cost: 15`, `t_cost: 2`, and `parallelism: 1`.
  `argon2_elixir` expresses `m_cost` as the base-2 exponent of kibibytes, so
  `15` uses 32 MiB. This is the smallest supported power-of-two memory setting
  above OWASP's 19 MiB minimum, and the validator enforces it as the floor
  (`m_cost >= 15`, `t_cost >= 2`). Benchmark production hardware before
  raising these values; for fast test fixtures use a deliberately cheap custom
  test hasher rather than tuning the real algorithm down. The configurable bounds are
  `m_cost` 15..21, `t_cost` 2..16, and `parallelism` 1..8; salt and tag are
  the conventional 16 and 32 bytes and are not configurable.

  Stored hashes are held to a verification budget rather than to the
  encoding's theoretical limits: by default a stored hash may not request
  more memory, passes, or lanes than the configured hashing costs, so a
  hostile, imported, or corrupted value can never make one verification more
  expensive than a login the host already pays for. Hosts that must keep
  verifying stronger imported hashes raise the budget explicitly:

      {Digestif.Argon2id,
       m_cost: 15, verification_budget: [m_cost: 19, t_cost: 4]}

  Each budget dimension defaults to its configured cost and may not fall
  below it (every hash this configuration mints must stay verifiable).

  ## Trust boundary

  Stored hashes are application-controlled database values, not untrusted
  network input. This adapter is a minimal resource preflight, defence in
  depth for corrupted, imported, or unexpectedly modified values: it bounds
  the total encoded length before any other work, extracts only the cost
  parameters for the budget decision, and hands everything else to
  `argon2_elixir`, which owns complete format parsing and cryptographic
  validation. The preflight is not a general parser or sanitizer for
  adversarial cryptographic encodings; anything it rejects fails closed
  after the configured dummy work, and malformed values below its ceilings
  are the backend's to reject.
  """

  @behaviour Digestif.Hasher

  import Bitwise

  @algorithm "argon2id"
  @argon2_version 19
  @backend Argon2
  @phc_prefix "$argon2id$"

  # Absolute option bounds. These validate what a host may configure or
  # budget; what a stored hash may request is bounded by the (typically much
  # smaller) verification budget.
  @maximum_m_cost 21
  @maximum_t_cost 16
  @maximum_parallelism 8
  # The conventional salt and tag sizes minted hashes always use.
  @salt_len 16
  @hashlen 32
  # Total encoded ceiling checked before anything else: the algorithm and
  # version labels, maximal cost parameters, and conventional salt and tag
  # segments come to well under 200 bytes, and 320 leaves room for imported
  # values with larger segments. Longer values fail closed without
  # input-proportional work.
  @maximum_encoded_length 320

  # Just enough fixed structure to find the fields Digestif's resource
  # policy needs — the version for the rehash decision and m/t/p for the
  # budget decision. Every other validity question belongs to the backend.
  @phc_pattern ~r/\A\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$/

  @default_options [
    backend: @backend,
    t_cost: 2,
    m_cost: 15,
    parallelism: 1,
    verification_budget: []
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
      {:ok, parsed} -> verify_parsed(backend, password, parsed.phc_hash, normalized)
      :error -> dummy_verify(backend, normalized)
    end
  end

  @impl true
  def no_user_verify(_password, options) when is_list(options) do
    normalized = normalize_options!(options)
    dummy_verify(backend!(normalized.backend), normalized)
  end

  @doc """
  Returns whether a stored Argon2id hash is weaker than the configured
  parameters. Hashes beyond the verification budget report `true` as well:
  they cannot verify under this configuration at all.
  """
  @impl true
  def needs_rehash?(encoded_hash, options \\ []) when is_binary(encoded_hash) do
    normalized = normalize_options!(options)

    case parse_hash(encoded_hash, normalized) do
      {:ok, parsed} ->
        parsed.version != @argon2_version or
          parsed.memory_kib < normalized.memory_kib or
          parsed.t_cost < normalized.t_cost or
          parsed.parallelism < normalized.parallelism

      :error ->
        true
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

  defp verify_parsed(backend, password, phc_hash, normalized) do
    apply(backend, :verify_pass, [password, phc_hash])
  rescue
    ArgumentError -> dummy_verify(backend, normalized)
  end

  defp dummy_verify(backend, normalized) do
    apply(backend, :no_user_verify, [normalized.backend_options])
  end

  defp backend!(backend) when is_atom(backend) do
    if Code.ensure_loaded?(backend) and
         function_exported?(backend, :hash_pwd_salt, 2) and
         function_exported?(backend, :verify_pass, 2) and
         function_exported?(backend, :no_user_verify, 1) do
      backend
    else
      raise ArgumentError,
            "Digestif.Argon2id requires the :argon2_elixir dependency"
    end
  end

  defp backend!(_backend), do: raise(ArgumentError, ":backend must be a module")

  defp normalize_options!(options) do
    options = Keyword.validate!(options, @default_options)
    backend = Keyword.fetch!(options, :backend)
    t_cost = integer_option!(options, :t_cost, 2, @maximum_t_cost)
    m_cost = integer_option!(options, :m_cost, 15, @maximum_m_cost)
    parallelism = integer_option!(options, :parallelism, 1, @maximum_parallelism)
    memory_kib = 1 <<< m_cost

    if memory_kib < 8 * parallelism do
      raise ArgumentError,
            "Argon2id memory must be at least 8 KiB per parallelism lane"
    end

    budget =
      Keyword.validate!(Keyword.fetch!(options, :verification_budget),
        m_cost: m_cost,
        t_cost: t_cost,
        parallelism: parallelism
      )

    %{
      backend: backend,
      t_cost: t_cost,
      memory_kib: memory_kib,
      parallelism: parallelism,
      budget_memory_kib: 1 <<< budget_option!(budget, :m_cost, m_cost),
      budget_t_cost: budget_option!(budget, :t_cost, t_cost),
      budget_parallelism: budget_option!(budget, :parallelism, parallelism),
      backend_options: [
        t_cost: t_cost,
        m_cost: m_cost,
        parallelism: parallelism,
        salt_len: @salt_len,
        hashlen: @hashlen,
        argon2_type: 2,
        format: :encoded
      ]
    }
  end

  defp integer_option!(options, name, minimum, maximum) do
    value = Keyword.fetch!(options, name)

    if is_integer(value) and value >= minimum and value <= maximum do
      value
    else
      raise ArgumentError,
            "Argon2id :#{name} must be an integer between #{minimum} and #{maximum}"
    end
  end

  # A budget dimension may not fall below its configured cost — every hash
  # the configuration mints must stay verifiable — nor exceed the absolute
  # option bound.
  defp budget_option!(budget, name, configured) do
    value = Keyword.fetch!(budget, name)
    maximum = maximum_for(name)

    if is_integer(value) and value >= configured and value <= maximum do
      value
    else
      raise ArgumentError,
            "Argon2id :verification_budget #{name} must be an integer between the " <>
              "configured :#{name} (#{configured}) and #{maximum}"
    end
  end

  defp maximum_for(:m_cost), do: @maximum_m_cost
  defp maximum_for(:t_cost), do: @maximum_t_cost
  defp maximum_for(:parallelism), do: @maximum_parallelism

  defp ensure_phc!(<<@phc_prefix, remainder::binary>> = encoded)
       when byte_size(remainder) > 0,
       do: encoded

  defp ensure_phc!(_unexpected) do
    raise ArgumentError, "argon2_elixir returned an unexpected non-Argon2id hash"
  end

  defp parse_hash(encoded_hash, _normalized)
       when byte_size(encoded_hash) > @maximum_encoded_length,
       do: :error

  defp parse_hash(encoded_hash, normalized) do
    case Regex.run(@phc_pattern, encoded_hash, capture: :all_but_first) do
      [version, memory, t_cost, parallelism] ->
        memory_kib = String.to_integer(memory)
        t_cost = String.to_integer(t_cost)
        parallelism = String.to_integer(parallelism)

        if memory_kib <= normalized.budget_memory_kib and
             t_cost <= normalized.budget_t_cost and
             parallelism <= normalized.budget_parallelism do
          {:ok,
           %{
             version: String.to_integer(version),
             memory_kib: memory_kib,
             t_cost: t_cost,
             parallelism: parallelism,
             phc_hash: encoded_hash
           }}
        else
          :error
        end

      nil ->
        :error
    end
  end
end
