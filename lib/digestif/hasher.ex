defmodule Digestif.Hasher do
  @moduledoc """
  Behaviour and migration dispatcher for password hashers.

  A hasher is configured as a `{module, options}` tuple. The module performs
  one algorithm; this dispatcher identifies the self-describing algorithm in
  a stored hash and routes verification only to the configured primary or
  legacy hashers.

  Hashers may expose a rehash predicate, configuration validation, aliases
  for compatible stored prefixes, and a password byte limit. The bundled
  adapters also perform a small resource preflight before invoking their
  cryptographic backend.

  Use the simpler `Digestif` facade in ordinary applications. This module is
  the extension and integration boundary for authentication libraries and
  custom hashers.
  """

  @type t :: {module(), keyword()}

  @callback hash(value :: String.t(), options :: keyword()) :: {:ok, String.t()}
  @callback verify(value :: String.t(), encoded_hash :: String.t(), options :: keyword()) ::
              boolean()
  @callback no_user_verify(value :: String.t(), options :: keyword()) :: false
  @callback algorithm() :: String.t()
  @callback algorithm_aliases() :: [String.t()]
  @callback needs_rehash?(encoded_hash :: String.t(), options :: keyword()) :: boolean()
  @callback validate_options!(options :: keyword()) :: :ok
  @callback password_byte_limit() :: pos_integer()

  @optional_callbacks algorithm: 0,
                      algorithm_aliases: 0,
                      needs_rehash?: 2,
                      validate_options!: 1,
                      password_byte_limit: 0

  @doc """
  Verifies a value against the hasher selected by the stored algorithm.

  Only the primary hasher and explicitly listed legacy hashers are eligible.
  Unknown or malformed algorithm identifiers fall back to the primary
  hasher, which must fail closed for foreign encodings.
  """
  @spec verify_with_hashers(String.t(), String.t(), t(), [t()]) :: {:ok, t()} | :error
  def verify_with_hashers(value, encoded_hash, primary, legacy_hashers)
      when is_binary(value) and is_binary(encoded_hash) do
    validate_set!(primary, legacy_hashers)
    {module, options} = selected_hasher(encoded_hash, primary, legacy_hashers)

    if module.verify(value, encoded_hash, options),
      do: {:ok, {module, options}},
      else: :error
  end

  @doc """
  Returns whether a verified hash should be replaced by the primary hasher.

  A hash verified by a legacy hasher always needs rehashing. For the primary
  hasher, its optional `c:needs_rehash?/2` callback decides.
  """
  @spec needs_rehash?(String.t(), t(), t()) :: boolean()
  def needs_rehash?(encoded_hash, selected_hasher, primary_hasher) do
    if selected_hasher != primary_hasher do
      true
    else
      {module, options} = primary_hasher

      if function_exported?(module, :needs_rehash?, 2) do
        safely_needs_rehash(module, encoded_hash, options)
      else
        false
      end
    end
  end

  @doc """
  Validates one hasher tuple and its options.
  """
  @spec validate!(t()) :: :ok
  def validate!({module, options}) when is_atom(module) and is_list(options) do
    unless Code.ensure_loaded?(module) do
      raise ArgumentError, "hasher #{inspect(module)} could not be loaded"
    end

    for {name, arity} <- [hash: 2, verify: 3, no_user_verify: 2] do
      unless function_exported?(module, name, arity) do
        raise ArgumentError, "hasher #{inspect(module)} must implement #{name}/#{arity}"
      end
    end

    if function_exported?(module, :validate_options!, 1) and
         module.validate_options!(options) != :ok do
      raise ArgumentError,
            "hasher #{inspect(module)} validate_options!/1 must return :ok"
    end

    validate_password_byte_limit!(module)
    :ok
  end

  def validate!(_hasher) do
    raise ArgumentError, "hasher must be a {module, options} tuple"
  end

  @doc """
  Validates a primary hasher and its legacy migration set.

  Legacy hashers must declare self-describing algorithm identifiers. All
  identifiers and aliases must be unique, so dispatch cannot depend on list
  order.
  """
  @spec validate_set!(t(), [t()]) :: :ok
  def validate_set!(primary, legacy_hashers) when is_list(legacy_hashers) do
    validate!(primary)

    Enum.each(legacy_hashers, fn hasher ->
      validate!(hasher)
      {module, _options} = hasher

      unless function_exported?(module, :algorithm, 0) and
               valid_algorithm?(module.algorithm()) do
        raise ArgumentError,
              "legacy hasher #{inspect(module)} must implement algorithm/0"
      end
    end)

    algorithms =
      Enum.flat_map(legacy_hashers, &declared_algorithms/1) ++
        declared_algorithms(primary)

    if length(algorithms) != length(Enum.uniq(algorithms)) do
      raise ArgumentError, "hasher algorithm identifiers must be unique"
    end

    :ok
  end

  def validate_set!(_primary, _legacy_hashers) do
    raise ArgumentError, "legacy_hashers must be a list of {module, options} tuples"
  end

  @doc """
  Returns a hasher's declared password byte limit, or `nil` when unlimited.
  """
  @spec password_byte_limit(t()) :: pos_integer() | nil
  def password_byte_limit({module, _options} = hasher) do
    validate!(hasher)

    if function_exported?(module, :password_byte_limit, 0),
      do: module.password_byte_limit(),
      else: nil
  end

  @doc false
  @spec selected_hasher(String.t(), t(), [t()]) :: t()
  def selected_hasher(encoded_hash, primary, legacy_hashers) do
    case encoded_algorithm(encoded_hash) do
      nil ->
        primary

      algorithm ->
        Enum.find([primary | legacy_hashers], primary, fn {module, _options} ->
          hasher_matches?(module, algorithm)
        end)
    end
  end

  defp hasher_matches?(module, algorithm) do
    (function_exported?(module, :algorithm, 0) and module.algorithm() == algorithm) or
      (function_exported?(module, :algorithm_aliases, 0) and
         algorithm in module.algorithm_aliases())
  end

  # Inspect at most the 64 bytes a valid identifier can occupy. This keeps
  # dispatch work bounded even when a caller supplies an enormous value.
  defp encoded_algorithm(<<"$", remainder::binary>>),
    do: take_algorithm(remainder, <<>>, 0)

  defp encoded_algorithm(_encoded_hash), do: nil

  defp take_algorithm(<<"$", _rest::binary>>, algorithm, size) when size > 0,
    do: algorithm

  defp take_algorithm(<<byte, rest::binary>>, algorithm, size) when size < 64,
    do: take_algorithm(rest, <<algorithm::binary, byte>>, size + 1)

  defp take_algorithm(_remainder, _algorithm, _size), do: nil

  defp declared_algorithms({module, _options}) do
    if function_exported?(module, :algorithm, 0) do
      algorithm = module.algorithm()

      unless valid_algorithm?(algorithm) do
        raise ArgumentError, "hasher #{inspect(module)} returned an invalid algorithm id"
      end

      [algorithm | algorithm_aliases!(module)]
    else
      []
    end
  end

  defp algorithm_aliases!(module) do
    if function_exported?(module, :algorithm_aliases, 0) do
      aliases = module.algorithm_aliases()

      unless is_list(aliases) and Enum.all?(aliases, &valid_algorithm?/1) do
        raise ArgumentError, "hasher #{inspect(module)} returned invalid algorithm aliases"
      end

      aliases
    else
      []
    end
  end

  defp valid_algorithm?(algorithm) when is_binary(algorithm) do
    Regex.match?(~r/\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/, algorithm)
  end

  defp valid_algorithm?(_algorithm), do: false

  defp validate_password_byte_limit!(module) do
    if function_exported?(module, :password_byte_limit, 0) do
      limit = module.password_byte_limit()

      unless is_integer(limit) and limit > 0 do
        raise ArgumentError, "hasher #{inspect(module)} returned an invalid password byte limit"
      end
    end
  end

  defp safely_needs_rehash(module, encoded_hash, options) do
    module.needs_rehash?(encoded_hash, options) == true
  rescue
    _exception -> false
  catch
    _kind, _reason -> false
  end
end
