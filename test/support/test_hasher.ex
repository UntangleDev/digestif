defmodule Digestif.TestHasher do
  @moduledoc false

  @behaviour Digestif.Hasher

  @algorithm "test-sha256"

  @impl true
  def algorithm, do: @algorithm

  @impl true
  def hash(value, options) when is_binary(value) do
    validate_options!(options)
    salt = :crypto.strong_rand_bytes(16)
    digest = derive(value, salt)

    {:ok,
     Enum.join(
       [
         "",
         @algorithm,
         Base.url_encode64(salt, padding: false),
         Base.url_encode64(digest, padding: false)
       ],
       "$"
     )}
  end

  @impl true
  def verify(value, encoded_hash, options)
      when is_binary(value) and is_binary(encoded_hash) do
    validate_options!(options)

    case parse(encoded_hash) do
      {:ok, salt, expected} -> :crypto.hash_equals(derive(value, salt), expected)
      :error -> no_user_verify(value, options)
    end
  end

  @impl true
  def no_user_verify(value, options) when is_binary(value) do
    validate_options!(options)
    :crypto.hash_equals(derive(value, <<0::128>>), <<0::256>>)
    false
  end

  @impl true
  def needs_rehash?(encoded_hash, options) do
    validate_options!(options)
    not match?({:ok, _salt, _digest}, parse(encoded_hash))
  end

  @impl true
  def validate_options!(options) do
    Keyword.validate!(options, [])
    :ok
  end

  defp derive(value, salt), do: :crypto.hash(:sha256, [salt, value])

  defp parse(encoded_hash) do
    with ["", @algorithm, encoded_salt, encoded_digest] <-
           String.split(encoded_hash, "$"),
         {:ok, salt} when byte_size(salt) == 16 <-
           Base.url_decode64(encoded_salt, padding: false),
         {:ok, digest} when byte_size(digest) == 32 <-
           Base.url_decode64(encoded_digest, padding: false) do
      {:ok, salt, digest}
    else
      _invalid -> :error
    end
  end
end
