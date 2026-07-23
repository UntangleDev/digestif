defmodule DigestifTest do
  use ExUnit.Case, async: false

  alias Digestif.{Hasher, PBKDF2}
  alias Digestif.TestHasher

  setup do
    original_hasher = Application.get_env(:digestif, :hasher)
    original_legacy = Application.get_env(:digestif, :legacy_hashers)

    on_exit(fn ->
      restore_env(:hasher, original_hasher)
      restore_env(:legacy_hashers, original_legacy)
    end)

    Application.delete_env(:digestif, :hasher)
    Application.delete_env(:digestif, :legacy_hashers)
    :ok
  end

  test "the facade hashes, verifies, and detects current hashes" do
    hash = Digestif.hash("correct horse battery staple")

    assert String.starts_with?(hash, "$argon2id$v=19$m=32768,t=2,p=1$")
    assert Digestif.verify?("correct horse battery staple", hash)
    refute Digestif.verify?("wrong password", hash)
    refute Digestif.needs_rehash?(hash)
  end

  test "central configuration controls hashing and verification together" do
    Application.put_env(
      :digestif,
      :hasher,
      {PBKDF2, [iterations: 700_000, max_iterations: 700_000]}
    )

    hash = Digestif.hash("password")

    assert String.starts_with?(hash, "$pbkdf2-sha256$700000$")
    assert Digestif.verify?("password", hash)
    refute Digestif.needs_rehash?(hash)
  end

  test "verification admits only configured algorithms and marks legacy hashes" do
    Application.put_env(:digestif, :hasher, {TestHasher, []})
    Application.put_env(:digestif, :legacy_hashers, [{PBKDF2, []}])

    {:ok, legacy_hash} = PBKDF2.hash("password", [])
    {:ok, unknown_hash} = TestHasher.hash("password", [])
    unknown_hash = String.replace_prefix(unknown_hash, "$test-sha256$", "$unknown$")

    assert Digestif.verify?("password", legacy_hash)
    assert Digestif.needs_rehash?(legacy_hash)
    refute Digestif.verify?("password", unknown_hash)
  end

  test "hasher sets reject algorithm collisions" do
    assert_raise ArgumentError, ~r/algorithm identifiers must be unique/, fn ->
      Hasher.validate_set!(
        {PBKDF2, []},
        [{PBKDF2, [iterations: 700_000, max_iterations: 700_000]}]
      )
    end
  end

  test "algorithm dispatch examines a bounded prefix" do
    enormous = "$" <> String.duplicate("a", 1_000_000)

    assert Hasher.selected_hasher(enormous, {TestHasher, []}, [{PBKDF2, []}]) ==
             {TestHasher, []}
  end

  defp restore_env(key, nil), do: Application.delete_env(:digestif, key)
  defp restore_env(key, value), do: Application.put_env(:digestif, key, value)
end
