defmodule Digestif.BcryptTest do
  use ExUnit.Case, async: true

  alias Digestif.Hasher
  alias Digestif.Bcrypt, as: BcryptHasher
  alias Digestif.PBKDF2

  defmodule TwoASquatter do
    @behaviour Digestif.Hasher

    @impl true
    def algorithm, do: "2a"

    @impl true
    def hash(password, options), do: PBKDF2.hash(password, options)

    @impl true
    def verify(password, encoded_hash, options),
      do: PBKDF2.verify(password, encoded_hash, options)

    @impl true
    def no_user_verify(password, options), do: PBKDF2.no_user_verify(password, options)
  end

  @password "correct horse battery staple"

  test "mints $2b$ hashes and validates options strictly" do
    assert {:ok, hash} = BcryptHasher.hash(@password, log_rounds: 10)
    assert String.starts_with?(hash, "$2b$10$")
    assert byte_size(hash) == 60

    assert BcryptHasher.verify(@password, hash, log_rounds: 10)
    refute BcryptHasher.verify("wrong password", hash, log_rounds: 10)
    refute BcryptHasher.no_user_verify(@password, log_rounds: 10)

    # OWASP floor for new hashes and dummy work; bcrypt's own cost ceiling.
    assert_raise ArgumentError, ~r/log_rounds/, fn ->
      BcryptHasher.validate_options!(log_rounds: 9)
    end

    assert_raise ArgumentError, ~r/log_rounds/, fn ->
      BcryptHasher.validate_options!(log_rounds: 32)
    end

    assert_raise ArgumentError, ~r/max_cost/, fn ->
      BcryptHasher.validate_options!(max_cost: 3)
    end

    # A cost that mints hashes the verification bound rejects is a
    # contradiction, not two independent settings.
    assert_raise ArgumentError, ~r/:log_rounds must not exceed :max_cost/, fn ->
      BcryptHasher.validate_options!(log_rounds: 12, max_cost: 10)
    end

    assert_raise ArgumentError, fn ->
      BcryptHasher.validate_options!(rounds: 12)
    end

    assert_raise ArgumentError, ~r/bcrypt_elixir/, fn ->
      BcryptHasher.validate_options!(backend: Digestif.NoSuchBcryptBackend)
    end

    assert :ok = BcryptHasher.validate_options!(log_rounds: 10)
  end

  test "verifies $2a$ and $2y$ prefixes and bounds the stored cost" do
    legacy_salt = Bcrypt.Base.gen_salt(10, true)
    legacy_hash = Bcrypt.Base.hash_password(@password, legacy_salt)
    assert String.starts_with?(legacy_hash, "$2a$10$")
    assert BcryptHasher.verify(@password, legacy_hash, log_rounds: 10)
    refute BcryptHasher.verify("wrong password", legacy_hash, log_rounds: 10)

    {:ok, modern_hash} = BcryptHasher.hash(@password, log_rounds: 10)
    php_hash = String.replace_prefix(modern_hash, "$2b$", "$2y$")
    assert BcryptHasher.verify(@password, php_hash, log_rounds: 10)
    refute BcryptHasher.verify("wrong password", php_hash, log_rounds: 10)

    # A stored cost above the configured bound fails closed even for the
    # correct password, without invoking the backend's variable-cost work.
    {:ok, strong_hash} = BcryptHasher.hash(@password, log_rounds: 11)
    refute BcryptHasher.verify(@password, strong_hash, log_rounds: 10, max_cost: 10)
    assert BcryptHasher.verify(@password, strong_hash, log_rounds: 10, max_cost: 11)

    # Malformed encodings fail closed with the correct password.
    for bad <- [
          "",
          "$2b$10$short",
          String.replace_prefix(modern_hash, "$2b$", "$2z$"),
          String.replace_prefix(modern_hash, "$2b$10$", "$2b$aa$"),
          String.replace_prefix(modern_hash, "$2b$10$", "$2b$03$"),
          modern_hash <> "extra",
          String.slice(modern_hash, 0, 59) <> "!"
        ] do
      refute BcryptHasher.verify(@password, bad, log_rounds: 10)
    end
  end

  test "needs_rehash? tracks prefix and cost policy" do
    {:ok, hash} = BcryptHasher.hash(@password, log_rounds: 10)

    refute BcryptHasher.needs_rehash?(hash, log_rounds: 10)
    assert BcryptHasher.needs_rehash?(hash, log_rounds: 11)
    assert BcryptHasher.needs_rehash?(String.replace_prefix(hash, "$2b$", "$2a$"), log_rounds: 10)
    assert BcryptHasher.needs_rehash?(String.replace_prefix(hash, "$2b$", "$2y$"), log_rounds: 10)
    assert BcryptHasher.needs_rehash?("not a hash", log_rounds: 10)
  end

  test "the dispatcher routes every bcrypt prefix through the declared aliases" do
    primary = {PBKDF2, []}
    legacy = {BcryptHasher, [log_rounds: 10]}

    {:ok, hash} = BcryptHasher.hash(@password, log_rounds: 10)

    for prefix <- ["$2b$", "$2a$", "$2y$"] do
      stored = String.replace_prefix(hash, "$2b$", prefix)

      assert {:ok, ^legacy} =
               Hasher.verify_with_hashers(@password, stored, primary, [legacy])

      assert Hasher.needs_rehash?(stored, legacy, primary)

      assert :error =
               Hasher.verify_with_hashers("wrong password", stored, primary, [legacy])
    end
  end

  test "bcrypt declares its 72-byte password limit" do
    assert BcryptHasher.password_byte_limit() == 72
    assert Hasher.password_byte_limit({BcryptHasher, [log_rounds: 10]}) == 72
  end

  test "configuration rejects alias collisions between hashers" do
    assert_raise ArgumentError, ~r/must be unique/, fn ->
      Hasher.validate_set!(
        {PBKDF2, []},
        [
          {BcryptHasher, [log_rounds: 10]},
          {TwoASquatter, []}
        ]
      )
    end
  end
end
