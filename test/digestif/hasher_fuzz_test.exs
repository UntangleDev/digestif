defmodule Digestif.HasherFuzzTest do
  # Fuzz and boundary coverage for the surfaces Digestif owns: the minimal
  # preflight ceilings of the thin PBKDF2, Argon2id, and
  # bcrypt adapters, and the dispatcher. The complete backend grammars
  # belong to pbkdf2_elixir, argon2_elixir, and bcrypt_elixir and are
  # deliberately not re-tested here: malformed values below the preflight
  # ceilings are asserted only to delegate and fail closed.
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Digestif.Fuzz

  alias Digestif.Hasher
  alias Digestif.{Argon2id, Bcrypt, PBKDF2}
  alias Digestif.TestHasher, as: TestHasher

  defmodule RecordingBcryptBackend do
    def hash_pwd_salt(_password, _options), do: raise("recording backend does not mint hashes")

    def verify_pass(_password, encoded_hash) do
      send(self(), {:bcrypt_backend, {:verify_pass, encoded_hash}})
      false
    end

    def no_user_verify(options) do
      send(self(), {:bcrypt_backend, {:no_user_verify, options}})
      false
    end
  end

  @password "correct horse battery staple"

  # Cheapest options each hasher accepts, so fuzz volume spends its time in
  # the preflights rather than in deliberate key-derivation work.
  @pbkdf2_options [iterations: 600_000]
  @bcrypt_options [log_rounds: 10, max_cost: 10]
  @argon2_options [t_cost: 2, m_cost: 15, parallelism: 1]

  @hashers [
    {TestHasher, []},
    {PBKDF2, @pbkdf2_options},
    {Bcrypt, @bcrypt_options},
    {Argon2id, @argon2_options}
  ]

  # Totality of Digestif's own preflight parsing — every adapter must answer
  # the rehash question with a boolean for any input, without crypto work.
  # This asserts Digestif behavior, not agreement with a backend grammar.
  property "needs_rehash? is a total boolean parser for hostile input" do
    check all(encoded <- hostile_binary(), max_runs: runs(150)) do
      for {module, options} <- @hashers do
        assert module.needs_rehash?(encoded, options) in [true, false]
      end
    end
  end

  property "the test hasher fails closed under high-volume hostile verify" do
    check all(encoded <- hostile_binary(), max_runs: runs(150)) do
      refute TestHasher.verify(@password, encoded, [])
    end
  end

  describe "PBKDF2 preflight boundaries" do
    # The preflight extracts only the algorithm label and round count;
    # rounds past the verification budget — or a zero count the backend's
    # derivation loop would never terminate on — fail closed without
    # backend work. Salt and digest validity beyond them belong to
    # pbkdf2_elixir (see Digestif.PBKDF2Test).
    property "round counts outside 1..configured budget never parse" do
      out_of_range =
        one_of([
          constant(0),
          integer(600_001..99_999_999)
        ])

      check all(rounds <- out_of_range, max_runs: runs(80)) do
        hostile = "$pbkdf2-sha256$#{rounds}$Igmnl/E3JR2Cevlp0Cshdw$digest"
        assert PBKDF2.needs_rehash?(hostile, @pbkdf2_options)
      end
    end
  end

  describe "bcrypt preflight boundaries" do
    setup do
      {:ok, encoded} = Bcrypt.hash(@password, @bcrypt_options)
      %{encoded: encoded}
    end

    test "only exactly 60 bytes pass the length preflight", context do
      # 59 and 61 bytes: rejected by the fixed-length bound before any
      # other inspection, paying the dummy path.
      for hostile <- [
            "$2b$04$" <> String.duplicate(".", 52),
            "$2b$04$" <> String.duplicate(".", 54),
            "$2b$4$" <> String.duplicate(".", 53),
            context.encoded <> "x",
            String.slice(context.encoded, 0, 59)
          ] do
        refute Bcrypt.verify(@password, hostile, @bcrypt_options)
        assert Bcrypt.needs_rehash?(hostile, @bcrypt_options)
      end

      # 60 bytes with an unsupported family prefix: rejected by dispatch.
      unknown_family = "$2z$04$" <> String.duplicate(".", 53)
      refute Bcrypt.verify(@password, unknown_family, @bcrypt_options)
      assert Bcrypt.needs_rehash?(unknown_family, @bcrypt_options)
    end

    test "malformed 60-byte bodies are delegated to the backend and fail closed" do
      # The preflight reads only the prefix and cost; body validity is
      # bcrypt_elixir's, which rejects these without raising.
      garbage_body = "$2b$10$" <> String.duplicate("!", 53)
      below_backend_floor = "$2b$03$" <> String.duplicate(".", 53)

      refute Bcrypt.verify(@password, garbage_body, @bcrypt_options)
      refute Bcrypt.verify(@password, below_backend_floor, @bcrypt_options)

      # A delegated body Digestif never inspected can still match the
      # configured prefix and cost, so the rehash answer is false; rehash
      # decisions are only meaningful for hashes that verify.
      refute Bcrypt.needs_rehash?(garbage_body, @bcrypt_options)
    end

    test "preflight rejections use dummy work while in-budget bodies reach the backend" do
      options = Keyword.put(@bcrypt_options, :backend, RecordingBcryptBackend)
      body = String.duplicate(".", 53)

      for rejected <- ["$2b$11$" <> body, "$2b$10$" <> body <> "."] do
        refute Bcrypt.verify(@password, rejected, options)
        assert_received {:bcrypt_backend, {:no_user_verify, [log_rounds: 10]}}
        refute_received {:bcrypt_backend, {:verify_pass, _encoded_hash}}
      end

      malformed_body = "$2b$10$" <> String.duplicate("!", 53)
      refute Bcrypt.verify(@password, malformed_body, options)
      assert_received {:bcrypt_backend, {:verify_pass, ^malformed_body}}
      refute_received {:bcrypt_backend, {:no_user_verify, _options}}

      assert Bcrypt.needs_rehash?("$2b$11$" <> body, @bcrypt_options)
    end
  end

  describe "Argon2id preflight boundaries" do
    setup do
      {:ok, encoded} = Argon2id.hash(@password, @argon2_options)
      ["", "argon2id", version, _parameters, salt, hash] = String.split(encoded, "$")

      rebuild = fn parameters, s, h ->
        Enum.join(["", "argon2id", version, parameters, s, h], "$")
      end

      %{encoded: encoded, salt: salt, hash: hash, rebuild: rebuild}
    end

    property "cost parameters past the verification budget never parse", context do
      hostile_parameters =
        one_of([
          # Anything past a default-budget dimension — one step over the
          # configured costs up to far past the encoding's own maxima.
          map(integer(32_769..1_000_000_000), &"m=#{&1},t=2,p=1"),
          map(integer(3..1_000), &"m=32768,t=#{&1},p=1"),
          map(integer(2..1_000), &"m=32768,t=2,p=#{&1}"),
          map(integer(1..1_000_000), &"m=-#{&1},t=2,p=1")
        ])

      check all(parameters <- hostile_parameters, max_runs: runs(80)) do
        hostile = context.rebuild.(parameters, context.salt, context.hash)
        assert Argon2id.needs_rehash?(hostile, @argon2_options)
      end
    end

    test "the total-length ceiling admits 320 bytes and rejects 321", context do
      prefix = "$argon2id$v=19$m=32768,t=2,p=1$#{context.salt}$"

      # Exactly at the ceiling: the preflight passes it through, and the
      # backend rejects the padded tag without crashing.
      at_ceiling = prefix <> String.duplicate("A", 320 - byte_size(prefix))
      assert byte_size(at_ceiling) == 320
      refute Argon2id.verify(@password, at_ceiling, @argon2_options)

      # One byte over: rejected before any splitting or decoding.
      over_ceiling = prefix <> String.duplicate("A", 321 - byte_size(prefix))
      assert byte_size(over_ceiling) == 321
      refute Argon2id.verify(@password, over_ceiling, @argon2_options)
      assert Argon2id.needs_rehash?(over_ceiling, @argon2_options)
    end

    test "stored costs one step past the default budget fail closed", context do
      for parameters <- ["m=65536,t=2,p=1", "m=32768,t=3,p=1", "m=32768,t=2,p=2"] do
        hostile = context.rebuild.(parameters, context.salt, context.hash)
        refute Argon2id.verify(@password, hostile, @argon2_options)
        assert Argon2id.needs_rehash?(hostile, @argon2_options)
      end
    end

    test "malformed values below the ceilings delegate to the backend", context do
      # The preflight reads only the version and cost fields; everything
      # after them — salt, tag, Base64 validity — is argon2_elixir's to
      # reject, and rejection lands on the dummy path rather than crashing.
      for delegated <- [
            context.rebuild.("m=32768,t=2,p=1", "!!!", "!!!"),
            context.rebuild.(
              "m=32768,t=2,p=1",
              Base.encode64(:binary.copy(<<1>>, 7), padding: false),
              context.hash
            ),
            context.rebuild.(
              "m=32768,t=2,p=1",
              context.salt,
              Base.encode64(:binary.copy(<<2>>, 3), padding: false)
            ),
            "$argon2id$v=19$m=32768,t=2,p=1$#{context.salt}",
            context.rebuild.("m=0,t=0,p=0", context.salt, context.hash)
          ] do
        refute Argon2id.verify(@password, delegated, @argon2_options)
      end
    end
  end

  describe "hasher dispatcher" do
    property "routing on hostile PHC prefixes is total and fails closed" do
      check all(encoded <- hostile_binary(), max_runs: runs(150)) do
        assert Hasher.verify_with_hashers(
                 @password,
                 encoded,
                 {TestHasher, []},
                 []
               ) == :error

        assert Hasher.needs_rehash?(encoded, {TestHasher, []}, {TestHasher, []}) in [
                 true,
                 false
               ]
      end
    end

    property "algorithm segments never route to an unintended hasher" do
      check all(
              algorithm <- string(:printable, min_length: 1, max_length: 64),
              algorithm != "test-sha256",
              max_runs: runs(150)
            ) do
        encoded = "$" <> algorithm <> "$salt$digest"

        assert Hasher.verify_with_hashers(
                 @password,
                 encoded,
                 {TestHasher, []},
                 []
               ) == :error
      end
    end
  end

  describe "round trips" do
    property "test hasher verifies exactly the hashed password" do
      check all(
              password <- binary(min_length: 1, max_length: 128),
              other <- binary(min_length: 1, max_length: 128),
              other != password,
              max_runs: runs(100)
            ) do
        {:ok, encoded} = TestHasher.hash(password, [])

        assert TestHasher.verify(password, encoded, [])
        refute TestHasher.verify(other, encoded, [])
        refute TestHasher.needs_rehash?(encoded, [])
      end
    end
  end
end
