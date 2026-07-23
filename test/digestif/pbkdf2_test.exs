defmodule Digestif.PBKDF2Test do
  use ExUnit.Case, async: true

  alias Digestif.PBKDF2

  # Contract tests for the thin adapter boundary: pbkdf2_elixir owns salt
  # generation, derivation, the modular encoding, and verification, while
  # Digestif owns configuration policy and the minimal resource preflight.
  # The backend's own grammar and primitive are deliberately not re-tested.

  defmodule RecordingBackend do
    def hash_pwd_salt(_password, options) do
      send(self(), {:pbkdf2_backend, {:hash_pwd_salt, options}})
      "$pbkdf2-sha256$#{options[:rounds]}$Igmnl/E3JR2Cevlp0Cshdw$fakedigest"
    end

    def verify_pass(_password, encoded_hash) do
      send(self(), {:pbkdf2_backend, {:verify_pass, encoded_hash}})
      false
    end

    def no_user_verify(options) do
      send(self(), {:pbkdf2_backend, {:no_user_verify, options}})
      false
    end
  end

  defmodule Sha512Backend do
    def hash_pwd_salt(_password, _options), do: "$pbkdf2-sha512$160000$salt$digest"
    def verify_pass(_password, _encoded_hash), do: false
    def no_user_verify(_options), do: false
  end

  @password "correct horse battery staple"
  @backend_options [
    rounds: 600_000,
    digest: :sha256,
    length: 32,
    salt_len: 16,
    format: :modular
  ]

  test "mints a backend hash that round-trips and fails the wrong password" do
    assert PBKDF2.algorithm() == "pbkdf2-sha256"
    assert {:ok, encoded} = PBKDF2.hash(@password, [])

    assert String.starts_with?(encoded, "$pbkdf2-sha256$600000$")
    assert PBKDF2.verify(@password, encoded, [])
    refute PBKDF2.verify("wrong password", encoded, [])
    refute PBKDF2.needs_rehash?(encoded, [])
    assert PBKDF2.needs_rehash?(encoded, iterations: 700_000)
  end

  test "verifies a hash produced directly by the backend with the documented parameters" do
    encoded = Pbkdf2.hash_pwd_salt(@password, @backend_options)

    assert PBKDF2.verify(@password, encoded, [])
  end

  test "hashing passes explicit SHA-256, rounds, salt, length, and format to the backend" do
    assert {:ok, _encoded} = PBKDF2.hash(@password, backend: RecordingBackend)

    assert_received {:pbkdf2_backend, {:hash_pwd_salt, options}}
    assert Enum.sort(options) == Enum.sort(@backend_options)

    assert {:ok, _encoded} =
             PBKDF2.hash(@password, backend: RecordingBackend, iterations: 700_000)

    assert_received {:pbkdf2_backend, {:hash_pwd_salt, options}}
    assert options[:rounds] == 700_000
  end

  test "hashing rejects a backend hash that is not PBKDF2-SHA-256" do
    assert_raise ArgumentError, ~r/unexpected non-PBKDF2-SHA-256/, fn ->
      PBKDF2.hash(@password, backend: Sha512Backend)
    end
  end

  test "missing-user dummy work delegates to the backend with the hashing options" do
    refute PBKDF2.no_user_verify(@password, backend: RecordingBackend)

    assert_received {:pbkdf2_backend, {:no_user_verify, options}}
    assert Enum.sort(options) == Enum.sort(@backend_options)

    # And the real backend path answers false as well.
    refute PBKDF2.no_user_verify(@password, [])
  end

  test "stored values the preflight rejects pay dummy work and never reach verification" do
    options = [backend: RecordingBackend]
    salt = "Igmnl/E3JR2Cevlp0Cshdw"

    for rejected <- [
          # Rounds one step over the default budget (the configured cost).
          "$pbkdf2-sha256$600001$#{salt}$digest",
          # Zero rounds would never terminate in the backend's derivation.
          "$pbkdf2-sha256$0$#{salt}$digest",
          # The backend's other digest is not this adapter's algorithm.
          "$pbkdf2-sha512$600000$#{salt}$digest",
          # One byte over the 160-byte total ceiling.
          "$pbkdf2-sha256$600000$" <> String.duplicate("A", 139),
          "",
          "not a hash"
        ] do
      refute PBKDF2.verify(@password, rejected, options)
      assert_received {:pbkdf2_backend, {:no_user_verify, _options}}
      refute_received {:pbkdf2_backend, {:verify_pass, _encoded_hash}}

      assert PBKDF2.needs_rehash?(rejected, [])
    end
  end

  test "a raised verification budget admits stronger stored hashes" do
    {:ok, strong} = PBKDF2.hash(@password, iterations: 700_000)

    # Over the default budget: fails closed before backend verification.
    refute PBKDF2.verify(@password, strong, backend: RecordingBackend)
    assert_received {:pbkdf2_backend, {:no_user_verify, _options}}
    refute_received {:pbkdf2_backend, {:verify_pass, _encoded_hash}}

    assert PBKDF2.verify(@password, strong, max_iterations: 700_000)
    assert PBKDF2.needs_rehash?(strong, max_iterations: 700_000)
  end

  test "malformed in-budget values are the backend's to reject and fail closed" do
    # The preflight reads only the algorithm label and round count; salt,
    # digest, and Base64 validity beyond them belong to the backend.
    for delegated <- [
          "$pbkdf2-sha256$600000$!!!$!!!",
          "$pbkdf2-sha256$600000$missing-digest",
          "$pbkdf2-sha256$600000$a$b$c$d"
        ] do
      refute PBKDF2.verify(@password, delegated, backend: RecordingBackend)
      assert_received {:pbkdf2_backend, {:verify_pass, ^delegated}}

      # The real backend rejects these by raising; the adapter normalizes
      # that to the fail-closed dummy path.
      refute PBKDF2.verify(@password, delegated, [])
    end
  end

  test "the previous Bonafide encoding remains an explicit storage break" do
    # Minted by the pre-delegation adapter (URL-safe Base64 segments) for
    # the password below. The backend's passlib-style decoder does not
    # accept URL-safe Base64, so these hashes fail closed and report
    # needs_rehash?; there is no compatibility path.
    old_format =
      "$pbkdf2-sha256$600000$BW9z9ZnKOw2SaSthko6nEA$2VJRszKdukXVIaSN2Syh2p6knkDBn6gr9B-6UduF0ac"

    refute PBKDF2.verify("probe password", old_format, [])

    # The preflight reads only the algorithm label and round count, both of
    # which the old encoding shares, so the rehash answer stays false;
    # rehash decisions are only meaningful for hashes that verify.
    refute PBKDF2.needs_rehash?(old_format, [])
  end

  test "configuration options are validated at configuration time" do
    assert :ok = PBKDF2.validate_options!([])
    assert :ok = PBKDF2.validate_options!(iterations: 600_000)
    assert :ok = PBKDF2.validate_options!(iterations: 600_000, max_iterations: 10_000_000)

    # OWASP floor for new HMAC-SHA-256 hashes and the absolute ceiling.
    assert_raise ArgumentError, ~r/iterations/, fn ->
      PBKDF2.validate_options!(iterations: 599_999)
    end

    assert_raise ArgumentError, ~r/iterations/, fn ->
      PBKDF2.validate_options!(iterations: 10_000_001)
    end

    # A budget below the configured cost would mint hashes its own
    # verification bound rejects.
    assert_raise ArgumentError, ~r/max_iterations/, fn ->
      PBKDF2.validate_options!(iterations: 700_000, max_iterations: 600_000)
    end

    # The backend's :rounds vocabulary is not exposed alongside :iterations.
    assert_raise ArgumentError, fn ->
      PBKDF2.validate_options!(rounds: 600_000)
    end

    assert_raise ArgumentError, ~r/pbkdf2_elixir/, fn ->
      PBKDF2.validate_options!(backend: Digestif.NoSuchPbkdf2Backend)
    end
  end
end
