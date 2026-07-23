defmodule Digestif.RecordingArgon2Backend do
  @moduledoc """
  Fake Argon2 backend that records every call without doing native work,
  proving which stored hashes reach the real verification path.
  """

  def hash_pwd_salt(_password, _options) do
    notify(:hash_pwd_salt)
    raise "the recording backend never mints hashes"
  end

  def verify_pass(_password, phc_hash) do
    notify({:verify_pass, phc_hash})
    false
  end

  def no_user_verify(_options) do
    notify(:no_user_verify)
    false
  end

  defp notify(message) do
    case Process.whereis(:argon2_backend_probe) do
      nil -> :ok
      pid -> send(pid, {:argon2_backend, message})
    end
  end
end

defmodule Digestif.Argon2idTest do
  use ExUnit.Case, async: false

  alias Digestif.Argon2id

  # The validator enforces the OWASP floor, so tests run the real algorithm
  # at the floor itself; tests should not weaken production parameters.
  @test_options [t_cost: 2, m_cost: 15, parallelism: 1]

  test "secure defaults produce a standard PHC Argon2id hash" do
    assert Argon2id.algorithm() == "argon2id"
    assert {:ok, encoded} = Argon2id.hash("correct horse battery staple", [])

    assert encoded =~ ~r/\A\$argon2id\$v=19\$m=32768,t=2,p=1\$/
    assert Argon2id.verify("correct horse battery staple", encoded, [])
    refute Argon2id.verify("wrong password", encoded, [])
    refute Argon2id.needs_rehash?(encoded, [])
  end

  test "malformed and foreign hashes fail closed with dummy work" do
    assert {:ok, encoded} = Argon2id.hash("correct horse battery staple", @test_options)
    branded_envelope = String.replace_prefix(encoded, "$argon2id$", "$foreign$argon2id$")

    refute Argon2id.verify("correct horse battery staple", branded_envelope, @test_options)
    refute Argon2id.verify("correct horse battery staple", "not-a-hash", @test_options)

    malformed = String.replace(encoded, "m=32768,t=2,p=1", "m=1,t=0,p=0")
    refute Argon2id.verify("correct horse battery staple", malformed, @test_options)

    nif_invalid = String.replace(encoded, "m=32768,t=2,p=1", "m=1,t=1,p=1")
    refute Argon2id.verify("correct horse battery staple", nif_invalid, @test_options)
    refute Argon2id.no_user_verify("arbitrary password", @test_options)
  end

  test "stored parameters beyond the verification budget fail closed" do
    password = "correct horse battery staple"
    assert {:ok, encoded} = Argon2id.hash(password, @test_options)
    ["", "argon2id", version, _parameters, salt, hash] = String.split(encoded, "$")

    rebuild = fn parameters, salt_part, hash_part ->
      Enum.join(["", "argon2id", version, parameters, salt_part, hash_part], "$")
    end

    # The budget defaults to the configured costs, so a stored hash may not
    # request even one step more memory, passes, or lanes than a login this
    # configuration already pays for.
    for hostile <- [
          rebuild.("m=65536,t=2,p=1", salt, hash),
          rebuild.("m=32768,t=3,p=1", salt, hash),
          rebuild.("m=32768,t=2,p=2", salt, hash)
        ] do
      refute Argon2id.verify(password, hostile, @test_options)
      assert Argon2id.needs_rehash?(hostile, @test_options)
    end

    # An explicit budget re-admits stronger imported hashes up to exactly
    # its dimensions and not past them.
    budgeted = @test_options ++ [verification_budget: [m_cost: 16, t_cost: 3]]
    within = rebuild.("m=65536,t=3,p=1", salt, hash)
    refute Argon2id.needs_rehash?(within, budgeted)
    assert Argon2id.needs_rehash?(rebuild.("m=131072,t=3,p=1", salt, hash), budgeted)
    assert Argon2id.needs_rehash?(rebuild.("m=65536,t=4,p=1", salt, hash), budgeted)

    # A genuine hash minted at stronger costs verifies only under a budget
    # that admits it.
    stronger_options = [t_cost: 2, m_cost: 16, parallelism: 1]
    assert {:ok, stronger} = Argon2id.hash(password, stronger_options)
    refute Argon2id.verify(password, stronger, @test_options)
    assert Argon2id.verify(password, stronger, budgeted)
  end

  test "hostile stored values never reach the native verification path" do
    Process.register(self(), :argon2_backend_probe)

    on_exit(fn ->
      Process.whereis(:argon2_backend_probe) && Process.unregister(:argon2_backend_probe)
    end)

    options = Keyword.put(@test_options, :backend, Digestif.RecordingArgon2Backend)
    salt = Base.encode64(:binary.copy(<<1>>, 16), padding: false)
    hash = Base.encode64(:binary.copy(<<2>>, 32), padding: false)

    rebuild = fn parameters, salt_part, hash_part ->
      Enum.join(["", "argon2id", "v=19", parameters, salt_part, hash_part], "$")
    end

    # Positive control: an in-budget stored hash does reach verify_pass, so
    # the probe genuinely observes the native path.
    in_budget = rebuild.("m=32768,t=2,p=1", salt, hash)
    refute Argon2id.verify("password", in_budget, options)
    assert_received {:argon2_backend, {:verify_pass, ^in_budget}}

    # An explicitly budgeted stronger hash reaches the backend too — but
    # only under the budget that admits it.
    stronger = rebuild.("m=65536,t=2,p=1", salt, hash)
    budgeted = Keyword.put(options, :verification_budget, m_cost: 16)
    refute Argon2id.verify("password", stronger, budgeted)
    assert_received {:argon2_backend, {:verify_pass, ^stronger}}

    # One byte past the total encoded ceiling: the labels, parameters, and
    # salt come to 54 bytes, so a 267-character tag segment lands the whole
    # value on 321 bytes, rejected before any decoding.
    over_length = rebuild.("m=32768,t=2,p=1", salt, String.duplicate("A", 267))
    assert byte_size(over_length) == 321

    hostile = [
      # The exact historical failure shape: the old encoding-level maxima
      # requesting 4 GiB with maximal time and lane costs.
      rebuild.("m=4194304,t=16,p=16", salt, hash),
      # One step past each default-budget dimension (the configured costs).
      rebuild.("m=65536,t=2,p=1", salt, hash),
      rebuild.("m=32768,t=3,p=1", salt, hash),
      rebuild.("m=32768,t=2,p=2", salt, hash),
      over_length
    ]

    for stored <- hostile do
      refute Argon2id.verify("password", stored, options)

      # Rejected values pay exactly the bounded dummy verification and are
      # never handed to the backend's real verification entry point.
      assert_received {:argon2_backend, :no_user_verify}
      refute_received {:argon2_backend, {:verify_pass, _phc}}
    end
  end

  test "rehash detection compares memory, time, lanes, and version" do
    stored_options = [t_cost: 2, m_cost: 16, parallelism: 1]
    assert {:ok, encoded} = Argon2id.hash("correct horse battery staple", stored_options)

    refute Argon2id.needs_rehash?(encoded, stored_options)

    # Under a weaker configuration the stored hash exceeds the default
    # verification budget, so it reports true from the budget side.
    assert Argon2id.needs_rehash?(encoded, t_cost: 2, m_cost: 15, parallelism: 1)

    # A budget that admits it restores the directional comparison: the
    # stored hash is stronger, so no rehash is needed.
    refute Argon2id.needs_rehash?(encoded,
             t_cost: 2,
             m_cost: 15,
             parallelism: 1,
             verification_budget: [m_cost: 16]
           )

    assert Argon2id.needs_rehash?(encoded, Keyword.put(stored_options, :m_cost, 17))
    assert Argon2id.needs_rehash?(encoded, Keyword.put(stored_options, :t_cost, 3))
    assert Argon2id.needs_rehash?(encoded, Keyword.put(stored_options, :parallelism, 2))
    assert Argon2id.needs_rehash?(String.replace(encoded, "v=19", "v=16"), stored_options)
    assert Argon2id.needs_rehash?("malformed", stored_options)
  end

  test "adapter options are validated before the hasher is configured" do
    assert :ok = Argon2id.validate_options!([])
    assert :ok = Argon2id.validate_options!(@test_options)

    for {options, message} <- [
          {[unknown: true], ~r/unknown keys \[:unknown\]/},
          # Salt and tag sizes are fixed conventions, no longer options.
          {[salt_len: 16], ~r/unknown keys \[:salt_len\]/},
          {[hashlen: 32], ~r/unknown keys \[:hashlen\]/},
          {[t_cost: 0], ~r/:t_cost/},
          {[t_cost: 1], ~r/:t_cost/},
          {[t_cost: 17], ~r/:t_cost/},
          {[m_cost: 14], ~r/:m_cost/},
          {[m_cost: 2], ~r/:m_cost/},
          {[m_cost: 22], ~r/:m_cost/},
          {[parallelism: 0], ~r/:parallelism/},
          {[parallelism: 9], ~r/:parallelism/},
          # Budget dimensions may neither undercut the configured costs nor
          # exceed the absolute option bounds.
          {[verification_budget: [unknown: 1]], ~r/unknown keys \[:unknown\]/},
          {[m_cost: 16, verification_budget: [m_cost: 15]], ~r/verification_budget m_cost/},
          {[verification_budget: [m_cost: 22]], ~r/verification_budget m_cost/},
          {[verification_budget: [t_cost: 17]], ~r/verification_budget t_cost/},
          {[verification_budget: [parallelism: 9]], ~r/verification_budget parallelism/}
        ] do
      assert_raise ArgumentError, message, fn -> Argon2id.validate_options!(options) end
    end

    # The full budget range is available to hosts that opt in explicitly.
    assert :ok =
             Argon2id.validate_options!(
               verification_budget: [m_cost: 21, t_cost: 16, parallelism: 8]
             )
  end

  test "the adapter reports a missing backend in-process" do
    assert_raise ArgumentError, ~r/requires the :argon2_elixir dependency/, fn ->
      Argon2id.validate_options!(backend: Digestif.MissingArgon2Backend)
    end
  end
end
