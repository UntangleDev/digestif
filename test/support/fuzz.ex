defmodule Digestif.Fuzz do
  @moduledoc false

  import StreamData

  def runs(base) do
    case System.get_env("DIGESTIF_FUZZ_FACTOR") do
      nil -> base
      factor -> base * max(String.to_integer(factor), 1)
    end
  end

  def hostile_binary do
    frequency([
      {3, binary(max_length: 128)},
      {3, string(:printable, max_length: 128)},
      {2, string([?$, ?., ?=, ?,, ?a..?z, ?A..?Z, ?0..?9, ?+, ?/, ?-, ?_], max_length: 128)},
      {1, string([0x00..0x1F, 0x7F], max_length: 32)},
      {1, constant("")},
      {1, map(binary(min_length: 1, max_length: 64), &:binary.copy(&1, 64))}
    ])
  end
end
