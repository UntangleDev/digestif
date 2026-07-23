defmodule Digestif.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :digestif,
      version: @version,
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Robust password hashing with a small Elixir API",
      package: package(),
      docs: docs(),
      test_coverage: [summary: [threshold: 90]]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:pbkdf2_elixir, "~> 2.3"},
      {:argon2_elixir, "~> 4.0"},
      {:bcrypt_elixir, "~> 3.0", optional: true},
      {:stream_data, "~> 1.2", only: [:dev, :test]},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"Documentation" => "https://hexdocs.pm/digestif"},
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      groups_for_modules: [
        "Hashing algorithms": [Digestif.Argon2id, Digestif.PBKDF2, Digestif.Bcrypt],
        Extension: [Digestif.Hasher]
      ]
    ]
  end
end
