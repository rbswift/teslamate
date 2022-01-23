defmodule TeslaMate.Auth.Tokens do
  use Ecto.Schema
  import Ecto.Changeset

  schema "tokens" do
    field :refresh, TeslaMate.Encrypted.Binary, redact: true
    field :access, TeslaMate.Encrypted.Binary, redact: true

    timestamps()
  end

  @doc false
  def changeset(tokens, attrs) do
    tokens
    |> cast(attrs, [:access, :refresh])
    |> validate_required([:access, :refresh])
  end
end
