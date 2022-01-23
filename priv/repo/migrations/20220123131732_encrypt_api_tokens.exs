defmodule TeslaMate.Repo.Migrations.EncryptApiTokens do
  use Ecto.Migration

  defmodule Tokens do
    use Ecto.Schema

    schema "tokens" do
      field(:refresh, :string)
      field(:access, :string)

      field(:encrypted_refresh, TeslaMate.Encrypted.Binary)
      field(:encrypted_access, TeslaMate.Encrypted.Binary)
    end
  end

  alias TeslaMate.Repo

  def change do
    alter table(:tokens) do
      add :encrypted_refresh, :binary
      add :encrypted_access, :binary
    end

    flush()

    {key_provided?, encryption_key} =
      case System.get_env("ENCRYPTION_KEY") do
        key when is_binary(key) and byte_size(key) > 0 ->
          {true, key}

        _ ->
          random_key = :crypto.strong_rand_bytes(32) |> Base.encode64() |> binary_part(0, 16)
          {false, random_key}
      end

    Cloak.Vault.save_config(TeslaMate.Vault.Config,
      ciphers: [
        default:
          {Cloak.Ciphers.AES.GCM, tag: "AES.GCM.V1", key: :crypto.hash(:sha256, encryption_key)}
      ]
    )

    tokens = Repo.all(Tokens)

    if not Enum.empty?(tokens) and not key_provided? do
      require Logger

      Logger.warn("""
      ------------------------------------------------------------------------------
      No ENCRYPTION_KEY was found to encrypt API tokens. Therefore, a random key was
      generated automatically:


                                  #{encryption_key}


      Create an environment variable named "ENCRYPTION_KEY" with the value of this
      key and pass it to this application from now on.


      If you choose to use a different key, a new login with your API tokens is
      required once after starting the application.
      ------------------------------------------------------------------------------
      """)
    end

    Enum.each(tokens, fn %Tokens{} = tokens ->
      tokens
      |> Ecto.Changeset.change(%{
        encrypted_access: tokens.access,
        encrypted_refresh: tokens.refresh
      })
      |> Repo.update!()
    end)

    alter table(:tokens) do
      remove :access
      remove :refresh
    end

    rename table(:tokens), :encrypted_access, to: :access
    rename table(:tokens), :encrypted_refresh, to: :refresh
  end
end
