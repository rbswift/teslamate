defmodule TeslaMate.Repo.Migrations.EncryptApiTokens do
  use Ecto.Migration

  Code.ensure_loaded!(TeslaMate.Vault)

  defmodule Encrypted.Binary do
    use Cloak.Ecto.Binary, vault: TeslaMate.Vault
  end

  defmodule Tokens do
    use Ecto.Schema

    schema "tokens" do
      field(:refresh, :string)
      field(:access, :string)

      field(:encrypted_refresh, Encrypted.Binary)
      field(:encrypted_access, Encrypted.Binary)
    end
  end

  defmodule Encryption do
    def setup do
      {type, key} =
        case System.get_env("ENCRYPTION_KEY") do
          key when is_binary(key) and byte_size(key) > 0 -> {:existing, key}
          _ -> {:generated, generate_key(64)}
        end

      setup_vault(key)

      {type, key}
    end

    defp generate_key(length) when length > 31 do
      :crypto.strong_rand_bytes(length) |> Base.encode64(padding: false) |> binary_part(0, length)
    end

    defp setup_vault(key) do
      Cloak.Vault.save_config(TeslaMate.Vault.Config,
        ciphers: [
          default: TeslaMate.Vault.default_chipher(:crypto.hash(:sha256, key))
        ]
      )
    end
  end

  alias TeslaMate.Repo

  def change do
    alter table(:tokens) do
      add :encrypted_refresh, :binary
      add :encrypted_access, :binary
    end

    flush()

    with [_ | _] = tokens <- Repo.all(Tokens) do
      with {:generated, encryption_key} <- Encryption.setup() do
        require Logger

        Logger.warning("""
        \n------------------------------------------------------------------------------
        No ENCRYPTION_KEY was found to encrypt API tokens. Therefore, a random key was
        generated automatically:


                #{encryption_key}


        Create an environment variable named "ENCRYPTION_KEY" with the value set to
        the key above and pass it to the application from now on.

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
    end

    alter table(:tokens) do
      remove :access
      remove :refresh
    end

    rename table(:tokens), :encrypted_access, to: :access
    rename table(:tokens), :encrypted_refresh, to: :refresh
  end
end
